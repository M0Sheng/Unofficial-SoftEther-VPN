mod dhcp;
mod ethernet;
mod wire;

use std::hash::{BuildHasher, RandomState};

use dhcp::{Client, Step};
use ethernet::{EthernetLink, arp_frame, parse_arp};

type MacAddress = [u8; 6];
const ETHERNET_HEADER: usize = 14;
const MAX_FRAME: usize = 1600;
const IPV4: u16 = 0x0800;
const ARP: u16 = 0x0806;
const BROADCAST: MacAddress = [0xff; 6];
const UNKNOWN: MacAddress = [0; 6];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Route {
    pub(crate) destination: u32,
    pub(crate) prefix_length: u8,
    pub(crate) gateway: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Lease {
    pub(crate) address: u32,
    pub(crate) prefix_length: u8,
    pub(crate) server_identifier: u32,
    pub(crate) duration_seconds: u64,
    pub(crate) renew_at_ms: u64,
    pub(crate) rebind_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) dns: Vec<u32>,
    pub(crate) routes: Vec<Route>,
}

impl Lease {
    // Network byte order integer values. An explicit route more specific than the
    // interface prefix can route an otherwise on-link destination through a gateway.
    fn next_hop(&self, destination: u32) -> Option<u32> {
        next_hop(self.address, self.prefix_length, &self.routes, destination)
    }
}

pub(crate) trait Output {
    fn frame(&mut self, data: &[u8], control: bool);
    fn packet(&mut self, data: &[u8]);
    fn lease(&mut self, lease: Option<&Lease>);
}

/// Owns the DHCP and Ethernet state on the TUN packet processing thread.
pub(crate) struct Session {
    mac: MacAddress,
    mtu: u16,
    dhcp: Client,
    link: Option<EthernetLink>,
    active: Option<Lease>,
    candidate: Option<Candidate>,
    announce_at: Option<u64>,
    random: Random,
}

struct Candidate {
    lease: Lease,
    next_probe_at: u64,
    probes: u8,
}

/// Seeds the transaction ID and probe jitter from the standard library's
/// OS-random hash key. No entropy reads or syscalls are needed per packet.
struct Random {
    seed: RandomState,
    counter: u64,
}

impl Random {
    fn new() -> Self {
        Self {
            seed: RandomState::new(),
            counter: 0,
        }
    }

    fn next(&mut self) -> u32 {
        self.counter = self.counter.wrapping_add(1);
        self.seed.hash_one(self.counter) as u32
    }
}

impl Session {
    pub(crate) fn new(mac: MacAddress, mtu: u16) -> Option<Self> {
        if !usable_mac(mac) || !(68..=(MAX_FRAME - ETHERNET_HEADER) as u16).contains(&mtu) {
            return None;
        }
        Some(Self {
            mac,
            mtu,
            dhcp: Client::new(mac, mtu.max(576)),
            link: None,
            active: None,
            candidate: None,
            announce_at: None,
            random: Random::new(),
        })
    }

    pub(crate) fn start(&mut self, now_ms: u64, out: &mut impl Output) {
        let step = self.dhcp.start(now_ms, &mut self.random);
        self.apply(step, now_ms, out);
    }

    pub(crate) fn receive(&mut self, frame: &[u8], now_ms: u64, out: &mut impl Output) {
        let step = self.dhcp.receive(frame, now_ms, &mut self.random);
        self.apply(step, now_ms, out);
        if let Some(ref candidate) = self.candidate
            && self.conflicts(frame, candidate.lease.address)
        {
            let step = self.dhcp.decline(now_ms);
            self.apply(step, now_ms, out);
            return;
        }
        if let Some(ref mut link) = self.link
            && !wire::is_response(frame)
        {
            link.receive(frame, now_ms, out);
        }
    }

    pub(crate) fn send(&mut self, packet: &[u8], now_ms: u64, out: &mut impl Output) {
        if let Some(ref mut link) = self.link {
            link.send(packet, now_ms, out);
        }
    }

    pub(crate) fn tick(&mut self, now_ms: u64, out: &mut impl Output) {
        let link = &mut self.link;
        let step = self.dhcp.tick(now_ms, &mut self.random, |hop| {
            link.as_mut()?.hardware_address(hop, now_ms)
        });
        self.apply(step, now_ms, out);

        if let Some(ref mut candidate) = self.candidate
            && now_ms >= candidate.next_probe_at
        {
            if candidate.probes < 3 {
                let frame = arp_frame(self.mac, BROADCAST, UNKNOWN, 1, 0, candidate.lease.address);
                out.frame(&frame, true);
                candidate.probes += 1;
                let delay = if candidate.probes < 3 {
                    1000 + u64::from(self.random.next() % 1001)
                } else {
                    2000
                };
                candidate.next_probe_at = now_ms.saturating_add(delay);
            } else if let Some(candidate) = self.candidate.take() {
                let address = candidate.lease.address;
                self.publish(candidate.lease, out);
                self.announce(address, out);
                self.announce_at = Some(now_ms.saturating_add(2000));
            }
        }
        if self.announce_at.is_some_and(|deadline| now_ms >= deadline)
            && let Some(ref lease) = self.active
        {
            self.announce(lease.address, out);
            self.announce_at = None;
        }
        if let Some(ref mut link) = self.link {
            link.tick(now_ms, out);
        }
    }

    pub(crate) fn stop(&mut self, now_ms: u64, out: &mut impl Output) {
        let link = &mut self.link;
        let step = self.dhcp.stop(|hop| link.as_mut()?.hardware_address(hop, now_ms));
        self.apply(step, now_ms, out);
    }

    fn apply(&mut self, step: Step, now_ms: u64, out: &mut impl Output) {
        if step.lease_lost {
            self.candidate = None;
            self.link = None;
            self.announce_at = None;
            if self.active.take().is_some() {
                out.lease(None);
            }
        }
        if let Some(frame) = step.frame {
            out.frame(&frame, true);
        }
        if let (Some(hop), Some(link)) = (step.resolve_next_hop, self.link.as_mut()) {
            link.resolve(hop, now_ms, out);
        }
        if let Some(lease) = step.lease {
            if step.check_address || self.candidate.is_some() {
                match self.candidate.as_mut() {
                    Some(candidate) if candidate.lease.address == lease.address => {
                        candidate.lease = lease;
                    }
                    _ => {
                        self.candidate = Some(Candidate {
                            lease,
                            next_probe_at: now_ms.saturating_add(u64::from(self.random.next() % 1001)),
                            probes: 0,
                        });
                    }
                }
            } else {
                self.publish(lease, out);
            }
        }
    }

    fn publish(&mut self, lease: Lease, out: &mut impl Output) {
        if self.active.as_ref().is_none_or(|active| {
            active.address != lease.address
                || active.prefix_length != lease.prefix_length
                || active.routes != lease.routes
        }) {
            self.link = Some(EthernetLink::new(self.mac, self.mtu, &lease));
        }
        out.lease(Some(&lease));
        self.active = Some(lease);
    }

    fn announce(&self, address: u32, out: &mut impl Output) {
        out.frame(&arp_frame(self.mac, BROADCAST, UNKNOWN, 1, address, address), true);
    }

    fn conflicts(&self, frame: &[u8], address: u32) -> bool {
        parse_arp(frame).is_some_and(|arp| {
            arp.sender != self.mac
                && matches!(arp.operation, 1 | 2)
                && (arp.source == address || (arp.operation == 1 && arp.source == 0 && arp.target_ip == address))
        })
    }
}

fn next_hop(address: u32, prefix_length: u8, routes: &[Route], destination: u32) -> Option<u32> {
    let mask = network_mask(prefix_length);
    let mut best = ((address & mask) == (destination & mask)).then_some((prefix_length, destination));
    for route in routes {
        if best.is_none_or(|(prefix, _)| route.prefix_length > prefix)
            && (destination & network_mask(route.prefix_length)) == route.destination
        {
            let hop = if route.gateway == 0 {
                destination
            } else {
                route.gateway
            };
            best = Some((route.prefix_length, hop));
        }
    }
    best.map(|(_, hop)| hop)
}

fn network_mask(prefix_length: u8) -> u32 {
    if prefix_length == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_length)
    }
}

fn usable_mac(mac: MacAddress) -> bool {
    mac[0] & 1 == 0 && mac != UNKNOWN
}

fn usable_address(address: u32) -> bool {
    matches!(address >> 24, 1..=126 | 128..=223)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("fixed-width field"))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests;
