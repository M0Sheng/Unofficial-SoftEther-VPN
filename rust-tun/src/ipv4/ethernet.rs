use std::collections::{HashMap, VecDeque};

use super::{
    ARP, BROADCAST, ETHERNET_HEADER, IPV4, Lease, MAX_FRAME, MacAddress, Output, Route, UNKNOWN,
    network_mask, next_hop, put_u16, put_u32, read_u16, read_u32, usable_address, usable_mac,
};

const REQUEST: u16 = 1;
const REPLY: u16 = 2;
const ARP_LEN: usize = 42;
const MAX_PENDING_NEIGHBORS: usize = 64;
const MAX_WAITING_PACKETS: usize = 16;
const MAX_CACHE_SIZE: usize = 128;
const RETRY_MS: u64 = 1000;
const CACHE_MS: u64 = 60_000;

struct Neighbor {
    mac: MacAddress,
    expires_at: u64,
    last_used: u64,
}

struct Pending {
    ip: u32,
    packets: VecDeque<Vec<u8>>,
    deadline: u64,
    sent: u8,
}

impl Pending {
    fn new(ip: u32) -> Self {
        Self {
            ip,
            packets: VecDeque::new(),
            deadline: 0,
            sent: 0,
        }
    }

    fn request(&mut self, mac: MacAddress, address: u32, now_ms: u64, out: &mut impl Output) {
        self.sent += 1;
        self.deadline = now_ms.saturating_add(RETRY_MS);
        out.frame(&arp_frame(mac, BROADCAST, UNKNOWN, REQUEST, address, self.ip), true);
    }
}

pub(super) struct EthernetLink {
    mac: MacAddress,
    address: u32,
    prefix_length: u8,
    mtu: usize,
    routes: Vec<Route>,
    neighbors: HashMap<u32, Neighbor>,
    use_counter: u64,
    pending: VecDeque<Pending>,
    frame_buffer: [u8; MAX_FRAME],
}

impl EthernetLink {
    pub(super) fn new(mac: MacAddress, mtu: u16, lease: &Lease) -> Self {
        Self {
            mac,
            address: lease.address,
            prefix_length: lease.prefix_length,
            mtu: usize::from(mtu),
            routes: lease.routes.clone(),
            neighbors: HashMap::new(),
            use_counter: 0,
            pending: VecDeque::new(),
            frame_buffer: [0; MAX_FRAME],
        }
    }

    pub(super) fn send(&mut self, packet: &[u8], now_ms: u64, out: &mut impl Output) {
        let Some(packet) = ip_packet(packet, self.mtu) else {
            return;
        };
        if read_u32(packet, 12) != self.address {
            return;
        }
        let destination = read_u32(packet, 16);
        if self.is_broadcast(destination) {
            self.send_ip(BROADCAST, packet, out);
            return;
        }
        if let Some(hardware) = multicast_mac(destination) {
            self.send_ip(hardware, packet, out);
            return;
        }
        if !usable_address(destination) {
            return;
        }
        let Some(hop) = next_hop(self.address, self.prefix_length, &self.routes, destination)
            .filter(|&hop| self.valid_hop(hop))
        else {
            return;
        };
        if let Some(hardware) = self.hardware_address(hop, now_ms) {
            self.send_ip(hardware, packet, out);
            return;
        }
        let (mac, address) = (self.mac, self.address);
        if let Some(waiting) = self.prepare_resolution(hop)
            && waiting.packets.len() < MAX_WAITING_PACKETS
        {
            waiting.packets.push_back(packet.to_vec());
            if waiting.sent == 0 {
                waiting.request(mac, address, now_ms, out);
            }
        }
    }

    pub(super) fn hardware_address(&mut self, hop: u32, now_ms: u64) -> Option<MacAddress> {
        let neighbor = self.neighbors.get_mut(&hop)?;
        if now_ms < neighbor.expires_at {
            self.use_counter = self.use_counter.saturating_add(1);
            neighbor.last_used = self.use_counter;
            Some(neighbor.mac)
        } else {
            self.neighbors.remove(&hop);
            None
        }
    }

    pub(super) fn resolve(&mut self, hop: u32, now_ms: u64, out: &mut impl Output) {
        if !self.valid_hop(hop) || self.hardware_address(hop, now_ms).is_some() {
            return;
        }
        let (mac, address) = (self.mac, self.address);
        if let Some(waiting) = self.prepare_resolution(hop)
            && waiting.sent == 0
        {
            waiting.request(mac, address, now_ms, out);
        }
    }

    fn prepare_resolution(&mut self, hop: u32) -> Option<&mut Pending> {
        if let Some(index) = self.pending.iter().position(|waiting| waiting.ip == hop) {
            return self.pending.get_mut(index);
        }
        if self.pending.len() == MAX_PENDING_NEIGHBORS {
            return None;
        }
        self.pending.push_back(Pending::new(hop));
        self.pending.back_mut()
    }

    pub(super) fn tick(&mut self, now_ms: u64, out: &mut impl Output) {
        self.pending.retain_mut(|waiting| {
            if now_ms < waiting.deadline {
                return true;
            }
            if waiting.sent == 3 {
                return false;
            }
            waiting.request(self.mac, self.address, now_ms, out);
            true
        });
    }

    pub(super) fn receive(&mut self, frame: &[u8], now_ms: u64, out: &mut impl Output) {
        let Some(header) = frame.get(..ETHERNET_HEADER) else {
            return;
        };
        let sender = mac_at(header, 6);
        if !usable_mac(sender) || sender == self.mac {
            return;
        }
        match read_u16(header, 12) {
            ARP => {
                if let Some(arp) = parse_arp(frame) {
                    self.receive_arp(arp, now_ms, out);
                }
            }
            IPV4 => {
                let Some(packet) = ip_packet(&frame[ETHERNET_HEADER..], self.mtu) else {
                    return;
                };
                let destination = read_u32(packet, 16);
                let expected = if destination == self.address {
                    Some(self.mac)
                } else if self.is_broadcast(destination) {
                    Some(BROADCAST)
                } else {
                    multicast_mac(destination)
                };
                if expected == Some(mac_at(header, 0)) {
                    out.packet(packet);
                }
            }
            _ => {}
        }
    }

    fn receive_arp(&mut self, arp: Arp, now_ms: u64, out: &mut impl Output) {
        if arp.target_ip != self.address {
            return;
        }
        match arp.operation {
            REQUEST
                if (arp.destination == BROADCAST || arp.destination == self.mac)
                    && arp.source != self.address
                    && (arp.source == 0 || usable_address(arp.source)) =>
            {
                out.frame(
                    &arp_frame(self.mac, arp.sender, arp.sender, REPLY, self.address, arp.source),
                    true,
                );
            }
            REPLY if usable_address(arp.source) && arp.destination == self.mac && arp.target == self.mac => {
                let Some(index) = self.pending.iter().position(|waiting| waiting.ip == arp.source) else {
                    return;
                };
                let Some(waiting) = self.pending.remove(index) else {
                    return;
                };

                if self.neighbors.len() == MAX_CACHE_SIZE
                    && !self.neighbors.contains_key(&arp.source)
                    && let Some((&oldest, _)) =
                        self.neighbors.iter().min_by_key(|(_, neighbor)| neighbor.last_used)
                {
                    self.neighbors.remove(&oldest);
                }
                self.use_counter = self.use_counter.saturating_add(1);
                self.neighbors.insert(
                    arp.source,
                    Neighbor {
                        mac: arp.sender,
                        expires_at: now_ms.saturating_add(CACHE_MS),
                        last_used: self.use_counter,
                    },
                );
                for packet in waiting.packets {
                    self.send_ip(arp.sender, &packet, out);
                }
            }
            _ => {}
        }
    }

    fn send_ip(&mut self, destination: MacAddress, packet: &[u8], out: &mut impl Output) {
        let frame = &mut self.frame_buffer;
        frame[..6].copy_from_slice(&destination);
        frame[6..12].copy_from_slice(&self.mac);
        put_u16(frame, 12, IPV4);
        let length = ETHERNET_HEADER + packet.len();
        frame[ETHERNET_HEADER..length].copy_from_slice(packet);
        out.frame(&frame[..length], false);
    }

    fn valid_hop(&self, hop: u32) -> bool {
        usable_address(hop) && hop != self.address && !self.is_broadcast(hop)
    }

    fn is_broadcast(&self, destination: u32) -> bool {
        destination == u32::MAX
            || (self.prefix_length <= 30 && destination == (self.address | !network_mask(self.prefix_length)))
    }
}

pub(super) struct Arp {
    pub(super) destination: MacAddress,
    pub(super) sender: MacAddress,
    pub(super) target: MacAddress,
    pub(super) operation: u16,
    pub(super) source: u32,
    pub(super) target_ip: u32,
}

pub(super) fn parse_arp(frame: &[u8]) -> Option<Arp> {
    if frame.len() < ARP_LEN
        || read_u16(frame, 12) != ARP
        || read_u16(frame, 14) != 1
        || read_u16(frame, 16) != IPV4
        || frame[18] != 6
        || frame[19] != 4
    {
        return None;
    }
    let sender = mac_at(frame, 6);
    if !usable_mac(sender) || mac_at(frame, 22) != sender {
        return None;
    }
    Some(Arp {
        destination: mac_at(frame, 0),
        sender,
        target: mac_at(frame, 32),
        operation: read_u16(frame, 20),
        source: read_u32(frame, 28),
        target_ip: read_u32(frame, 38),
    })
}

pub(super) fn arp_frame(
    mac: MacAddress,
    ethernet_destination: MacAddress,
    target: MacAddress,
    operation: u16,
    source: u32,
    destination: u32,
) -> [u8; ARP_LEN] {
    let mut frame = [0; ARP_LEN];
    frame[..6].copy_from_slice(&ethernet_destination);
    frame[6..12].copy_from_slice(&mac);
    put_u16(&mut frame, 12, ARP);
    put_u16(&mut frame, 14, 1);
    put_u16(&mut frame, 16, IPV4);
    frame[18] = 6;
    frame[19] = 4;
    put_u16(&mut frame, 20, operation);
    frame[22..28].copy_from_slice(&mac);
    put_u32(&mut frame, 28, source);
    frame[32..38].copy_from_slice(&target);
    put_u32(&mut frame, 38, destination);
    frame
}

fn ip_packet(bytes: &[u8], mtu: usize) -> Option<&[u8]> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(bytes[0] & 15) * 4;
    let size = usize::from(read_u16(bytes, 2));
    if header < 20 || size < header || size > mtu {
        return None;
    }
    bytes.get(..size)
}

fn multicast_mac(destination: u32) -> Option<MacAddress> {
    if destination >> 28 != 14 {
        return None;
    }
    let [_, second, third, fourth] = destination.to_be_bytes();
    Some([1, 0, 0x5e, second & 0x7f, third, fourth])
}

fn mac_at(frame: &[u8], offset: usize) -> MacAddress {
    frame[offset..offset + 6].try_into().expect("valid Ethernet hardware address field")
}
