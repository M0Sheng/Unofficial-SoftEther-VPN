mod wire;

use std::collections::{HashMap, VecDeque};
use std::net::Ipv6Addr;
use wire::{ALL_NODES, Control, Packet, Prefix, RouterAdvertisement, multicast_mac, solicited_node};

const ETHERNET_HEADER: usize = 14;
const MINIMUM_MTU: usize = 1280;
const DUPLICATE_WAIT_MS: u64 = 1_000;
const ROUTER_WAIT_MS: u64 = 4_000;
const NEIGHBOR_WAIT_MS: u64 = 1_000;
const MAX_SOLICITATIONS: u8 = 3;
const MAX_ADVERTISEMENTS: usize = 8;
const MAX_NEIGHBORS: usize = 64;
const MAX_WAITING_PACKETS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Configuration {
    pub address: Ipv6Addr,
    pub on_link_prefix: Option<Ipv6Addr>,
    pub default_router: Option<Ipv6Addr>,
    pub mtu: usize,
}

impl Configuration {
    fn next_hop(self, destination: Ipv6Addr) -> Option<Ipv6Addr> {
        if !wire::valid_unicast(destination) || destination.is_unicast_link_local() {
            return None;
        }
        if self.on_link_prefix.is_some_and(|network| network.octets()[..8] == destination.octets()[..8]) {
            Some(destination)
        } else {
            self.default_router
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    MtuTooSmall,
    DuplicateAddress,
    NoAdvertisement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    Discovering,
    Ready(Configuration),
    Failed(Failure),
    Expired,
}

pub(super) enum Output {
    Control(Vec<u8>),
    Frame(Vec<u8>),
    Packet(Vec<u8>),
}

#[derive(Clone, Copy)]
struct Binding {
    configuration: Configuration,
    router: Ipv6Addr,
    router_mac: [u8; 6],
    prefix: Prefix,
    address_expiry: u64,
    router_expiry: u64,
}

impl Binding {
    fn active(self, now: u64) -> bool {
        now < self.address_expiry.min(self.router_expiry)
    }

    fn refresh(&mut self, options: &RouterAdvertisement, now: u64) {
        if let Some(prefix) = options.prefixes.iter().find(|prefix| prefix.network == self.prefix.network) {
            self.address_expiry = if prefix.on_link == self.prefix.on_link {
                prefix_expiry(*prefix, now)
            } else {
                now
            };
        }
        if self.configuration.default_router.is_some() {
            self.router_expiry = deadline(now, options.lifetime_seconds.into());
        }
        if options.mtu.is_some_and(|mtu| mtu < self.configuration.mtu) {
            self.address_expiry = now;
        }
    }
}

enum State {
    WaitToProbe(u64),
    ProbeLinkLocal(u64),
    WaitForRouter { probes: u8, deadline: u64 },
    ProbeAddress { candidate: Binding, deadline: u64 },
    Bound(Binding),
    Failed(Failure),
    Expired,
}

struct Neighbor {
    mac: Option<[u8; 6]>,
    expiry: u64,
}

struct PendingNeighbor {
    packets: Vec<Vec<u8>>,
    probes: u8,
    deadline: u64,
}

/// Single-worker IPv6 host link attached to the SoftEther Ethernet endpoint.
/// All timers use the same monotonic milliseconds supplied by the forwarder.
pub(super) struct Link {
    mac: [u8; 6],
    mtu: usize,
    interface_id: [u8; 8],
    allow_non_on_link: bool,
    link_local: Ipv6Addr,
    link_local_group: Ipv6Addr,
    state: State,
    advertisements: VecDeque<Option<Binding>>,
    neighbors: HashMap<Ipv6Addr, Neighbor>,
    neighbor_order: VecDeque<Ipv6Addr>,
    pending: HashMap<Ipv6Addr, PendingNeighbor>,
}

impl Link {
    pub fn new(
        mac: [u8; 6],
        mtu: usize,
        mut interface_id: [u8; 8],
        now_ms: u64,
        initial_delay_ms: u16,
        allow_non_on_link: bool,
    ) -> Self {
        if interface_id == [0; 8] {
            interface_id[7] = 1;
        }
        let link_local = address_in(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), interface_id);
        let state = if mtu < MINIMUM_MTU {
            State::Failed(Failure::MtuTooSmall)
        } else {
            State::WaitToProbe(now_ms.saturating_add(initial_delay_ms.into()))
        };
        Self {
            mac, mtu, interface_id, allow_non_on_link, link_local,
            link_local_group: solicited_node(link_local), state,
            advertisements: VecDeque::new(), neighbors: HashMap::new(),
            neighbor_order: VecDeque::new(), pending: HashMap::new(),
        }
    }

    pub fn status(&self, now: u64) -> Status {
        match self.state {
            State::Bound(binding) if binding.active(now) => Status::Ready(binding.configuration),
            State::Bound(_) | State::Expired => Status::Expired,
            State::Failed(failure) => Status::Failed(failure),
            _ => Status::Discovering,
        }
    }

    pub fn tick(&mut self, now: u64, emit: &mut impl FnMut(Output)) {
        match self.state {
            State::WaitToProbe(until) if now >= until => {
                self.listener_report(Ipv6Addr::UNSPECIFIED, emit);
                self.dad_probe(self.link_local, emit);
                self.state = State::ProbeLinkLocal(now.saturating_add(DUPLICATE_WAIT_MS));
            }
            State::ProbeLinkLocal(until) if now >= until => {
                self.listener_report(self.link_local, emit);
                self.router_probe(1, now, emit);
                let candidate = self.advertisements.drain(..).flatten().next();
                if let Some(candidate) = candidate {
                    self.probe_address(candidate, now, emit);
                }
            }
            State::WaitForRouter { probes, deadline } if now >= deadline => {
                if probes == MAX_SOLICITATIONS {
                    self.fail(Failure::NoAdvertisement);
                } else {
                    self.router_probe(probes + 1, now, emit);
                }
            }
            State::ProbeAddress { candidate, deadline } if now >= deadline => {
                if candidate.active(now) {
                    self.state = State::Bound(candidate);
                    self.advertisements.clear();
                } else {
                    self.fail(Failure::NoAdvertisement);
                }
            }
            State::Bound(binding) if binding.active(now) => self.retry_neighbors(now, emit),
            State::Bound(_) => {
                self.state = State::Expired;
                self.clear_pending();
            }
            _ => {}
        }
    }

    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }

    pub fn receive(
        &mut self,
        frame: &[u8],
        now: u64,
        requires_router: impl Fn(Ipv6Addr) -> bool,
        emit: &mut impl FnMut(Output),
    ) {
        if matches!(self.state, State::Failed(_) | State::Expired) {
            return;
        }
        let Some(header) = frame.get(..ETHERNET_HEADER) else { return };
        if header[12..14] != [0x86, 0xdd] {
            return;
        }
        let Some(packet) = Packet::parse(&frame[ETHERNET_HEADER..]) else { return };
        let source_mac = [header[6], header[7], header[8], header[9], header[10], header[11]];
        if !wire::valid_mac(source_mac) || source_mac == self.mac {
            return;
        }
        let destination_mac = if packet.destination.is_multicast() {
            multicast_mac(packet.destination)
        } else {
            self.mac
        };
        if header[..6] != destination_mac {
            return;
        }

        match packet.control() {
            Control::Data => {
                if self.configuration(now).is_some_and(|configuration| {
                    packet.destination == configuration.address
                        && packet.bytes.len() <= configuration.mtu
                        && !packet.source.is_unspecified()
                        && !packet.source.is_multicast()
                }) {
                    emit(Output::Packet(packet.bytes.to_vec()));
                }
            }
            Control::ListenerQuery => {
                if self.link_local_ready()
                    && (packet.destination == ALL_NODES || packet.destination == self.link_local_group)
                {
                    self.listener_report(self.link_local, emit);
                }
            }
            Control::RouterAdvertisement(options) => {
                if packet.destination == ALL_NODES || packet.destination == self.link_local {
                    self.receive_advertisement(packet.source, source_mac, options, now, requires_router, emit);
                }
            }
            Control::Solicitation(target) => {
                if self.tentative_address() == Some(target) {
                    if packet.source.is_unspecified() {
                        self.fail(Failure::DuplicateAddress);
                    }
                } else if self.owns_address(target, now)
                    && (packet.destination == target || packet.destination == solicited_node(target))
                {
                    let solicited = !packet.source.is_unspecified();
                    let (reply_to, reply_mac) = if solicited {
                        (packet.source, source_mac)
                    } else {
                        (ALL_NODES, multicast_mac(ALL_NODES))
                    };
                    let payload = wire::neighbor_advertisement(target, reply_to, self.mac, solicited);
                    self.control(&payload, reply_mac, emit);
                }
            }
            Control::NeighborAdvertisement(advertisement) => {
                if self.tentative_address() == Some(advertisement.target) && packet.destination == ALL_NODES {
                    self.fail(Failure::DuplicateAddress);
                } else if advertisement.solicited && packet.destination == self.link_local
                    && advertisement.mac == Some(source_mac)
                {
                    self.resolve_neighbor(advertisement.target, source_mac, now, emit);
                }
            }
            Control::Discard => {}
        }
    }

    pub fn send(&mut self, payload: &[u8], now: u64, emit: &mut impl FnMut(Output)) {
        let State::Bound(binding) = self.state else { return };
        let configuration = binding.configuration;
        if !binding.active(now) || payload.len() > configuration.mtu {
            return;
        }
        let Some(packet) = Packet::parse(payload) else { return };
        if packet.source != configuration.address || packet.bytes.len() != payload.len() {
            return;
        }
        let Some(hop) = configuration.next_hop(packet.destination) else { return };
        if configuration.default_router == Some(hop) {
            emit(Output::Frame(frame(self.mac, binding.router_mac, payload)));
            return;
        }
        if let Some(cached) = self.neighbors.get(&hop).filter(|cached| cached.expiry > now) {
            if let Some(destination) = cached.mac {
                emit(Output::Frame(frame(self.mac, destination, payload)));
            }
            return;
        }
        if let Some(waiting) = self.pending.get_mut(&hop) {
            if waiting.packets.len() < MAX_WAITING_PACKETS {
                waiting.packets.push(payload.to_vec());
            }
            return;
        }
        if self.pending.len() >= MAX_NEIGHBORS {
            return;
        }

        self.pending.insert(hop, PendingNeighbor {
            packets: vec![payload.to_vec()], probes: 1, deadline: now.saturating_add(NEIGHBOR_WAIT_MS),
        });
        emit(neighbor_probe(self.mac, self.link_local, hop));
    }

    fn configuration(&self, now: u64) -> Option<Configuration> {
        match self.status(now) {
            Status::Ready(configuration) => Some(configuration),
            _ => None,
        }
    }

    fn link_local_ready(&self) -> bool {
        matches!(self.state, State::WaitForRouter { .. } | State::ProbeAddress { .. } | State::Bound(_))
    }

    fn tentative_address(&self) -> Option<Ipv6Addr> {
        match self.state {
            State::ProbeLinkLocal(_) => Some(self.link_local),
            State::ProbeAddress { candidate, .. } => Some(candidate.configuration.address),
            _ => None,
        }
    }

    fn owns_address(&self, address: Ipv6Addr, now: u64) -> bool {
        (self.link_local_ready() && address == self.link_local)
            || self.configuration(now).is_some_and(|configuration| configuration.address == address)
    }

    fn fail(&mut self, failure: Failure) {
        self.state = State::Failed(failure);
        self.advertisements.clear();
        self.clear_pending();
    }

    fn listener_report(&self, source: Ipv6Addr, emit: &mut impl FnMut(Output)) {
        let payload = wire::listener_report(source, self.link_local_group);
        self.control(&payload, multicast_mac(self.link_local_group), emit);
    }

    fn dad_probe(&self, target: Ipv6Addr, emit: &mut impl FnMut(Output)) {
        emit(neighbor_probe(self.mac, Ipv6Addr::UNSPECIFIED, target));
    }

    fn router_probe(&mut self, probes: u8, now: u64, emit: &mut impl FnMut(Output)) {
        let payload = wire::router_solicitation(self.link_local, self.mac);
        self.control(&payload, multicast_mac(wire::ALL_ROUTERS), emit);
        self.state = State::WaitForRouter { probes, deadline: now.saturating_add(ROUTER_WAIT_MS) };
    }

    fn probe_address(&mut self, candidate: Binding, now: u64, emit: &mut impl FnMut(Output)) {
        self.dad_probe(candidate.configuration.address, emit);
        self.state = State::ProbeAddress { candidate, deadline: now.saturating_add(DUPLICATE_WAIT_MS) };
    }

    fn receive_advertisement(
        &mut self,
        router: Ipv6Addr,
        router_mac: [u8; 6],
        options: RouterAdvertisement,
        now: u64,
        requires_router: impl Fn(Ipv6Addr) -> bool,
        emit: &mut impl FnMut(Output),
    ) {
        if let State::Bound(binding) = &mut self.state {
            if binding.active(now) && binding.router == router && binding.router_mac == router_mac {
                binding.refresh(&options, now);
            }
            return;
        }
        let candidate = self.select_binding(router, router_mac, &options, now, requires_router);
        if matches!(self.state, State::WaitForRouter { .. }) {
            if let Some(binding) = candidate {
                self.probe_address(binding, now, emit);
            }
        } else if matches!(self.state, State::WaitToProbe(_) | State::ProbeLinkLocal(_)) {
            if self.advertisements.len() == MAX_ADVERTISEMENTS {
                self.advertisements.pop_front();
            }
            self.advertisements.push_back(candidate);
        }
    }

    fn select_binding(
        &self,
        router: Ipv6Addr,
        router_mac: [u8; 6],
        options: &RouterAdvertisement,
        now: u64,
        requires_router: impl Fn(Ipv6Addr) -> bool,
    ) -> Option<Binding> {
        let mut best: Option<(u8, Prefix, bool)> = None;
        for &prefix in &options.prefixes {
            if prefix.preferred_seconds == 0 || prefix.valid_seconds == 0 || (!prefix.on_link && !self.allow_non_on_link) {
                continue;
            }
            let needs_router = !prefix.on_link || requires_router(prefix.network);
            if needs_router && options.lifetime_seconds == 0 {
                continue;
            }
            let rank = if !needs_router { 0 }
                else if prefix.network.octets()[0] & 0xe0 == 0x20 { 1 }
                else { 2 };
            if best.is_none_or(|(previous, _, _)| rank < previous) {
                best = Some((rank, prefix, needs_router));
            }
            if rank == 0 {
                break;
            }
        }
        let (_, prefix, needs_router) = best?;
        Some(Binding {
            configuration: Configuration {
                address: address_in(prefix.network, self.interface_id),
                on_link_prefix: prefix.on_link.then_some(prefix.network),
                default_router: needs_router.then_some(router),
                mtu: self.mtu.min(options.mtu.unwrap_or(self.mtu)),
            },
            router,
            router_mac,
            prefix,
            address_expiry: prefix_expiry(prefix, now),
            router_expiry: if needs_router { deadline(now, options.lifetime_seconds.into()) } else { u64::MAX },
        })
    }

    fn resolve_neighbor(&mut self, target: Ipv6Addr, mac: [u8; 6], now: u64, emit: &mut impl FnMut(Output)) {
        let Some(pending) = self.pending.remove(&target) else { return };
        if self.configuration(now).is_none() {
            return;
        }
        self.cache(target, Some(mac), now.saturating_add(30_000));
        for payload in pending.packets {
            emit(Output::Frame(frame(self.mac, mac, &payload)));
        }
    }

    fn retry_neighbors(&mut self, now: u64, emit: &mut impl FnMut(Output)) {
        let mut expired = Vec::new();
        let (source_mac, source_address) = (self.mac, self.link_local);
        self.pending.retain(|&target, pending| {
            if pending.deadline > now {
                return true;
            }
            if pending.probes == MAX_SOLICITATIONS {
                expired.push(target);
                return false;
            }
            emit(neighbor_probe(source_mac, source_address, target));
            pending.probes += 1;
            pending.deadline = now.saturating_add(NEIGHBOR_WAIT_MS);
            true
        });
        for target in expired {
            self.cache(target, None, now.saturating_add(3_000));
        }
    }

    fn cache(&mut self, target: Ipv6Addr, mac: Option<[u8; 6]>, expiry: u64) {
        if self.neighbors.contains_key(&target) {
            self.neighbor_order.retain(|&address| address != target);
        } else if self.neighbor_order.len() == MAX_NEIGHBORS {
            if let Some(oldest) = self.neighbor_order.pop_front() {
                self.neighbors.remove(&oldest);
            }
        }
        self.neighbor_order.push_back(target);
        self.neighbors.insert(target, Neighbor { mac, expiry });
    }

    fn control(&self, payload: &[u8], destination: [u8; 6], emit: &mut impl FnMut(Output)) {
        emit(Output::Control(frame(self.mac, destination, payload)));
    }
}

fn frame(source: [u8; 6], destination: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETHERNET_HEADER + payload.len());
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(payload);
    frame
}

fn neighbor_probe(mac: [u8; 6], source: Ipv6Addr, target: Ipv6Addr) -> Output {
    let payload = wire::solicitation(source, target, mac);
    Output::Control(frame(mac, multicast_mac(solicited_node(target)), &payload))
}

fn address_in(network: Ipv6Addr, interface_id: [u8; 8]) -> Ipv6Addr {
    let mut address = network.octets();
    address[8..].copy_from_slice(&interface_id);
    Ipv6Addr::from(address)
}

fn deadline(now: u64, seconds: u32) -> u64 {
    now.saturating_add(u64::from(seconds) * 1_000)
}

fn prefix_expiry(prefix: Prefix, now: u64) -> u64 {
    deadline(now, prefix.preferred_seconds.min(prefix.valid_seconds))
}

#[cfg(test)]
mod tests;
