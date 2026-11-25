use super::{
    BROADCAST, Lease, MacAddress, Random, usable_address, usable_mac,
    wire::{self, ACK, BROADCAST_ADDRESS, DECLINE, DISCOVER, NAK, OFFER, RELEASE, REQUEST, Reply, Request, RequestFrame},
};

const INFINITE_LEASE: u64 = u32::MAX as u64;
const NO_WAKE: u64 = u64::MAX;
const MAXIMUM_REQUEST_ATTEMPTS: u8 = 4;

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Stopped,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    DeclineWait,
}

#[derive(Default)]
pub(super) struct Step {
    pub(super) frame: Option<RequestFrame>,
    pub(super) lease: Option<Lease>,
    pub(super) lease_lost: bool,
    pub(super) check_address: bool,
    pub(super) resolve_next_hop: Option<u32>,
}

/// DHCP requests use monotonic deadlines measured from the first request of a
/// transaction. A stale or malformed reply cannot change the installed lease.
pub(super) struct Client {
    mac: MacAddress,
    maximum_message_size: u16,
    state: State,
    wake_at: u64,
    transaction_started_at: u64,
    request_sent_at: Option<u64>,
    transaction_id: u32,
    attempts: u8,
    selected_address: u32,
    selected_server: u32,
    lease: Option<Lease>,
    known_server_mac: Option<MacAddress>,
}

impl Client {
    pub(super) fn new(mac: MacAddress, maximum_message_size: u16) -> Self {
        Self {
            mac,
            maximum_message_size,
            state: State::Stopped,
            wake_at: NO_WAKE,
            transaction_started_at: 0,
            request_sent_at: None,
            transaction_id: 0,
            attempts: 0,
            selected_address: 0,
            selected_server: 0,
            lease: None,
            known_server_mac: None,
        }
    }

    pub(super) fn start(&mut self, now_ms: u64, random: &mut Random) -> Step {
        self.begin_discovery(now_ms, random)
    }

    pub(super) fn receive(&mut self, frame: &[u8], now_ms: u64, random: &mut Random) -> Step {
        if self.expired(now_ms) {
            return self.begin_discovery(now_ms, random);
        }
        if !matches!(
            self.state,
            State::Selecting | State::Requesting | State::Renewing | State::Rebinding
        ) {
            return Step::default();
        }
        let configured_address = self.lease.as_ref().map_or(0, |lease| lease.address);
        let Some(reply) = wire::decode(frame, self.mac, self.transaction_id, configured_address) else {
            return Step::default();
        };

        if self.state == State::Selecting {
            if reply.kind != OFFER
                || !usable_address(reply.offered_address)
                || reply.lease_seconds().is_none_or(|seconds| seconds == 0)
            {
                return Step::default();
            }
            self.selected_address = reply.offered_address;
            self.selected_server = reply.server_id;
            self.state = State::Requesting;
            self.attempts = 0;
            return self.request_selection(now_ms);
        }
        let Some(request_start) = self.request_sent_at else {
            return Step::default();
        };
        if self.state != State::Rebinding && reply.server_id != self.selected_server {
            return Step::default();
        }
        if reply.kind == NAK {
            return self.begin_discovery(now_ms, random);
        }
        if reply.kind != ACK {
            return Step::default();
        }
        let address = if reply.offered_address == 0 {
            configured_address
        } else {
            reply.offered_address
        };
        if address != self.selected_address || !usable_address(address) {
            return Step::default();
        }
        self.bind(reply, address, request_start, now_ms, random).unwrap_or_default()
    }

    pub(super) fn tick(
        &mut self,
        now_ms: u64,
        random: &mut Random,
        mut resolve: impl FnMut(u32) -> Option<MacAddress>,
    ) -> Step {
        if self.wake_at == NO_WAKE || now_ms < self.wake_at {
            return Step::default();
        }
        if self.expired(now_ms) {
            return self.begin_discovery(now_ms, random);
        }
        match self.state {
            State::Selecting => self.discover(now_ms),
            State::Requesting if self.attempts < MAXIMUM_REQUEST_ATTEMPTS => self.request_selection(now_ms),
            State::Requesting | State::DeclineWait => self.begin_discovery(now_ms, random),
            State::Bound | State::Renewing | State::Rebinding => self.renew_or_rebind(now_ms, random, &mut resolve),
            State::Stopped => Step::default(),
        }
    }

    pub(super) fn decline(&mut self, now_ms: u64) -> Step {
        let Some(lease) = self.lease.as_ref() else {
            return Step::default();
        };
        let packet = Request {
            requested_address: lease.address,
            server_id: lease.server_identifier,
            ..self.request(DECLINE, 0)
        };
        self.clear_lease();
        self.state = State::DeclineWait;
        self.wake_at = now_ms.saturating_add(10_000);
        Step {
            frame: Some(packet.encode()),
            lease_lost: true,
            ..Step::default()
        }
    }

    pub(super) fn stop(&mut self, mut resolve: impl FnMut(u32) -> Option<MacAddress>) -> Step {
        let had_lease = self.lease.is_some();
        let frame = self.lease.as_ref().and_then(|lease| {
            let hop = lease.next_hop(lease.server_identifier)?;
            let destination_mac = self.resolve_mac(lease, hop, &mut resolve)?;
            Some(
                Request {
                    client_address: lease.address,
                    destination: lease.server_identifier,
                    destination_mac,
                    server_id: lease.server_identifier,
                    ..self.request(RELEASE, 0)
                }
                .encode(),
            )
        });
        self.clear_lease();
        self.state = State::Stopped;
        self.wake_at = NO_WAKE;
        Step { frame, lease_lost: had_lease, ..Step::default() }
    }

    fn bind(
        &mut self,
        reply: Reply,
        address: u32,
        request_start: u64,
        now_ms: u64,
        random: &mut Random,
    ) -> Option<Step> {
        let duration_seconds = reply.lease_seconds()?;
        if duration_seconds == 0 {
            return None;
        }
        let (expires_at_ms, renew_at_ms, rebind_at_ms) = if duration_seconds == INFINITE_LEASE {
            (NO_WAKE, NO_WAKE, NO_WAKE)
        } else {
            let lifetime = duration_seconds * 1000;
            let expires_at = request_start.saturating_add(lifetime);
            if now_ms >= expires_at {
                return Some(self.begin_discovery(now_ms, random));
            }
            let mut renew = reply.renewal_seconds()? * 1000;
            let mut rebind = reply.rebinding_seconds()? * 1000;
            if renew == 0 {
                renew = lifetime / 2;
            }
            if rebind == 0 {
                rebind = lifetime * 7 / 8;
            }
            if renew >= rebind || rebind >= lifetime {
                renew = lifetime / 2;
                rebind = lifetime * 7 / 8;
            }
            (
                expires_at,
                request_start.saturating_add(renew),
                request_start.saturating_add(rebind),
            )
        };
        let bound = Lease {
            address,
            prefix_length: reply.prefix_length(address)?,
            server_identifier: reply.server_id,
            duration_seconds,
            renew_at_ms,
            rebind_at_ms,
            expires_at_ms,
            dns: reply.dns()?,
            routes: reply.routes()?,
        };
        let check_address = self.lease.is_none();
        self.selected_address = bound.address;
        self.selected_server = bound.server_identifier;
        self.known_server_mac = (reply.source_address == reply.server_id).then_some(reply.source_mac);
        self.state = State::Bound;
        self.wake_at = renew_at_ms;
        self.lease = Some(bound.clone());
        Some(Step { lease: Some(bound), check_address, ..Step::default() })
    }

    fn renew_or_rebind(
        &mut self,
        now_ms: u64,
        random: &mut Random,
        resolve: &mut impl FnMut(u32) -> Option<MacAddress>,
    ) -> Step {
        let Some(lease) = self.lease.as_ref() else {
            return Step::default();
        };
        let (address, server, rebind_at, expires_at) =
            (lease.address, lease.server_identifier, lease.rebind_at_ms, lease.expires_at_ms);
        let broadcast = now_ms >= rebind_at;
        let next_hop = (!broadcast).then(|| lease.next_hop(server)).flatten();
        let destination_mac = if broadcast {
            Some(BROADCAST)
        } else {
            next_hop.and_then(|hop| self.resolve_mac(lease, hop, resolve))
        };
        let next_state = if broadcast { State::Rebinding } else { State::Renewing };
        if self.state != next_state {
            self.state = next_state;
            self.start_transaction(now_ms, random);
        }
        let end = if broadcast { expires_at } else { rebind_at };
        let Some(destination_mac) = destination_mac else {
            self.wake_at = next_hop.map_or(end, |_| end.min(now_ms.saturating_add(1000)));
            return Step { resolve_next_hop: next_hop, ..Step::default() };
        };
        self.request_sent_at.get_or_insert(now_ms);
        self.wake_at = end.min(now_ms.saturating_add(60_000.max(end.saturating_sub(now_ms) / 2)));
        let packet = Request {
            client_address: address,
            destination: if broadcast { BROADCAST_ADDRESS } else { server },
            destination_mac,
            ..self.request(REQUEST, now_ms.saturating_sub(self.transaction_started_at))
        };
        Step { frame: Some(packet.encode()), ..Step::default() }
    }

    fn resolve_mac(
        &self,
        lease: &Lease,
        hop: u32,
        resolve: &mut impl FnMut(u32) -> Option<MacAddress>,
    ) -> Option<MacAddress> {
        resolve(hop).filter(|&mac| usable_mac(mac)).or_else(|| {
            if hop == lease.server_identifier {
                self.known_server_mac
            } else {
                None
            }
        })
    }

    fn begin_discovery(&mut self, now_ms: u64, random: &mut Random) -> Step {
        let had_lease = self.lease.is_some();
        self.clear_lease();
        self.state = State::Selecting;
        self.start_transaction(now_ms, random);
        let mut step = self.discover(now_ms);
        step.lease_lost = had_lease;
        step
    }

    fn discover(&mut self, now_ms: u64) -> Step {
        self.schedule_acquisition_retry(now_ms);
        let packet = self.request(DISCOVER, now_ms.saturating_sub(self.transaction_started_at));
        Step { frame: Some(packet.encode()), ..Step::default() }
    }

    fn request_selection(&mut self, now_ms: u64) -> Step {
        self.request_sent_at.get_or_insert(now_ms);
        self.schedule_acquisition_retry(now_ms);
        let packet = Request {
            requested_address: self.selected_address,
            server_id: self.selected_server,
            ..self.request(REQUEST, now_ms.saturating_sub(self.transaction_started_at))
        };
        Step { frame: Some(packet.encode()), ..Step::default() }
    }

    fn request(&self, kind: u8, elapsed_ms: u64) -> Request {
        Request {
            kind,
            xid: self.transaction_id,
            elapsed_ms,
            mac: self.mac,
            client_address: 0,
            destination: BROADCAST_ADDRESS,
            destination_mac: BROADCAST,
            requested_address: 0,
            server_id: 0,
            maximum_message_size: self.maximum_message_size,
        }
    }

    fn start_transaction(&mut self, now_ms: u64, random: &mut Random) {
        let next_id = random.next();
        self.transaction_id = if next_id == self.transaction_id { !next_id } else { next_id };
        self.transaction_started_at = now_ms;
        self.attempts = 0;
        self.request_sent_at = None;
    }

    fn clear_lease(&mut self) {
        self.lease = None;
        self.known_server_mac = None;
        self.selected_address = 0;
        self.selected_server = 0;
    }

    fn expired(&self, now_ms: u64) -> bool {
        self.lease.as_ref().is_some_and(|lease| now_ms >= lease.expires_at_ms)
    }

    fn schedule_acquisition_retry(&mut self, now_ms: u64) {
        let mix = self.transaction_id.wrapping_mul(0x9e37_79b9).rotate_left(u32::from(self.attempts) * 7 + 5);
        let jitter = (mix as i32).rem_euclid(2001) - 1000;
        let interval = (4000 << self.attempts) + jitter;
        self.wake_at = now_ms.saturating_add(interval.min(64_000) as u64);
        self.attempts = (self.attempts + 1).min(MAXIMUM_REQUEST_ATTEMPTS);
    }
}
