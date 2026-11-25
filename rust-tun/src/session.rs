use crate::{batch, ipv4, ipv6};
use std::{collections::VecDeque, net::Ipv6Addr};

const CONTROL_QUEUE: usize = 32;
const PACKET_QUEUE: usize = 256;
const MAX_FRAME: usize = 1600;
const MAX_PREFIXES: usize = 256;

#[derive(Clone, Copy)]
struct Prefix {
    network: u128,
    bits: u32,
}

impl Prefix {
    fn new(address: u128, bits: u32) -> Option<Self> {
        if bits > 128 {
            return None;
        }
        let network = if bits == 0 { 0 } else { address & (u128::MAX << (128 - bits)) };
        Some(Self { network, bits })
    }

    fn contains(self, other: Self) -> bool {
        self.bits <= other.bits && Self::new(other.network, self.bits).unwrap().network == self.network
    }

    fn children(self) -> [Self; 2] {
        let bits = self.bits + 1;
        [Self { network: self.network, bits },
            Self { network: self.network | (1 << (128 - bits)), bits }]
    }
}

enum RouterPolicy {
    Always,
    OnLink,
    Routes { included: Vec<Prefix>, excluded: Vec<Prefix> },
}

impl RouterPolicy {
    fn requires_router(&self, on_link: Ipv6Addr) -> bool {
        match self {
            Self::Always => true,
            Self::OnLink => false,
            Self::Routes { included, excluded } => {
                let local = Prefix::new(u128::from(on_link), 64).unwrap();
                included.iter().any(|prefix| survives(*prefix, excluded, local))
            }
        }
    }
}

fn survives(prefix: Prefix, excluded: &[Prefix], local: Prefix) -> bool {
    if local.contains(prefix) || excluded.iter().any(|block| block.contains(prefix)) {
        return false;
    }
    if !prefix.contains(local) && !excluded.iter().any(|block| prefix.contains(*block)) {
        return true;
    }
    // At /128 any intersecting block already contains the prefix.
    prefix.children().into_iter().any(|child| survives(child, excluded, local))
}

pub struct Options {
    mac: [u8; 6],
    iid: [u8; 8],
    mtu: u16,
    ipv6: bool,
    allow_non_on_link: bool,
    delay: u16,
    router_policy: RouterPolicy,
}

impl Options {
    pub fn decode(mut bytes: &[u8]) -> Option<Self> {
        let mac = take(&mut bytes)?;
        let iid = take(&mut bytes)?;
        let mtu = u16::try_from(number(&mut bytes)?).ok()?;
        let flags = number(&mut bytes)?;
        let delay = u16::try_from(number(&mut bytes)?).ok()?;
        let include_count = number(&mut bytes)? as usize;
        let exclude_count = number(&mut bytes)? as usize;
        if flags & !15 != 0 || flags >> 2 > 2 || delay >= 1000
            || !(68..=(MAX_FRAME as u16 - 14)).contains(&mtu)
            || include_count > MAX_PREFIXES || exclude_count > MAX_PREFIXES
            || bytes.len() != (include_count + exclude_count) * 17
            || (flags >> 2 != 2 && (include_count != 0 || exclude_count != 0))
        {
            return None;
        }
        let mut prefixes = |count| -> Option<Vec<Prefix>> {
            (0..count).map(|_| {
                let address = u128::from_be_bytes(take(&mut bytes)?);
                Prefix::new(address, u32::from(take::<1>(&mut bytes)?[0]))
            }).collect()
        };
        let router_policy = match flags >> 2 {
            0 => RouterPolicy::Always,
            1 => RouterPolicy::OnLink,
            _ => RouterPolicy::Routes {
                included: prefixes(include_count)?,
                excluded: prefixes(exclude_count)?,
            },
        };
        Some(Self { mac, iid, mtu, ipv6: flags & 1 != 0, allow_non_on_link: flags & 2 != 0, delay, router_policy })
    }
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = bytes.split_at_checked(N)?;
    *bytes = tail;
    head.try_into().ok()
}

fn number(bytes: &mut &[u8]) -> Option<u32> {
    take(bytes).map(u32::from_ne_bytes)
}

struct PacketQueue {
    pending: VecDeque<Vec<u8>>,
    reusable: Vec<Vec<u8>>,
    limit: usize,
}

impl PacketQueue {
    fn new(limit: usize) -> Self {
        Self { pending: VecDeque::new(), reusable: Vec::new(), limit }
    }

    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() > MAX_FRAME || self.pending.len() >= self.limit {
            return;
        }
        let mut packet = self.reusable.pop().unwrap_or_default();
        packet.extend_from_slice(bytes);
        self.pending.push_back(packet);
    }

    fn push_owned(&mut self, packet: Vec<u8>) {
        if packet.len() <= MAX_FRAME && self.pending.len() < self.limit {
            self.pending.push_back(packet);
        }
    }

    fn recycle(&mut self) {
        if let Some(mut packet) = self.pending.pop_front() {
            packet.clear();
            if self.reusable.len() < self.limit {
                self.reusable.push(packet);
            }
        }
    }

    fn clear(&mut self) {
        while !self.pending.is_empty() {
            self.recycle();
        }
    }

    fn drain(
        &mut self, io: &mut impl batch::PacketIo, descriptor: i32, kind: batch::Kind, limit: usize,
    ) -> Result<(usize, u32), i32> {
        let mut packets = 0;
        let mut bytes = 0;
        while packets < limit {
            let Some(packet) = self.pending.front() else { break };
            match io.write(descriptor, packet, kind) {
                Ok(count) if count == packet.len() => {
                    packets += 1;
                    bytes += count as u32;
                    self.recycle();
                }
                Ok(_) => return Err(batch::EIO),
                Err(batch::EINTR | batch::EAGAIN) => break, // EINTR or EAGAIN, retry queued packets on the next poll.
                Err(error) => return Err(error),
            }
        }
        Ok((packets, bytes))
    }
}

struct Outgoing {
    control: PacketQueue,
    ethernet: PacketQueue,
    tun: PacketQueue,
    tun_active: bool,
    mtu: usize,
    lease: Option<ipv4::Lease>,
    lease_lost: bool,
    updated: bool,
}

impl Outgoing {
    fn new(mtu: usize) -> Self {
        Self {
            control: PacketQueue::new(CONTROL_QUEUE), ethernet: PacketQueue::new(PACKET_QUEUE),
            tun: PacketQueue::new(PACKET_QUEUE), tun_active: false, mtu,
            lease: None, lease_lost: false, updated: true,
        }
    }

    fn clear_data(&mut self) {
        self.ethernet.clear();
        self.tun.clear();
    }

    fn ipv6(&mut self, output: ipv6::Output) {
        match output {
            ipv6::Output::Control(frame) => self.control.push_owned(frame),
            ipv6::Output::Frame(frame) => self.ethernet.push_owned(frame),
            ipv6::Output::Packet(packet) if self.tun_active && packet.len() <= self.mtu => {
                self.tun.push_owned(packet);
            }
            ipv6::Output::Packet(_) => {}
        }
    }
}

impl ipv4::Output for Outgoing {
    fn frame(&mut self, data: &[u8], control: bool) {
        if control { self.control.push(data) } else { self.ethernet.push(data) }
    }

    fn packet(&mut self, data: &[u8]) {
        if self.tun_active && data.len() <= self.mtu {
            self.tun.push(data);
        }
    }

    fn lease(&mut self, lease: Option<&ipv4::Lease>) {
        let unchanged = match (&self.lease, lease) {
            (Some(previous), Some(current)) => previous.address == current.address
                && previous.prefix_length == current.prefix_length
                && previous.dns == current.dns && previous.routes == current.routes,
            (None, None) => true,
            _ => false,
        };
        if unchanged {
            return;
        }
        if lease.is_none() {
            self.lease_lost |= self.tun_active;
            self.tun_active = false;
            self.clear_data();
            self.control.clear();
        }
        self.lease = lease.cloned();
        self.updated = true;
    }
}

pub struct Session {
    ipv4: ipv4::Session,
    ipv6: Option<ipv6::Link>,
    ipv6_state: Option<ipv6::Status>,
    router_policy: RouterPolicy,
    out: Outgoing,
    frames: Vec<u8>,
    packets: Vec<u8>,
    mtu: usize,
}

impl Session {
    pub fn new(options: Options, now: u64) -> Option<Self> {
        let mtu = usize::from(options.mtu);
        let mut out = Outgoing::new(mtu);
        let mut ipv4 = ipv4::Session::new(options.mac, options.mtu)?;
        ipv4.start(now, &mut out);
        let ipv6 = options.ipv6.then(|| {
            ipv6::Link::new(options.mac, mtu, options.iid, now, options.delay, options.allow_non_on_link)
        });
        Some(Self {
            ipv4, ipv6, ipv6_state: None, router_policy: options.router_policy, out,
            frames: vec![0; batch::ARENA_SIZE], packets: vec![0; batch::ARENA_SIZE], mtu,
        })
    }

    pub fn step(
        &mut self, io: &mut impl batch::PacketIo, frame_fd: i32, tun_fd: i32, mtu: usize,
        reset_data: bool, now: u64, status: &mut [u8],
    ) -> Result<(), i32> {
        if tun_fd >= 0 && !(68..=self.mtu).contains(&mtu) {
            return Err(batch::EINVAL);
        }
        if reset_data {
            self.out.clear_data();
        }
        self.out.tun_active = tun_fd >= 0 && self.out.lease.is_some();
        self.out.mtu = mtu;
        self.ipv4.tick(now, &mut self.out);
        if let Some(link) = &mut self.ipv6 {
            link.tick(now, &mut |output| self.out.ipv6(output));
        }
        self.refresh_ipv6_state(now);
        if self.out.updated {
            return self.snapshot(0, 0, status);
        }

        let active_fd = if self.out.tun_active { tun_fd } else { -1 };
        let ready = batch::poll_read(
            io, [frame_fd, active_fd], [
                !self.out.control.pending.is_empty() || !self.out.ethernet.pending.is_empty(),
                !self.out.tun.pending.is_empty(),
            ], &mut self.frames, &mut self.packets,
        )?;
        for frame in batch::records(&self.frames, (ready & 63) as usize) {
            match frame.get(12..14) {
                Some([0x08, 0x00] | [0x08, 0x06]) => self.ipv4.receive(frame, now, &mut self.out),
                Some([0x86, 0xdd]) => if let Some(link) = &mut self.ipv6 {
                    link.receive(frame, now, |prefix| self.router_policy.requires_router(prefix),
                        &mut |output| self.out.ipv6(output));
                },
                _ => {}
            }
            if self.out.lease_lost {
                break;
            }
        }
        self.refresh_ipv6_state(now);
        if self.out.updated {
            return self.snapshot(0, 0, status);
        }

        let mut sent = 0;
        for packet in batch::records(&self.packets, ((ready >> 6) & 63) as usize) {
            if packet.len() > mtu { continue; }
            match packet[0] >> 4 {
                4 => self.ipv4.send(packet, now, &mut self.out),
                6 => if let Some(link) = &mut self.ipv6 {
                    link.send(packet, now, &mut |output| self.out.ipv6(output));
                },
                _ => continue,
            }
            sent += packet.len() as u32;
        }
        if ready & batch::FRAME_WRITABLE != 0 {
            self.flush_ethernet(io, frame_fd)?;
        }
        let received = if active_fd >= 0 && ready & batch::TUN_WRITABLE != 0 {
            self.out.tun.drain(io, active_fd, batch::Kind::Tun, batch::MAX_PACKETS)?.1
        } else { 0 };
        self.snapshot(received, sent, status)
    }

    fn refresh_ipv6_state(&mut self, now: u64) {
        if self.out.lease_lost {
            if let Some(link) = &mut self.ipv6 { link.clear_pending(); }
        }
        let state = self.ipv6.as_ref().map(|link| link.status(now));
        if self.ipv6_state != state {
            self.ipv6_state = state;
            self.out.updated = true;
        }
    }

    fn flush_ethernet(&mut self, io: &mut impl batch::PacketIo, descriptor: i32) -> Result<(), i32> {
        let requested = self.out.control.pending.len().min(batch::MAX_PACKETS);
        let (written, _) = self.out.control.drain(io, descriptor, batch::Kind::Ethernet, requested)?;
        if written == requested {
            self.out.ethernet.drain(io, descriptor, batch::Kind::Ethernet, batch::MAX_PACKETS - written)?;
        }
        Ok(())
    }

    pub fn stop(&mut self, io: &mut impl batch::PacketIo, frame_fd: i32, now: u64) {
        self.out.control.clear();
        self.out.clear_data();
        self.out.tun_active = false;
        self.ipv4.stop(now, &mut self.out);
        let _ = self.flush_ethernet(io, frame_fd);
    }

    fn snapshot(&mut self, received: u32, sent: u32, bytes: &mut [u8]) -> Result<(), i32> {
        let mut state = Snapshot(bytes);
        state.number(received)?;
        state.number(sent)?;
        state.number(u32::from(self.out.updated))?;
        if !self.out.updated {
            return Ok(());
        }
        state.number(u32::from(self.out.lease.is_some()) | u32::from(self.out.lease_lost) << 1)?;
        let ipv6_code = match &self.ipv6_state {
            None => 0,
            Some(ipv6::Status::Discovering) => 1,
            Some(ipv6::Status::Ready(_)) => 2,
            Some(ipv6::Status::Failed(ipv6::Failure::MtuTooSmall)) => 3,
            Some(ipv6::Status::Failed(ipv6::Failure::DuplicateAddress)) => 4,
            Some(ipv6::Status::Failed(ipv6::Failure::NoAdvertisement)) => 5,
            Some(ipv6::Status::Expired) => 6,
        };
        state.number(ipv6_code)?;
        if let Some(lease) = &self.out.lease {
            state.number(lease.address)?;
            state.number(u32::from(lease.prefix_length))?;
            state.number(lease.dns.len() as u32)?;
            state.number(lease.routes.len() as u32)?;
            for &dns in &lease.dns { state.number(dns)?; }
            for route in &lease.routes {
                state.number(route.destination)?;
                state.number(u32::from(route.prefix_length))?;
                state.number(route.gateway)?;
            }
        }
        if let Some(ipv6::Status::Ready(configuration)) = &self.ipv6_state {
            state.write(&configuration.address.octets())?;
            state.number(configuration.mtu as u32)?;
            state.number(u32::from(configuration.on_link_prefix.is_some())
                | u32::from(configuration.default_router.is_some()) << 1)?;
            if let Some(prefix) = configuration.on_link_prefix { state.write(&prefix.octets())?; }
        }
        self.out.updated = false;
        self.out.lease_lost = false;
        Ok(())
    }
}

struct Snapshot<'a>(&'a mut [u8]);

impl Snapshot<'_> {
    fn number(&mut self, value: u32) -> Result<(), i32> {
        self.write(&value.to_ne_bytes())
    }

    fn write(&mut self, data: &[u8]) -> Result<(), i32> {
        let bytes = std::mem::take(&mut self.0);
        let (target, rest) = bytes.split_at_mut_checked(data.len()).ok_or(batch::EINVAL)?;
        target.copy_from_slice(data);
        self.0 = rest;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(address: &str, bits: u32) -> Prefix {
        Prefix::new(u128::from(address.parse::<Ipv6Addr>().unwrap()), bits).unwrap()
    }

    #[test]
    fn checks_whether_android_captures_any_surviving_off_link_destination() {
        let network = "2001:db8:42:1::".parse().unwrap();
        let captured = prefix("2001:db8:42:1::", 64);
        let other = prefix("2001:db8:42::", 63);
        assert!(!RouterPolicy::Routes { included: vec![captured], excluded: vec![] }
            .requires_router(network));
        assert!(RouterPolicy::Routes { included: vec![other], excluded: vec![] }
            .requires_router(network));
        assert!(!RouterPolicy::Routes {
            included: vec![other],
            excluded: vec![prefix("2001:db8:42::", 65), prefix("2001:db8:42:0:8000::", 65)],
        }.requires_router(network));
        assert!(RouterPolicy::Always.requires_router(network));
        assert!(!RouterPolicy::OnLink.requires_router(network));
    }

    struct ShortWrite {
        remaining: usize,
        writes: Vec<Vec<u8>>,
    }

    impl batch::PacketIo for ShortWrite {
        fn poll(&mut self, _: [i32; 2], _: [i16; 2]) -> Result<[i16; 2], i32> {
            Ok([0, 0])
        }

        fn read(&mut self, _: i32, _: &mut [u8]) -> Result<usize, i32> {
            unreachable!("drain never reads")
        }

        fn write(&mut self, _: i32, packet: &[u8], _: batch::Kind) -> Result<usize, i32> {
            if self.remaining == 0 {
                return Err(batch::EAGAIN);
            }
            self.remaining -= 1;
            self.writes.push(packet.to_vec());
            Ok(packet.len())
        }
    }

    #[test]
    fn queued_packets_survive_backpressure_and_keep_their_order() {
        let mut queue = PacketQueue::new(2);
        queue.push(&[1, 2]);
        queue.push(&[3, 4, 5]);
        queue.push(&[6]); // Beyond the queue limit.
        let mut io = ShortWrite { remaining: 1, writes: vec![] };
        assert_eq!(queue.drain(&mut io, 1, batch::Kind::Tun, 48), Ok((1, 2)));
        assert_eq!(queue.drain(&mut io, 1, batch::Kind::Tun, 48), Ok((0, 0)));
        queue.push(&[7]);
        io.remaining = 2;
        assert_eq!(queue.drain(&mut io, 1, batch::Kind::Tun, 48), Ok((2, 4)));
        assert_eq!(io.writes, vec![vec![1, 2], vec![3, 4, 5], vec![7]]);
    }

    #[test]
    fn a_single_egress_batch_prioritizes_control_and_caps_data() {
        let options = Options {
            mac: [2, 0, 0, 0, 0, 1], iid: [0; 8], mtu: 68, ipv6: false,
            allow_non_on_link: false, delay: 0, router_policy: RouterPolicy::OnLink,
        };
        let mut session = Session::new(options, 0).unwrap();
        session.out.control.clear();
        session.out.control.push(&[8; 14]);
        for _ in 0..50 { session.out.ethernet.push(&[42; 82]); }
        let mut io = ShortWrite { remaining: 100, writes: vec![] };
        assert_eq!(session.flush_ethernet(&mut io, 7), Ok(()));
        assert_eq!(io.writes.len(), batch::MAX_PACKETS);
        assert_eq!(io.writes[0], vec![8; 14]);
        assert_eq!(io.writes[batch::MAX_PACKETS - 1], vec![42; 82]);
        assert_eq!(session.out.ethernet.pending.len(), 3);
    }

    #[test]
    fn lease_loss_discards_pending_traffic_before_announcing_the_change() {
        use crate::ipv4::Output;
        let mut out = Outgoing::new(1500);
        let mut lease = ipv4::Lease {
            address: 0xc000020a, prefix_length: 24, dns: vec![0xc0000201], routes: vec![],
            server_identifier: 0xc0000201, duration_seconds: 600, renew_at_ms: 300_000,
            rebind_at_ms: 525_000, expires_at_ms: 600_000,
        };
        out.lease(Some(&lease));
        out.updated = false;
        out.tun_active = true;
        out.packet(&[0x45; 20]);
        out.frame(&[1; 40], false);
        out.frame(&[2; 40], true);
        lease.renew_at_ms += 300_000;
        out.lease(Some(&lease));
        assert!(!out.updated && !out.tun.pending.is_empty());
        out.lease(None);
        assert!(out.lease_lost && out.updated && !out.tun_active);
        assert!(out.control.pending.is_empty() && out.ethernet.pending.is_empty() && out.tun.pending.is_empty());
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod integration_tests;
