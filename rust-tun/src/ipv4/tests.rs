use super::{
    ARP, BROADCAST, IPV4, Lease, MacAddress, Output, Random, Route, Session, UNKNOWN,
    dhcp::Client,
    ethernet::{EthernetLink, arp_frame, parse_arp},
    put_u16, put_u32, read_u16, read_u32,
    wire::{ACK, DECLINE, DISCOVER, NAK, OFFER, RELEASE, REQUEST},
};

const MAC: MacAddress = [2, 0, 0, 0, 0, 42];
const SERVER_MAC: MacAddress = [2, 0, 0, 0, 0, 1];
const GATEWAY_MAC: MacAddress = [2, 0, 0, 0, 0, 2];
// IANA documentation ranges keep fixtures separate from deployment addresses.
const ADDRESS: u32 = 0xc000_026e;
const SERVER: u32 = 0xc000_0201;
const GATEWAY: u32 = 0xc000_0202;
const OTHER_SERVER: u32 = 0xcb00_7101;
const DNS: u32 = 0xc633_6435;

const IP: usize = 14;
const UDP: usize = 34;
const DHCP: usize = 42;
const OPTIONS: usize = DHCP + 240;

#[derive(Default)]
struct Collected {
    frames: Vec<(Vec<u8>, bool)>,
    packets: Vec<Vec<u8>>,
    leases: Vec<Option<Lease>>,
}

impl Collected {
    fn last_frame(&self) -> &[u8] {
        &self.frames.last().unwrap().0
    }
}

impl Output for Collected {
    fn frame(&mut self, data: &[u8], control: bool) {
        self.frames.push((data.to_vec(), control));
    }
    fn packet(&mut self, data: &[u8]) {
        self.packets.push(data.to_vec());
    }
    fn lease(&mut self, lease: Option<&Lease>) {
        self.leases.push(lease.cloned());
    }
}

// Compute the fixtures independently of the production DHCP encoder.
fn ones_complement(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for (index, value) in parts.iter().copied().flatten().copied().enumerate() {
        sum += if index % 2 == 0 { u32::from(value) << 8 } else { u32::from(value) };
        if sum > 0xffff {
            sum = (sum & 0xffff) + 1;
        }
    }
    !(sum as u16)
}

fn udp_checksum(frame: &[u8]) -> u16 {
    let udp_length = read_u16(frame, UDP + 4).to_be_bytes();
    ones_complement(&[&frame[IP + 12..IP + 20], &[0, 17, udp_length[0], udp_length[1]], &frame[UDP..]])
}

fn checksums(frame: &mut [u8]) {
    put_u16(frame, IP + 10, 0);
    put_u16(frame, UDP + 6, 0);
    let ip_checksum = ones_complement(&[&frame[IP..UDP]]);
    put_u16(frame, IP + 10, ip_checksum);
    let value = udp_checksum(frame);
    put_u16(frame, UDP + 6, if value == 0 { u16::MAX } else { value });
}

fn reply(
    xid: u32,
    kind: u8,
    address: u32,
    server: u32,
    destination: u32,
    options: &[Vec<u8>],
) -> [u8; 342] {
    let mut frame = [0; 342];
    frame[..6].copy_from_slice(if destination == u32::MAX { &BROADCAST } else { &MAC });
    frame[6..12].copy_from_slice(&SERVER_MAC);
    put_u16(&mut frame, 12, IPV4);
    frame[IP] = 0x45;
    put_u16(&mut frame, IP + 2, 328);
    frame[IP + 8] = 64;
    frame[IP + 9] = 17;
    put_u32(&mut frame, IP + 12, server);
    put_u32(&mut frame, IP + 16, destination);
    put_u16(&mut frame, UDP, 67);
    put_u16(&mut frame, UDP + 2, 68);
    put_u16(&mut frame, UDP + 4, 308);
    frame[DHCP..DHCP + 3].copy_from_slice(&[2, 1, 6]);
    put_u32(&mut frame, DHCP + 4, xid);
    put_u32(&mut frame, DHCP + 16, address);
    frame[DHCP + 28..DHCP + 34].copy_from_slice(&MAC);
    put_u32(&mut frame, DHCP + 236, 0x6382_5363);
    frame[OPTIONS..OPTIONS + 3].copy_from_slice(&[53, 1, kind]);
    frame[OPTIONS + 3..OPTIONS + 9].copy_from_slice(&opt32(54, server));
    let mut cursor = OPTIONS + 9;
    for option in options {
        frame[cursor..cursor + option.len()].copy_from_slice(option);
        cursor += option.len();
    }
    frame[cursor] = 255;
    checksums(&mut frame);
    frame
}

fn opt(number: u8, value: &[u8]) -> Vec<u8> {
    let mut option = vec![number, value.len() as u8];
    option.extend_from_slice(value);
    option
}

fn opt32(number: u8, value: u32) -> Vec<u8> {
    opt(number, &value.to_be_bytes())
}

fn option(frame: &[u8], requested: u8) -> Option<&[u8]> {
    let mut rest = &frame[OPTIONS..];
    while let Some((&number, bytes)) = rest.split_first() {
        rest = bytes;
        match number {
            0 => {}
            255 => return None,
            _ => {
                let (&length, values) = rest.split_first().unwrap();
                let (value, tail) = values.split_at(usize::from(length));
                if number == requested {
                    return Some(value);
                }
                rest = tail;
            }
        }
    }
    panic!("missing DHCP option terminator");
}

fn xid(frame: &[u8]) -> u32 {
    read_u32(frame, DHCP + 4)
}

fn check_request(frame: &[u8], kind: u8, source: u32, destination: u32, hardware: MacAddress) {
    assert_eq!(frame[..6], hardware);
    assert_eq!(frame[6..12], MAC);
    assert_eq!(read_u16(frame, UDP), 68);
    assert_eq!(read_u16(frame, UDP + 2), 67);
    assert_eq!(option(frame, 53), Some(&[kind][..]));
    assert_eq!(read_u32(frame, IP + 12), source);
    assert_eq!(read_u32(frame, IP + 16), destination);
    assert_eq!(read_u32(frame, DHCP + 12), source);
    assert_eq!(ones_complement(&[&frame[IP..UDP]]), 0);
    assert_eq!(udp_checksum(frame), 0);
}

fn select(client: &mut Client, random: &mut Random, server: u32) -> u32 {
    let tx = xid(&client.start(0, random).frame.unwrap());
    let offer = reply(tx, OFFER, ADDRESS, server, u32::MAX, &[opt32(51, 120)]);
    let request = client.receive(&offer, 10, random).frame.unwrap();
    assert_eq!(xid(&request), tx);
    tx
}

fn acquire(client: &mut Client, random: &mut Random, server: u32, options: &[Vec<u8>]) -> Lease {
    let tx = select(client, random, server);
    let ack = reply(tx, ACK, ADDRESS, server, u32::MAX, options);
    let bound = client.receive(&ack, 20, random);
    assert!(bound.check_address);
    bound.lease.unwrap()
}

#[test]
fn acquires_lease_with_classless_routes_and_releases_it() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let discover = client.start(0, &mut random).frame.unwrap();
    check_request(&discover, DISCOVER, 0, u32::MAX, BROADCAST);
    assert_eq!(option(&discover, 55), Some(&[1, 121, 3, 6, 58, 59][..]));
    assert_eq!(option(&discover, 61), Some(&[1, 2, 0, 0, 0, 0, 42][..]));
    assert_eq!(read_u16(&discover, 20), 0x4000);
    assert_eq!(read_u16(&discover, DHCP + 10), 0x8000);

    let tx = xid(&discover);
    let offer = reply(tx, OFFER, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    let request = client.receive(&offer, 20, &mut random).frame.unwrap();
    check_request(&request, REQUEST, 0, u32::MAX, BROADCAST);
    assert_eq!(xid(&request), tx);
    assert_eq!(option(&request, 50), Some(&ADDRESS.to_be_bytes()[..]));
    assert_eq!(option(&request, 54), Some(&SERVER.to_be_bytes()[..]));

    let mut routes = vec![19, 198, 51, 111];
    routes.extend(GATEWAY.to_be_bytes());
    routes.push(0);
    routes.extend(GATEWAY.to_be_bytes());
    let ack = reply(
        tx, ACK, ADDRESS, SERVER, ADDRESS,
        &[opt32(51, 120), opt32(1, 0xffff_ff00), opt32(3, SERVER), opt32(6, DNS), opt(121, &routes)],
    );
    let bound = client.receive(&ack, 100, &mut random);
    assert!(bound.check_address);
    let lease = bound.lease.unwrap();
    assert_eq!((lease.address, lease.server_identifier, lease.prefix_length), (ADDRESS, SERVER, 24));
    assert_eq!(lease.dns, [DNS]);
    assert_eq!(
        lease.routes,
        [
            Route { destination: 0xc633_6000, prefix_length: 19, gateway: GATEWAY },
            Route { destination: 0, prefix_length: 0, gateway: GATEWAY },
        ]
    );
    assert_eq!(lease.next_hop(SERVER), Some(SERVER));
    assert_eq!(lease.next_hop(DNS), Some(GATEWAY));
    assert_eq!(
        (lease.renew_at_ms, lease.rebind_at_ms, lease.expires_at_ms),
        (60_020, 105_020, 120_020)
    );
    let stopped = client.stop(|_| None);
    assert!(stopped.lease_lost);
    check_request(&stopped.frame.unwrap(), RELEASE, ADDRESS, SERVER, SERVER_MAC);
}

#[test]
fn ignores_bad_frames_and_acknowledgements() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let tx = xid(&client.start(0, &mut random).frame.unwrap());
    let offer = reply(tx, OFFER, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    for length in 0..offer.len() {
        assert!(client.receive(&offer[..length], 1, &mut random).frame.is_none());
    }
    for (offset, recompute) in [
        (0, false), (DHCP + 4, true), (DHCP + 28, true), (DHCP + 236, true),
        (IP + 10, false), (UDP + 7, false),
    ] {
        let mut changed = offer;
        changed[offset] ^= 1;
        if recompute {
            checksums(&mut changed);
        }
        assert!(client.receive(&changed, 1, &mut random).frame.is_none(), "offset {offset}");
    }
    let wrong_id = reply(tx, OFFER, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120), opt(61, &[1, 2, 0, 0, 0, 0, 55])]);
    assert!(client.receive(&wrong_id, 1, &mut random).frame.is_none());
    assert!(client.receive(&offer, 1, &mut random).frame.is_some());

    for (address, server, options) in [
        (ADDRESS + 1, SERVER, vec![opt32(51, 120)]),
        (ADDRESS, OTHER_SERVER, vec![opt32(51, 120)]),
        (ADDRESS, SERVER, vec![opt32(51, 120), opt32(1, 0xff00_ff00)]),
        (ADDRESS, SERVER, vec![opt32(51, 120), opt32(54, OTHER_SERVER)]),
        (ADDRESS, SERVER, vec![opt32(51, 120), opt(121, &[20, 198])]),
    ] {
        let frame = reply(tx, ACK, address, server, u32::MAX, &options);
        assert!(client.receive(&frame, 2, &mut random).lease.is_none());
    }
    let mut ack = reply(tx, ACK, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    put_u16(&mut ack, UDP + 6, 0); // A zero UDP checksum is permitted on IPv4.
    assert!(client.receive(&ack, 2, &mut random).lease.is_some());
}

#[test]
fn renews_unicast_then_rebinds_with_a_new_transaction() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let lease = acquire(&mut client, &mut random, SERVER, &[opt32(51, 120), opt32(1, 0xffff_ff00)]);
    assert!(client.tick(lease.renew_at_ms - 1, &mut random, |_| None).frame.is_none());
    let renewal = client.tick(lease.renew_at_ms, &mut random, |_| None).frame.unwrap();
    check_request(&renewal, REQUEST, ADDRESS, SERVER, SERVER_MAC);
    assert!(option(&renewal, 50).is_none() && option(&renewal, 54).is_none());
    assert_eq!(read_u16(&renewal, DHCP + 10), 0);
    let rebound = client.tick(lease.rebind_at_ms, &mut random, |_| None).frame.unwrap();
    check_request(&rebound, REQUEST, ADDRESS, u32::MAX, BROADCAST);
    assert_ne!(xid(&renewal), xid(&rebound));
    let stale = reply(xid(&renewal), ACK, ADDRESS, SERVER, ADDRESS, &[opt32(51, 120)]);
    assert!(client.receive(&stale, lease.rebind_at_ms + 1, &mut random).lease.is_none());
    let replacement = reply(
        xid(&rebound), ACK, ADDRESS, OTHER_SERVER, ADDRESS, &[opt32(51, 200), opt32(3, GATEWAY)],
    );
    let updated = client.receive(&replacement, lease.rebind_at_ms + 10, &mut random);
    assert!(!updated.check_address);
    let lease_after = updated.lease.unwrap();
    assert_eq!(lease_after.server_identifier, OTHER_SERVER);
    assert_eq!(lease_after.expires_at_ms, lease.rebind_at_ms + 200_000);
}

#[test]
fn resolves_off_link_renewals_via_gateway_and_accepts_zero_yiaddr() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let options = [opt32(51, 1200), opt32(1, 0xffff_ff00), opt32(3, GATEWAY)];
    let lease = acquire(&mut client, &mut random, OTHER_SERVER, &options);
    let missing = client.tick(lease.renew_at_ms, &mut random, |hop| {
        assert_eq!(hop, GATEWAY);
        None
    });
    assert!(missing.frame.is_none());
    assert_eq!(missing.resolve_next_hop, Some(GATEWAY));
    let sent_at = lease.renew_at_ms + 1000;
    let renewal = client.tick(sent_at, &mut random, |hop| {
        assert_eq!(hop, GATEWAY);
        Some(GATEWAY_MAC)
    }).frame.unwrap();
    check_request(&renewal, REQUEST, ADDRESS, OTHER_SERVER, GATEWAY_MAC);
    let ack = reply(xid(&renewal), ACK, 0, OTHER_SERVER, ADDRESS, &options);
    let refreshed = client.receive(&ack, sent_at + 4, &mut random).lease.unwrap();
    assert_eq!(refreshed.address, ADDRESS);
    assert_eq!(refreshed.expires_at_ms, sent_at + 1_200_000);
}

#[test]
fn honors_lease_deadlines_and_infinite_duration() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let valid = acquire(&mut client, &mut random, SERVER, &[opt32(51, 120), opt32(58, 50), opt32(59, 100)]);
    assert_eq!((valid.renew_at_ms, valid.rebind_at_ms), (50_010, 100_010));
    let invalid = acquire(&mut client, &mut random, SERVER, &[opt32(51, 120), opt32(58, 104), opt32(59, 100)]);
    assert_eq!((invalid.renew_at_ms, invalid.rebind_at_ms), (60_010, 105_010));
    let expired = client.tick(invalid.expires_at_ms, &mut random, |_| None);
    assert!(expired.lease_lost);
    check_request(&expired.frame.unwrap(), DISCOVER, 0, u32::MAX, BROADCAST);
    let infinite = acquire(&mut client, &mut random, SERVER, &[opt32(51, u32::MAX)]);
    assert_eq!(infinite.duration_seconds, u64::from(u32::MAX));
    assert_eq!((infinite.renew_at_ms, infinite.expires_at_ms), (u64::MAX, u64::MAX));
    assert!(client.tick(5_000_000, &mut random, |_| None).frame.is_none());
}

#[test]
fn concatenates_routes_and_reads_overloaded_fields() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let tx = select(&mut client, &mut random, SERVER);
    let mut ack = reply(
        tx, ACK, ADDRESS, SERVER, u32::MAX,
        &[opt32(51, 120), opt32(3, GATEWAY), opt(52, &[3]), opt(121, &[24, 198, 51, 100, 0])],
    );
    ack[DHCP + 108..DHCP + 113].copy_from_slice(&[121, 3, 0, 0, 0]);
    ack[DHCP + 113] = 255;
    ack[DHCP + 44..DHCP + 50].copy_from_slice(&opt32(6, DNS));
    ack[DHCP + 50] = 255;
    checksums(&mut ack);
    let lease = client.receive(&ack, 20, &mut random).lease.unwrap();
    assert_eq!(lease.dns, [DNS]);
    assert_eq!(lease.routes, [Route { destination: 0xc633_6400, prefix_length: 24, gateway: 0 }]);
    assert_eq!(lease.next_hop(DNS), Some(DNS));
    assert_eq!(lease.next_hop(OTHER_SERVER), None);
}

#[test]
fn request_retries_preserve_id_until_new_discovery() {
    let mut client = Client::new(MAC, 1500);
    let mut random = Random::new();
    let tx = xid(&client.start(0, &mut random).frame.unwrap());
    assert!(client.tick(2999, &mut random, |_| None).frame.is_none());
    let retry = client.tick(5001, &mut random, |_| None).frame.unwrap();
    assert_eq!(xid(&retry), tx);
    let offer = reply(tx, OFFER, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    let request = client.receive(&offer, 5010, &mut random).frame.unwrap();
    assert_eq!(xid(&request), tx);
    for now in [11_000, 21_000, 39_000] {
        let retry = client.tick(now, &mut random, |_| None).frame.unwrap();
        assert_eq!(xid(&retry), tx);
        check_request(&retry, REQUEST, 0, u32::MAX, BROADCAST);
    }
    let restarted = client.tick(73_000, &mut random, |_| None).frame.unwrap();
    check_request(&restarted, DISCOVER, 0, u32::MAX, BROADCAST);
    assert_ne!(xid(&restarted), tx);
}

fn select_session(session: &mut Session, collected: &mut Collected) -> u32 {
    session.start(0, collected);
    let tx = xid(collected.last_frame());
    let offer = reply(tx, OFFER, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    session.receive(&offer, 10, collected);
    assert_eq!(option(collected.last_frame(), 53), Some(&[REQUEST][..]));
    tx
}

#[test]
fn probes_and_announces_before_publishing_then_withdraws_on_nak() {
    let mut session = Session::new(MAC, 1500).unwrap();
    let mut collected = Collected::default();
    let tx = select_session(&mut session, &mut collected);
    let invalid = reply(tx, ACK, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120), opt32(1, 0)]);
    session.receive(&invalid, 15, &mut collected);
    session.tick(17, &mut collected);
    assert_eq!(collected.frames.len(), 2);
    assert!(collected.leases.is_empty());

    let mut routes = vec![0];
    routes.extend(GATEWAY.to_be_bytes());
    let options = [opt32(51, 120), opt32(1, 0xffff_ff00), opt(121, &routes)];
    let ack = reply(tx, ACK, ADDRESS, SERVER, u32::MAX, &options);
    session.receive(&ack, 20, &mut collected);
    for now in [2020, 4020, 6020] {
        session.tick(now, &mut collected);
        assert!(collected.leases.is_empty());
        let arp = parse_arp(collected.last_frame()).unwrap();
        assert_eq!((arp.operation, arp.source, arp.target_ip), (1, 0, ADDRESS));
    }
    assert_eq!(collected.frames.len(), 5);
    session.tick(8019, &mut collected);
    assert!(collected.leases.is_empty());
    session.tick(8020, &mut collected);
    let lease = collected.leases[0].clone().unwrap();
    assert_eq!(lease.routes, [Route { destination: 0, prefix_length: 0, gateway: GATEWAY }]);
    let announced = parse_arp(collected.last_frame()).unwrap();
    assert_eq!((announced.source, announced.target_ip), (ADDRESS, ADDRESS));
    session.tick(10020, &mut collected);
    assert_eq!(collected.frames.len(), 7);
    session.tick(lease.renew_at_ms, &mut collected);
    let tx = xid(collected.last_frame());
    let ack = reply(tx, ACK, ADDRESS, SERVER, ADDRESS, &options);
    session.receive(&ack, lease.renew_at_ms + 1, &mut collected);
    assert_eq!(collected.leases.len(), 2);
    let renew_at = collected.leases[1].as_ref().unwrap().renew_at_ms;
    session.tick(renew_at, &mut collected);
    let tx = xid(collected.last_frame());
    let nak = reply(tx, NAK, 0, SERVER, u32::MAX, &[]);
    session.receive(&nak, renew_at + 1, &mut collected);
    assert_eq!(collected.leases.len(), 3);
    assert!(collected.leases[2].is_none());
    check_request(collected.last_frame(), DISCOVER, 0, u32::MAX, BROADCAST);
    assert!(collected.packets.is_empty());
    assert!(collected.frames.iter().all(|(_, control)| *control));
}

#[test]
fn detects_conflicts_and_delays_retry_for_unpublished_lease() {
    let mut session = Session::new(MAC, 1500).unwrap();
    let mut collected = Collected::default();
    let tx = select_session(&mut session, &mut collected);
    let ack = reply(tx, ACK, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    session.receive(&ack, 20, &mut collected);
    session.tick(2020, &mut collected);
    let echoed = collected.last_frame().to_vec();
    session.receive(&echoed, 2021, &mut collected);
    assert_eq!(collected.frames.len(), 3);
    let conflict = arp_frame(GATEWAY_MAC, BROADCAST, UNKNOWN, 1, ADDRESS, ADDRESS);
    session.receive(&conflict, 2022, &mut collected);
    check_request(collected.last_frame(), DECLINE, 0, u32::MAX, BROADCAST);
    assert_eq!(option(collected.last_frame(), 50), Some(&ADDRESS.to_be_bytes()[..]));
    session.tick(12021, &mut collected);
    assert_eq!(collected.frames.len(), 4);
    assert!(collected.leases.is_empty());
    session.tick(12022, &mut collected);
    check_request(collected.last_frame(), DISCOVER, 0, u32::MAX, BROADCAST);
    assert_ne!(xid(collected.last_frame()), tx);
}

fn packet(source: u32, destination: u32) -> [u8; 20] {
    let mut packet = [0; 20];
    packet[0] = 0x45;
    put_u16(&mut packet, 2, 20);
    put_u32(&mut packet, 12, source);
    put_u32(&mut packet, 16, destination);
    packet
}

#[test]
fn resolves_neighbors_and_forwards_ipv4_frames() {
    let mut link = EthernetLink::new(
        MAC, 1500,
        &Lease {
            address: ADDRESS, prefix_length: 24, server_identifier: SERVER, duration_seconds: 120,
            renew_at_ms: 60_000, rebind_at_ms: 105_000, expires_at_ms: 120_000, dns: vec![DNS],
            routes: vec![Route { destination: 0, prefix_length: 0, gateway: GATEWAY }],
        },
    );
    let mut out = Collected::default();
    let outbound = packet(ADDRESS, OTHER_SERVER);
    link.send(&packet(SERVER, OTHER_SERVER), 0, &mut out);
    assert!(out.frames.is_empty(), "reject unrelated TUN source");
    link.send(&outbound, 1, &mut out);
    assert!(out.frames[0].1);
    let arp = parse_arp(out.last_frame()).unwrap();
    assert_eq!((arp.operation, arp.source, arp.target_ip), (1, ADDRESS, GATEWAY));
    link.send(&outbound, 2, &mut out);
    assert_eq!(out.frames.len(), 1, "coalesce resolution");
    link.tick(1001, &mut out);
    assert_eq!(out.frames.len(), 2, "retry unresolved neighbor");
    let reply = arp_frame(GATEWAY_MAC, MAC, MAC, 2, GATEWAY, ADDRESS);
    link.receive(&reply, 1002, &mut out);
    assert_eq!(out.frames.len(), 4, "forward both queued packets");
    assert!(!out.frames[2].1);
    assert_eq!(out.last_frame()[..6], GATEWAY_MAC);
    assert_eq!(out.last_frame()[14..], outbound);

    link.send(&outbound, 1003, &mut out);
    assert_eq!(out.frames.len(), 5, "reuse the resolved neighbor");
    let inbound = packet(OTHER_SERVER, ADDRESS);
    let mut frame = [0; 40]; // Ethernet padding is never passed to the TUN.
    frame[..6].copy_from_slice(&MAC);
    frame[6..12].copy_from_slice(&GATEWAY_MAC);
    put_u16(&mut frame, 12, IPV4);
    frame[14..34].copy_from_slice(&inbound);
    link.receive(&frame, 1004, &mut out);
    frame[0] ^= 1;
    link.receive(&frame, 1005, &mut out);
    assert_eq!(out.packets, [inbound]);
    link.send(&outbound, 61_002, &mut out);
    assert_eq!(read_u16(out.last_frame(), 12), ARP, "resolve an expired neighbor again");
}

#[test]
fn routes_ipv4_broadcast_and_multicast_without_arp() {
    let mut link = EthernetLink::new(
        MAC, 1500,
        &Lease {
            address: ADDRESS, prefix_length: 24, server_identifier: SERVER, duration_seconds: 120,
            renew_at_ms: 60_000, rebind_at_ms: 105_000, expires_at_ms: 120_000, dns: Vec::new(), routes: Vec::new(),
        },
    );
    let mut out = Collected::default();
    let directed = packet(ADDRESS, 0xc000_02ff);
    link.send(&directed, 0, &mut out);
    assert_eq!(out.last_frame()[..6], BROADCAST);
    assert!(!out.frames.last().unwrap().1);
    let multicast = packet(ADDRESS, 0xe001_0203);
    link.send(&multicast, 0, &mut out);
    assert_eq!(out.last_frame()[..6], [1, 0, 0x5e, 1, 2, 3]);
    assert_eq!(out.last_frame()[14..], multicast);
}


#[test]
fn session_gates_data_on_published_lease_and_releases_when_stopped() {
    let mut session = Session::new(MAC, 1500).unwrap();
    let mut out = Collected::default();
    let outbound = packet(ADDRESS, u32::MAX);
    session.send(&outbound, 0, &mut out);
    assert!(out.frames.is_empty());

    let tx = select_session(&mut session, &mut out);
    let ack = reply(tx, ACK, ADDRESS, SERVER, u32::MAX, &[opt32(51, 120)]);
    session.receive(&ack, 20, &mut out);
    for now in [2020, 4020, 6020, 8020] {
        session.tick(now, &mut out);
    }
    assert_eq!(out.leases.len(), 1);
    assert!(out.leases[0].is_some());
    session.send(&outbound, 8021, &mut out);
    assert_eq!(out.last_frame()[14..], outbound);
    assert!(!out.frames.last().unwrap().1);

    session.stop(8022, &mut out);
    check_request(out.last_frame(), RELEASE, ADDRESS, SERVER, SERVER_MAC);
    assert_eq!(out.leases.last(), Some(&None));
    let frames = out.frames.len();
    session.send(&outbound, 8023, &mut out);
    session.tick(1_000_000, &mut out);
    assert_eq!(out.frames.len(), frames);
}
