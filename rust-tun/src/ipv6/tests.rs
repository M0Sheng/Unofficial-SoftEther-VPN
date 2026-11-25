use super::*;
use wire::{multicast_mac, solicited_node};

const CLIENT: [u8; 6] = [0x52, 1, 2, 3, 4, 5];
const ROUTER: [u8; 6] = [0x52, 6, 7, 8, 9, 10];
const PEER: [u8; 6] = [0x52, 11, 12, 13, 14, 15];

fn address(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

fn body_checksum(source: Ipv6Addr, destination: Ipv6Addr, body: &[u8]) -> u16 {
    let mut pseudo_header = source.octets().to_vec();
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(body.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 58]);
    pseudo_header.extend_from_slice(body);
    let mut sum: u32 = pseudo_header.chunks(2).map(|word| {
        let high = u32::from(word[0]) * 256;
        high + u32::from(word.get(1).copied().unwrap_or(0))
    }).sum();
    while sum > 65535 {
        sum = sum / 65536 + sum % 65536;
    }
    !(sum as u16)
}

fn raw(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    body: &[u8],
    protocol: u8,
    hop_limit: u8,
    extensions: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((extensions.len() + body.len()) as u16).to_be_bytes());
    packet[6] = protocol;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet.extend_from_slice(extensions);
    packet.extend_from_slice(body);
    if protocol == 58 || !extensions.is_empty() {
        let start = 40 + extensions.len();
        packet[start + 2..start + 4].fill(0);
        let checksum = body_checksum(source, destination, &packet[start..]);
        packet[start + 2..start + 4].copy_from_slice(&checksum.to_be_bytes());
    }
    packet
}

fn pio(network: Ipv6Addr, flags: u8, valid: u32, preferred: u32) -> [u8; 32] {
    let mut option = [0; 32];
    option[..4].copy_from_slice(&[3, 4, 64, flags]);
    option[4..8].copy_from_slice(&valid.to_be_bytes());
    option[8..12].copy_from_slice(&preferred.to_be_bytes());
    option[16..].copy_from_slice(&network.octets());
    option
}

fn mtu_option(mtu: u32) -> [u8; 8] {
    let mut option = [5, 1, 0, 0, 0, 0, 0, 0];
    option[4..].copy_from_slice(&mtu.to_be_bytes());
    option
}

fn ra_packet(source: Ipv6Addr, destination: Ipv6Addr, lifetime: u16, options: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[0] = 134;
    body[4] = 64;
    body[6..8].copy_from_slice(&lifetime.to_be_bytes());
    body.extend_from_slice(options);
    raw(source, destination, &body, 58, 255, &[])
}

fn router_advertisement(lifetime: u16, options: &[u8]) -> Vec<u8> {
    ra_packet(address("fe80::600"), ALL_NODES, lifetime, options)
}

fn control(bytes: &[u8]) -> Control {
    Packet::parse(bytes).unwrap().control()
}

fn parse_ra(bytes: &[u8]) -> RouterAdvertisement {
    match control(bytes) {
        Control::RouterAdvertisement(result) => result,
        other => panic!("expected RA, found {other:?}"),
    }
}

#[test]
fn bounds_non_jumbo_packet_and_ignores_ethernet_padding() {
    let source = address("2001:db8:1::1");
    let destination = address("2001:db8:2::1");
    let valid = raw(source, destination, &[1, 2, 3], 17, 3, &[]);
    let mut padded = valid.clone();
    padded.extend_from_slice(&[0; 12]);
    let packet = Packet::parse(&padded).unwrap();
    assert_eq!(packet.source, source);
    assert_eq!(packet.destination, destination);
    assert_eq!(packet.bytes, valid);
    assert!(Packet::parse(&valid[..42]).is_none());
    assert!(Packet::parse(&valid[..39]).is_none());
    padded[0] = 0x40;
    assert!(Packet::parse(&padded).is_none());
    padded[0] = 0x60;
    padded[4..6].fill(0);
    assert!(Packet::parse(&padded).is_none());
    padded[6] = 59;
    assert_eq!(Packet::parse(&padded).unwrap().bytes.len(), 40);
}

#[test]
fn solicitations_and_advertisements_have_exact_addresses_options_and_checksums() {
    let source = address("fe80::1");
    let target = address("2001:db8::aabb:ccdd");
    let group = address("ff02::1:ffbb:ccdd");
    assert_eq!(solicited_node(target), group);
    assert_eq!(multicast_mac(group), [0x33, 0x33, 0xff, 0xbb, 0xcc, 0xdd]);

    let rs = wire::router_solicitation(source, CLIENT);
    assert_eq!(Packet::parse(&rs).unwrap().destination, wire::ALL_ROUTERS);
    assert_eq!(&rs[48..], &[1, 1, 0x52, 1, 2, 3, 4, 5]);
    assert_eq!(body_checksum(source, wire::ALL_ROUTERS, &rs[40..]), 0);
    let unspecified_rs = wire::router_solicitation(Ipv6Addr::UNSPECIFIED, CLIENT);
    assert_eq!(unspecified_rs.len(), 48);
    assert_eq!(body_checksum(Ipv6Addr::UNSPECIFIED, wire::ALL_ROUTERS, &unspecified_rs[40..]), 0);

    let normal = wire::solicitation(source, target, CLIENT);
    assert_eq!(body_checksum(source, group, &normal[40..]), 0);
    assert!(matches!(control(&normal), Control::Solicitation(address) if address == target));
    let dad = wire::solicitation(Ipv6Addr::UNSPECIFIED, target, CLIENT);
    assert_eq!(dad.len(), 64);
    assert_eq!(body_checksum(Ipv6Addr::UNSPECIFIED, group, &dad[40..]), 0);
    assert!(matches!(control(&dad), Control::Solicitation(address) if address == target));
    let invalid_dad = raw(Ipv6Addr::UNSPECIFIED, group, &normal[40..], 58, 255, &[]);
    assert!(matches!(control(&invalid_dad), Control::Discard));

    let solicited = wire::neighbor_advertisement(target, source, PEER, true);
    assert_eq!(body_checksum(target, source, &solicited[40..]), 0);
    assert!(matches!(control(&solicited), Control::NeighborAdvertisement(na)
        if na.target == target && na.solicited && na.mac == Some(PEER)));
    let conflict = wire::neighbor_advertisement(target, ALL_NODES, PEER, false);
    assert_eq!(conflict[44], 0x20);
    assert_eq!(body_checksum(target, ALL_NODES, &conflict[40..]), 0);
    assert!(matches!(control(&conflict), Control::NeighborAdvertisement(na)
        if na.target == target && !na.solicited));
    assert!(matches!(control(&raw(target, ALL_NODES, &solicited[40..], 58, 255, &[])), Control::Discard));
}

#[test]
fn validates_ra_prefixes_lifetimes_mtu_and_options() {
    let prefix = address("2001:db8:1234:5678::1234");
    let non_on_link = address("fd12:3456:7890:1::9");
    let first = pio(prefix, 0xc0, 3600, 1800);
    let second = pio(non_on_link, 0x40, u32::MAX, u32::MAX);
    let mut opts = first.to_vec();
    opts.extend_from_slice(&second);
    opts.extend_from_slice(&mtu_option(1440));
    // RDNSS with one record has valid structural length.
    opts.extend_from_slice(&[25, 3, 0, 0, 0, 0, 0, 60]);
    opts.extend_from_slice(&address("2001:db8::53").octets());
    let ra = parse_ra(&router_advertisement(90, &opts));
    assert_eq!(ra.lifetime_seconds, 90);
    assert_eq!(ra.mtu, Some(1440));
    assert_eq!(ra.prefixes, [
        Prefix { network: address("2001:db8:1234:5678::"), on_link: true, valid_seconds: 3600, preferred_seconds: 1800 },
        Prefix { network: address("fd12:3456:7890:1::"), on_link: false, valid_seconds: u32::MAX, preferred_seconds: u32::MAX },
    ]);
    let withdrawn = parse_ra(&router_advertisement(0, &pio(prefix, 0xc0, 0, 0)));
    assert_eq!(withdrawn.lifetime_seconds, 0);
    assert_eq!(withdrawn.prefixes[0].valid_seconds, 0);
    assert!(parse_ra(&router_advertisement(90, &pio(prefix, 0xc0, 5, 6))).prefixes.is_empty());
    assert!(parse_ra(&router_advertisement(90, &pio(address("fe80::1"), 0xc0, 3600, 1800))).prefixes.is_empty());
    assert!(parse_ra(&router_advertisement(90, &pio(ALL_NODES, 0xc0, 3600, 1800))).prefixes.is_empty());
    assert_eq!(parse_ra(&router_advertisement(90, &mtu_option(1279))).mtu, None);
    assert_eq!(parse_ra(&router_advertisement(90, &mtu_option(u32::MAX))).mtu, None);

    let mut invalid = first.to_vec();
    invalid.extend_from_slice(&pio(prefix, 0xc0, 500, 300));
    assert!(matches!(control(&router_advertisement(90, &invalid)), Control::Discard));
    let invalid = [mtu_option(1290), mtu_option(1300)].concat();
    assert!(matches!(control(&router_advertisement(90, &invalid)), Control::Discard));
    let invalid = [25, 2, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(control(&router_advertisement(90, &invalid)), Control::Discard));
    assert!(matches!(control(&router_advertisement(90, &[99, 0])), Control::Discard));
    assert!(matches!(control(&router_advertisement(90, &[99, 5])), Control::Discard));
    let many = [99, 1, 0, 0, 0, 0, 0, 0].repeat(65);
    assert!(matches!(control(&router_advertisement(90, &many)), Control::Discard));
}

#[test]
fn malformed_control_is_consumed_and_extensions_do_not_enable_fragmented_nd() {
    let local = address("fe80::1");
    let target = address("fe80::2");
    let expected = solicited_node(target);
    let mut invalid_ra = router_advertisement(90, &[]);
    invalid_ra[43] ^= 1;
    assert!(matches!(control(&invalid_ra), Control::Discard));
    invalid_ra[7] = 64;
    assert!(matches!(control(&invalid_ra), Control::Discard));
    let wrong_source = ra_packet(address("2001:db8::1"), ALL_NODES, 18, &[]);
    let wrong_destination = ra_packet(local, wire::ALL_ROUTERS, 18, &[]);
    assert!(matches!(control(&wrong_source), Control::Discard));
    assert!(matches!(control(&wrong_destination), Control::Discard));

    let ns = wire::solicitation(local, target, CLIENT);
    let body = &ns[40..];
    let extension = [58, 0, 0, 0, 0, 0, 0, 0];
    let extended = raw(local, expected, body, 60, 255, &extension);
    assert!(matches!(control(&extended), Control::Solicitation(found) if found == target));
    for fragment in [[58, 0, 0, 0, 0, 0, 0, 1], [58, 0, 0, 8, 0, 0, 0, 1]] {
        let fragmented = raw(local, expected, body, 44, 255, &fragment);
        assert!(matches!(control(&fragmented), Control::Discard));
    }
    let extension = raw(local, target, body, 60, 255, &[58, 127]);
    assert!(matches!(control(&extension), Control::Data));
    let echo = raw(local, target, &[128, 0, 0, 0, 0, 0, 0, 0], 58, 255, &[]);
    assert!(matches!(control(&echo), Control::Data));
}

#[test]
fn mld_requires_a_valid_query_and_emits_an_exact_report() {
    let local = address("fe80::1234");
    let group = solicited_node(address("2001:db8::1234"));
    let report = wire::listener_report(local, group);
    assert_eq!(report[7], 1);
    assert_eq!(&report[40..48], &[58, 0, 5, 2, 0, 0, 1, 0]);
    assert_eq!(report[48], 131);
    assert_eq!(report[56..72], group.octets());
    assert_eq!(body_checksum(local, group, &report[48..]), 0);
    assert!(matches!(control(&report), Control::Discard));

    let mut query_body = [0; 28];
    query_body[0] = 130;
    query_body[8..24].copy_from_slice(&group.octets());
    let alert = [58, 0, 5, 2, 0, 0, 1, 0];
    let query = raw(local, group, &query_body, 0, 1, &alert);
    assert!(matches!(control(&query), Control::ListenerQuery));
    let wrong_hop = raw(local, group, &query_body, 0, 255, &alert);
    assert!(matches!(control(&wrong_hop), Control::Discard));
    let no_alert = raw(local, group, &query_body, 0, 1, &[58, 0, 1, 2, 0, 0, 1, 0]);
    assert!(matches!(control(&no_alert), Control::Discard));
    query_body[8..24].fill(0);
    let general = raw(local, ALL_NODES, &query_body[..24], 0, 1, &alert);
    assert!(matches!(control(&general), Control::ListenerQuery));
}

#[test]
fn every_truncation_of_a_router_advertisement_is_safe() {
    let prefix = address("2001:db8::1234");
    let bytes = router_advertisement(900, &pio(prefix, 0xc0, 100, 90));
    for size in 0..bytes.len() {
        assert!(Packet::parse(&bytes[..size]).is_none());
        // A forged outer length may admit bytes into the parser, but a
        // truncated checksum or option must never install a route.
        if size >= 40 {
            let mut truncated = bytes[..size].to_vec();
            truncated[4..6].copy_from_slice(&((size - 40) as u16).to_be_bytes());
            if let Some(packet) = Packet::parse(&truncated) {
                assert!(!matches!(packet.control(), Control::RouterAdvertisement(_)));
            }
        }
    }
}

fn link(allow_non_on_link: bool) -> Link {
    Link::new(CLIENT, 1500, [0, 0, 0, 0, 0, 0, 0, 7], 0, 0, allow_non_on_link)
}

fn emit_tick(link: &mut Link, time: u64) -> Vec<Output> {
    let mut output = Vec::new();
    link.tick(time, &mut |event| output.push(event));
    output
}

fn emit_receive(
    link: &mut Link,
    bytes: &[u8],
    time: u64,
    requires_router: impl Fn(Ipv6Addr) -> bool,
) -> Vec<Output> {
    let mut output = Vec::new();
    link.receive(bytes, time, requires_router, &mut |event| output.push(event));
    output
}

fn emit_send(link: &mut Link, bytes: &[u8], time: u64) -> Vec<Output> {
    let mut output = Vec::new();
    link.send(bytes, time, &mut |event| output.push(event));
    output
}

fn route(link: &mut Link, requires_router: bool) -> Configuration {
    assert_eq!(emit_tick(link, 0).len(), 2);
    assert_eq!(emit_tick(link, 1000).len(), 2);
    let mut options = pio(address("2001:db8:1::"), 0xc0, 3000, 2000).to_vec();
    options.extend_from_slice(&mtu_option(1450));
    let ra = frame(ROUTER, multicast_mac(ALL_NODES), &router_advertisement(900, &options));
    assert!(matches!(emit_receive(link, &ra, 1100, |_| requires_router).as_slice(), [Output::Control(_)]));
    assert_eq!(link.status(2099), Status::Discovering);
    assert!(emit_tick(link, 2100).is_empty());
    let Status::Ready(configuration) = link.status(2100) else { panic!("expected a configured link") };
    configuration
}

#[test]
fn prefers_on_link_prefix_and_never_waits_for_a_router_in_lan_only_mode() {
    let mut host = link(false);
    let ula = pio(address("fd00:42::"), 0x40, 100, 90);
    let on_link = pio(address("2001:db8:1::"), 0xc0, 100, 90);
    let ra = frame(ROUTER, multicast_mac(ALL_NODES), &router_advertisement(0, &[ula, on_link].concat()));
    // Accept advertisements queued while performing link-local DAD.
    assert!(emit_receive(&mut host, &ra, 0, |_| false).is_empty());
    assert_eq!(emit_tick(&mut host, 0).len(), 2);
    assert_eq!(emit_tick(&mut host, 1000).len(), 3);
    assert!(emit_tick(&mut host, 2000).is_empty());
    let Status::Ready(cfg) = host.status(2000) else { panic!("missing SLAAC address"); };
    assert_eq!(cfg.address, address("2001:db8:1::7"));
    assert_eq!(cfg.on_link_prefix, Some(address("2001:db8:1::")));
    assert_eq!(cfg.default_router, None);
    assert_eq!(cfg.next_hop(address("2001:db8:1::8")), Some(address("2001:db8:1::8")));
    assert_eq!(cfg.next_hop(address("2001:db8:2::8")), None);
    assert_eq!(cfg.next_hop(address("fe80::8")), None);
    assert_eq!(cfg.next_hop(ALL_NODES), None);
    assert_eq!(cfg.next_hop(Ipv6Addr::LOCALHOST), None);
}

#[test]
fn uses_valid_gateway_and_ignores_foreign_lifetime_updates() {
    let mut host = link(true);
    let cfg = route(&mut host, true);
    assert_eq!(cfg.default_router, Some(address("fe80::600")));
    assert_eq!(cfg.mtu, 1450);
    let packet = raw(cfg.address, address("2001:db8:2::8"), &[1, 2, 3, 4], 17, 32, &[]);
    let results = emit_send(&mut host, &packet, 2200);
    assert!(matches!(results.as_slice(), [Output::Frame(bytes)]
        if bytes[..6] == ROUTER && bytes[ETHERNET_HEADER..] == packet));

    let withdraw = router_advertisement(0, &[]);
    let foreign = frame(PEER, multicast_mac(ALL_NODES), &withdraw);
    emit_receive(&mut host, &foreign, 2400, |_| true);
    assert_eq!(host.status(2400), Status::Ready(cfg));
    let owned = frame(ROUTER, multicast_mac(ALL_NODES), &withdraw);
    emit_receive(&mut host, &owned, 2500, |_| true);
    assert_eq!(host.status(2500), Status::Expired);
    emit_tick(&mut host, 2500);
    assert!(emit_send(&mut host, &packet, 2500).is_empty());
}

#[test]
fn flushes_bounded_waiting_packets_only_to_valid_solicited_neighbors() {
    let mut host = link(true);
    let cfg = route(&mut host, false);
    let destination = address("2001:db8:1::8");
    let packet = raw(cfg.address, destination, &[1, 2, 3], 17, 64, &[]);
    let first = emit_send(&mut host, &packet, 2200);
    assert!(matches!(first.as_slice(), [Output::Control(bytes)]
        if bytes[..6] == multicast_mac(solicited_node(destination))));
    for _ in 0..10 {
        assert!(emit_send(&mut host, &packet, 2210).is_empty());
    }

    let response = wire::neighbor_advertisement(destination, host.link_local, PEER, true);
    let spoofed = frame(ROUTER, CLIENT, &response);
    assert!(emit_receive(&mut host, &spoofed, 2220, |_| false).is_empty());
    let correct = frame(PEER, CLIENT, &response);
    let delivery = emit_receive(&mut host, &correct, 2230, |_| false);
    assert_eq!(delivery.len(), MAX_WAITING_PACKETS);
    assert!(delivery.iter().all(|event| matches!(event, Output::Frame(bytes) if bytes[..6] == PEER)));
    assert!(matches!(emit_send(&mut host, &packet, 2240).as_slice(), [Output::Frame(bytes)] if bytes[..6] == PEER));

    let data = raw(destination, cfg.address, &[5, 6, 7], 17, 50, &[]);
    let mut padded = frame(PEER, CLIENT, &data);
    padded.extend_from_slice(&[0; 20]);
    assert!(matches!(emit_receive(&mut host, &padded, 2250, |_| false).as_slice(),
        [Output::Packet(bytes)] if *bytes == data));
}

#[test]
fn quietly_retries_neighbor_lookups_and_expires_negative_cache() {
    let mut host = link(true);
    let cfg = route(&mut host, false);
    let packet = raw(cfg.address, address("2001:db8:1::8"), &[1], 17, 64, &[]);
    assert_eq!(emit_send(&mut host, &packet, 2200).len(), 1);
    assert_eq!(emit_tick(&mut host, 3200).len(), 1);
    assert_eq!(emit_tick(&mut host, 4200).len(), 1);
    assert!(emit_tick(&mut host, 5200).is_empty());
    assert!(emit_send(&mut host, &packet, 5300).is_empty());
    assert_eq!(emit_send(&mut host, &packet, 8200).len(), 1);
    host.clear_pending();
    assert!(emit_tick(&mut host, 9200).is_empty());
}

#[test]
fn reports_duplicate_mtu_and_router_timeout_as_separate_failures() {
    let mut host = link(true);
    emit_tick(&mut host, 0);
    let dad = wire::solicitation(Ipv6Addr::UNSPECIFIED, host.link_local, PEER);
    let probe = frame(PEER, multicast_mac(solicited_node(host.link_local)), &dad);
    emit_receive(&mut host, &probe, 100, |_| true);
    assert_eq!(host.status(100), Status::Failed(Failure::DuplicateAddress));

    let small = Link::new(CLIENT, 1270, [0; 8], 0, 0, true);
    assert_eq!(small.status(0), Status::Failed(Failure::MtuTooSmall));

    let mut host = link(true);
    emit_tick(&mut host, 0);
    emit_tick(&mut host, 1_000);
    assert_eq!(emit_tick(&mut host, 5_000).len(), 1);
    assert_eq!(emit_tick(&mut host, 9_000).len(), 1);
    assert!(emit_tick(&mut host, 13_000).is_empty());
    assert_eq!(host.status(13_000), Status::Failed(Failure::NoAdvertisement));
}
