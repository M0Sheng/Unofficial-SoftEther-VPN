use std::net::Ipv6Addr;

pub(super) const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
pub(super) const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
const HEADER: usize = 40;
const ICMPV6: u8 = 58;

#[derive(Debug)]
pub(super) struct Packet<'a> {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub bytes: &'a [u8],
    next_header: u8,
    hop_limit: u8,
}

impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        let header = bytes.get(..HEADER)?;
        let payload = usize::from(get16(header, 4));
        let next_header = header[6];
        if header[0] >> 4 != 6 || (payload == 0 && next_header != 59) {
            return None;
        }
        Some(Self {
            source: address(header, 8),
            destination: address(header, 24),
            bytes: bytes.get(..HEADER + payload)?,
            next_header,
            hop_limit: header[7],
        })
    }

    pub fn control(&self) -> Control {
        let Some(layer) = upper_layer(self) else {
            return Control::Data;
        };
        if layer.protocol != ICMPV6 {
            return Control::Data;
        }
        // A non-first fragment cannot be classified by ICMP type. No fragmented
        // ICMPv6 message can update neighbor discovery state.
        if layer.fragmented {
            return Control::Discard;
        }
        let Some(kind) = layer.body.first().copied() else {
            return Control::Data;
        };
        if !matches!(kind, 130..=137 | 143) {
            return Control::Data;
        }

        if kind == 130 && valid_listener_query(self, &layer) {
            return Control::ListenerQuery;
        }
        if self.hop_limit != 255
            || layer.body.len() < 4
            || layer.body[1] != 0
            || checksum(self.source, self.destination, layer.body) != 0
            || self.destination.is_unspecified()
            || self.source.is_multicast()
            || self.source.is_loopback()
        {
            return Control::Discard;
        }
        match kind {
            134 => parse_advertisement(self, layer.body)
                .map_or(Control::Discard, Control::RouterAdvertisement),
            135 => parse_solicitation(self, layer.body).map_or(Control::Discard, Control::Solicitation),
            136 => parse_neighbor_advertisement(self, layer.body)
                .map_or(Control::Discard, Control::NeighborAdvertisement),
            _ => Control::Discard,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Prefix {
    pub network: Ipv6Addr,
    pub on_link: bool,
    pub preferred_seconds: u32,
    pub valid_seconds: u32,
}

#[derive(Debug)]
pub(super) struct RouterAdvertisement {
    pub lifetime_seconds: u16,
    pub prefixes: Vec<Prefix>,
    pub mtu: Option<usize>,
}

#[derive(Debug)]
pub(super) struct NeighborAdvertisement {
    pub target: Ipv6Addr,
    pub mac: Option<[u8; 6]>,
    pub solicited: bool,
}

#[derive(Debug)]
pub(super) enum Control {
    Data,
    Discard,
    ListenerQuery,
    RouterAdvertisement(RouterAdvertisement),
    Solicitation(Ipv6Addr),
    NeighborAdvertisement(NeighborAdvertisement),
}

pub(super) fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
    let address = target.octets();
    Ipv6Addr::new(
        0xff02, 0, 0, 0, 0, 1,
        u16::from_be_bytes([0xff, address[13]]),
        u16::from_be_bytes([address[14], address[15]]),
    )
}

pub(super) fn multicast_mac(address: Ipv6Addr) -> [u8; 6] {
    let bytes = address.octets();
    [0x33, 0x33, bytes[12], bytes[13], bytes[14], bytes[15]]
}

pub(super) fn router_solicitation(source: Ipv6Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut body = [0; 16];
    body[0] = 133;
    if source.is_unspecified() {
        return icmp_packet(source, ALL_ROUTERS, &body[..8]);
    }
    mac_option_into(&mut body[8..16], 1, mac);
    icmp_packet(source, ALL_ROUTERS, &body)
}

pub(super) fn solicitation(source: Ipv6Addr, target: Ipv6Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut body = [0; 32];
    body[0] = 135;
    body[8..24].copy_from_slice(&target.octets());
    let destination = solicited_node(target);
    // A DAD probe uses the unspecified source and omits the link-layer option.
    if source.is_unspecified() {
        return icmp_packet(source, destination, &body[..24]);
    }
    mac_option_into(&mut body[24..32], 1, mac);
    icmp_packet(source, destination, &body)
}

pub(super) fn neighbor_advertisement(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    mac: [u8; 6],
    solicited: bool,
) -> Vec<u8> {
    let mut body = [0; 32];
    body[0] = 136;
    body[4] = if solicited { 0x60 } else { 0x20 };
    body[8..24].copy_from_slice(&source.octets());
    mac_option_into(&mut body[24..32], 2, mac);
    icmp_packet(source, destination, &body)
}

pub(super) fn listener_report(source: Ipv6Addr, group: Ipv6Addr) -> Vec<u8> {
    let mut packet = vec![0; 72];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&32u16.to_be_bytes());
    packet[7] = 1;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&group.octets());
    // Hop-by-Hop Router Alert for MLD, with zero-length PadN.
    packet[40..48].copy_from_slice(&[ICMPV6, 0, 5, 2, 0, 0, 1, 0]);
    packet[48] = 131;
    packet[56..72].copy_from_slice(&group.octets());
    let check = checksum(source, group, &packet[48..]);
    packet[50..52].copy_from_slice(&check.to_be_bytes());
    packet
}

fn parse_advertisement(packet: &Packet<'_>, body: &[u8]) -> Option<RouterAdvertisement> {
    if !packet.source.is_unicast_link_local()
        || body.len() < 16
        || (packet.destination.is_multicast() && packet.destination != ALL_NODES)
    {
        return None;
    }

    let mut prefixes = Vec::new();
    let mut mtu = None;
    for option in options(&body[16..]) {
        let option = option?;
        match option[0] {
            1 => {
                if option.len() != 8 || !valid_mac(option[2..8].try_into().ok()?) {
                    return None;
                }
            }
            3 => {
                if option.len() != 32 {
                    return None;
                }
                let flags = option[3];
                let valid_seconds = get32(option, 4);
                let preferred_seconds = get32(option, 8);
                let address = address(option, 16);
                if option[2] != 64
                    || flags & 0x40 == 0
                    || preferred_seconds > valid_seconds
                    || address.is_unicast_link_local()
                    || address.is_multicast()
                {
                    continue;
                }
                let network = Ipv6Addr::from(u128::from(address) & (u128::MAX << 64));
                if !valid_unicast(network) {
                    continue;
                }
                let prefix = Prefix { network, on_link: flags & 0x80 != 0, preferred_seconds, valid_seconds };
                if let Some(previous) = prefixes.iter().find(|previous: &&Prefix| previous.network == network) {
                    if *previous != prefix {
                        return None;
                    }
                } else {
                    prefixes.push(prefix);
                }
            }
            5 => {
                if option.len() != 8 {
                    return None;
                }
                let value = get32(option, 4);
                if (1280..=i32::MAX as u32).contains(&value) {
                    let value = value as usize;
                    if mtu.is_some_and(|existing| existing != value) {
                        return None;
                    }
                    mtu = Some(value);
                }
            }
            // RDNSS is structurally validated. The Android VPN interface
            // continues to configure DNS using the existing DHCP/routing policy.
            25 if option.len() < 24 || (option.len() - 8) % 16 != 0 => return None,
            _ => {}
        }
    }
    Some(RouterAdvertisement { lifetime_seconds: get16(body, 6), prefixes, mtu })
}

fn parse_solicitation(packet: &Packet<'_>, body: &[u8]) -> Option<Ipv6Addr> {
    if body.len() < 24 {
        return None;
    }
    let target = address(body, 8);
    if !valid_unicast(target) {
        return None;
    }
    let source_mac = parse_mac_option(&body[24..], 1)?;
    let group = solicited_node(target);
    if packet.source.is_unspecified() {
        if source_mac.is_some() || packet.destination != group {
            return None;
        }
    } else if !valid_unicast(packet.source) || (packet.destination.is_multicast() && packet.destination != group) {
        return None;
    }
    Some(target)
}

fn parse_neighbor_advertisement(packet: &Packet<'_>, body: &[u8]) -> Option<NeighborAdvertisement> {
    if body.len() < 24 || !valid_unicast(packet.source) {
        return None;
    }
    let target = address(body, 8);
    let solicited = body[4] & 0x40 != 0;
    if !valid_unicast(target) || (solicited && packet.destination.is_multicast()) {
        return None;
    }
    let mac = parse_mac_option(&body[24..], 2)?;
    Some(NeighborAdvertisement { target, mac, solicited })
}

fn options(mut remaining: &[u8]) -> impl Iterator<Item = Option<&[u8]>> {
    let mut count = 0;
    std::iter::from_fn(move || {
        if remaining.is_empty() {
            return None;
        }
        count += 1;
        let length = remaining.get(1).map_or(0, |&units| usize::from(units) * 8);
        if length == 0 || length > remaining.len() || count > 64 {
            remaining = &[];
            return Some(None);
        }
        let (option, next) = remaining.split_at(length);
        remaining = next;
        Some(Some(option))
    })
}

fn parse_mac_option(bytes: &[u8], kind: u8) -> Option<Option<[u8; 6]>> {
    let mut found = None;
    for option in options(bytes) {
        let option = option?;
        if option[0] != kind {
            continue;
        }
        if found.is_some() || option.len() != 8 {
            return None;
        }
        let mac = option[2..8].try_into().ok()?;
        if !valid_mac(mac) {
            return None;
        }
        found = Some(mac);
    }
    Some(found)
}

struct UpperLayer<'a> {
    protocol: u8,
    body: &'a [u8],
    fragmented: bool,
    router_alert: bool,
}

fn upper_layer<'a>(packet: &Packet<'a>) -> Option<UpperLayer<'a>> {
    let mut protocol = packet.next_header;
    let mut body = &packet.bytes[HEADER..];
    let mut fragmented = false;
    let mut router_alert = false;
    for index in 0..8 {
        let size = match protocol {
            0 | 43 | 60 => {
                let size = (usize::from(*body.get(1)?) + 1) * 8;
                if protocol == 0 {
                    if index != 0 {
                        return None;
                    }
                    router_alert = parse_hop_options(body.get(2..size)?)?;
                }
                size
            }
            44 => {
                let fragment = body.get(..8)?;
                fragmented = true;
                if get16(fragment, 2) & 0xfff8 != 0 {
                    return Some(UpperLayer { protocol: fragment[0], body: &[], fragmented, router_alert });
                }
                8
            }
            51 => (usize::from(*body.get(1)?) + 2) * 4,
            _ => return Some(UpperLayer { protocol, body, fragmented, router_alert }),
        };
        let (extension, next) = body.split_at_checked(size)?;
        protocol = extension[0];
        body = next;
    }
    None
}

fn parse_hop_options(mut bytes: &[u8]) -> Option<bool> {
    let mut router_alert = false;
    while !bytes.is_empty() {
        let kind = bytes[0];
        if kind == 0 {
            bytes = &bytes[1..];
            continue;
        }
        let length = usize::from(*bytes.get(1)?) + 2;
        let (option, next) = bytes.split_at_checked(length)?;
        if kind == 5 {
            if length != 4 || get16(option, 2) != 0 || router_alert {
                return None;
            }
            router_alert = true;
        }
        bytes = next;
    }
    Some(router_alert)
}

fn valid_listener_query(packet: &Packet<'_>, layer: &UpperLayer<'_>) -> bool {
    let body = layer.body;
    if !layer.router_alert
        || packet.hop_limit != 1
        || !packet.source.is_unicast_link_local()
        || body.len() < 24
        || body[1] != 0
        || checksum(packet.source, packet.destination, body) != 0
    {
        return false;
    }
    let group = address(body, 8);
    let destination = if group.is_unspecified() {
        ALL_NODES
    } else if group.is_multicast() {
        group
    } else {
        return false;
    };
    packet.destination == destination
        && (body.len() == 24 || (body.len() >= 28 && body.len() == 28 + 16 * usize::from(get16(body, 26))))
}

fn icmp_packet(source: Ipv6Addr, destination: Ipv6Addr, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; HEADER + body.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    packet[6] = ICMPV6;
    packet[7] = u8::MAX;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[HEADER..].copy_from_slice(body);
    let check = checksum(source, destination, body);
    packet[42..44].copy_from_slice(&check.to_be_bytes());
    packet
}

fn mac_option_into(bytes: &mut [u8], kind: u8, mac: [u8; 6]) {
    bytes[0] = kind;
    bytes[1] = 1;
    bytes[2..].copy_from_slice(&mac);
}

fn checksum(source: Ipv6Addr, destination: Ipv6Addr, body: &[u8]) -> u16 {
    fn words(bytes: &[u8]) -> u32 {
        bytes.chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]))).sum()
    }
    let size = body.len() as u32;
    let mut sum = words(&source.octets()) + words(&destination.octets()) + words(body)
        + (size >> 16) + (size & 0xffff) + u32::from(ICMPV6);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn valid_unicast(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_multicast() && !address.is_loopback()
}

pub(super) fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

fn address(bytes: &[u8], offset: usize) -> Ipv6Addr {
    let mut address = [0; 16];
    address.copy_from_slice(&bytes[offset..offset + 16]);
    Ipv6Addr::from(address)
}

fn get16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    (u32::from(get16(bytes, offset)) << 16) | u32::from(get16(bytes, offset + 2))
}
