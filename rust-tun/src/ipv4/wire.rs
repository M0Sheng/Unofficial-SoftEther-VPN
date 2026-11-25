use super::{
    BROADCAST, ETHERNET_HEADER, IPV4, MacAddress, Route, network_mask, put_u16, put_u32, read_u16,
    read_u32, usable_address, usable_mac,
};

pub(super) const DISCOVER: u8 = 1;
pub(super) const OFFER: u8 = 2;
pub(super) const REQUEST: u8 = 3;
pub(super) const DECLINE: u8 = 4;
pub(super) const ACK: u8 = 5;
pub(super) const NAK: u8 = 6;
pub(super) const RELEASE: u8 = 7;

const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const OPTIONS: usize = 240;
const COOKIE: u32 = 0x6382_5363;
const FILE_FIELD: usize = 108;
const SERVER_NAME_FIELD: usize = 44;
const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;
const MASK: u8 = 1;
const ROUTER: u8 = 3;
const DNS: u8 = 6;
const REQUESTED_ADDRESS: u8 = 50;
const LEASE: u8 = 51;
const OVERLOAD: u8 = 52;
const MESSAGE_TYPE: u8 = 53;
const SERVER_ID: u8 = 54;
const PARAMETER_LIST: u8 = 55;
const MAXIMUM_MESSAGE_SIZE: u8 = 57;
const RENEWAL_TIME: u8 = 58;
const REBINDING_TIME: u8 = 59;
const CLIENT_ID: u8 = 61;
const CLASSLESS_ROUTES: u8 = 121;
const END: u8 = 255;

pub(super) const BROADCAST_ADDRESS: u32 = u32::MAX;
const REQUEST_FRAME_LEN: usize = ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER + 300;

pub(super) type RequestFrame = [u8; REQUEST_FRAME_LEN];

pub(super) struct Request {
    pub(super) kind: u8,
    pub(super) xid: u32,
    pub(super) elapsed_ms: u64,
    pub(super) mac: MacAddress,
    pub(super) client_address: u32,
    pub(super) destination: u32,
    pub(super) destination_mac: MacAddress,
    pub(super) requested_address: u32,
    pub(super) server_id: u32,
    pub(super) maximum_message_size: u16,
}

impl Request {
    pub(super) fn encode(self) -> RequestFrame {
        let ip = ETHERNET_HEADER;
        let udp = ip + IPV4_HEADER;
        let bootp = udp + UDP_HEADER;
        let mut frame = [0; REQUEST_FRAME_LEN];

        frame[..6].copy_from_slice(&self.destination_mac);
        frame[6..12].copy_from_slice(&self.mac);
        put_u16(&mut frame, 12, IPV4);
        frame[ip] = 0x45;
        put_u16(&mut frame, ip + 2, (REQUEST_FRAME_LEN - ip) as u16);
        put_u16(&mut frame, ip + 6, 0x4000);
        frame[ip + 8] = 64;
        frame[ip + 9] = 17;
        put_u32(&mut frame, ip + 12, self.client_address);
        put_u32(&mut frame, ip + 16, self.destination);
        put_u16(&mut frame, udp, CLIENT_PORT);
        put_u16(&mut frame, udp + 2, SERVER_PORT);
        put_u16(&mut frame, udp + 4, (REQUEST_FRAME_LEN - udp) as u16);

        frame[bootp..bootp + 4].copy_from_slice(&[1, 1, 6, 0]);
        put_u32(&mut frame, bootp + 4, self.xid);
        let negotiating = matches!(self.kind, DISCOVER | REQUEST);
        if negotiating {
            let seconds = (self.elapsed_ms / 1000).min(u64::from(u16::MAX)) as u16;
            put_u16(&mut frame, bootp + 8, seconds);
            if self.client_address == 0 {
                put_u16(&mut frame, bootp + 10, 0x8000);
            }
        }
        put_u32(&mut frame, bootp + 12, self.client_address);
        frame[bootp + 28..bootp + 34].copy_from_slice(&self.mac);
        put_u32(&mut frame, bootp + OPTIONS - 4, COOKIE);

        let mut offset = bootp + OPTIONS;
        let mut client_id = [1; 7];
        client_id[1..].copy_from_slice(&self.mac);
        write_option(&mut frame, &mut offset, MESSAGE_TYPE, &[self.kind]);
        write_option(&mut frame, &mut offset, CLIENT_ID, &client_id);
        if self.requested_address != 0 {
            write_option(
                &mut frame,
                &mut offset,
                REQUESTED_ADDRESS,
                &self.requested_address.to_be_bytes(),
            );
        }
        if self.server_id != 0 {
            write_option(&mut frame, &mut offset, SERVER_ID, &self.server_id.to_be_bytes());
        }
        if negotiating {
            write_option(
                &mut frame,
                &mut offset,
                MAXIMUM_MESSAGE_SIZE,
                &self.maximum_message_size.to_be_bytes(),
            );
            write_option(
                &mut frame,
                &mut offset,
                PARAMETER_LIST,
                &[MASK, CLASSLESS_ROUTES, ROUTER, DNS, RENEWAL_TIME, REBINDING_TIME],
            );
        }
        frame[offset] = END;
        let ip_checksum = !checksum(&frame[ip..udp], 0);
        put_u16(&mut frame, ip + 10, ip_checksum);
        let udp_checksum = !udp_checksum(&frame, ip, udp, REQUEST_FRAME_LEN - udp);
        put_u16(&mut frame, udp + 6, if udp_checksum == 0 { u16::MAX } else { udp_checksum });
        frame
    }
}

fn write_option(frame: &mut [u8], offset: &mut usize, number: u8, value: &[u8]) {
    frame[*offset] = number;
    frame[*offset + 1] = value.len() as u8;
    *offset += 2;
    frame[*offset..*offset + value.len()].copy_from_slice(value);
    *offset += value.len();
}

/// Identify DHCP frames even after binding so they do not reach the IP interface.
pub(super) fn is_response(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER
        || read_u16(frame, 12) != IPV4
        || frame[ETHERNET_HEADER] >> 4 != 4
        || frame[ETHERNET_HEADER + 9] != 17
    {
        return false;
    }
    let ip_header = usize::from(frame[ETHERNET_HEADER] & 15) * 4;
    let udp = ETHERNET_HEADER + ip_header;
    ip_header >= IPV4_HEADER
        && frame.len() >= udp + UDP_HEADER
        && read_u16(frame, udp) == SERVER_PORT
        && read_u16(frame, udp + 2) == CLIENT_PORT
}

pub(super) fn decode(
    frame: &[u8],
    expected_mac: MacAddress,
    expected_xid: u32,
    configured_address: u32,
) -> Option<Reply> {
    if frame.len() < ETHERNET_HEADER + IPV4_HEADER + UDP_HEADER + OPTIONS
        || !is_response(frame)
        || (frame[..6] != expected_mac && frame[..6] != BROADCAST)
    {
        return None;
    }
    let source_mac = frame[6..12].try_into().ok()?;
    if !usable_mac(source_mac) {
        return None;
    }

    let ip = ETHERNET_HEADER;
    let header_size = usize::from(frame[ip] & 15) * 4;
    let ip_length = usize::from(read_u16(frame, ip + 2));
    let udp = ip + header_size;
    if ip_length < header_size + UDP_HEADER + OPTIONS
        || ip_length > frame.len() - ip
        || read_u16(frame, ip + 6) & 0xbfff != 0
        || checksum(&frame[ip..udp], 0) != u16::MAX
    {
        return None;
    }
    let udp_length = usize::from(read_u16(frame, udp + 4));
    if udp_length != ip_length - header_size
        || (read_u16(frame, udp + 6) != 0
            && udp_checksum(frame, ip, udp, udp_length) != u16::MAX)
    {
        return None;
    }

    let bootp = udp + UDP_HEADER;
    let offered_address = read_u32(frame, bootp + 16);
    let source_address = read_u32(frame, ip + 12);
    let destination = read_u32(frame, ip + 16);
    if frame[bootp..bootp + 3] != [2, 1, 6]
        || read_u32(frame, bootp + 4) != expected_xid
        || frame[bootp + 28..bootp + 34] != expected_mac
        || read_u32(frame, bootp + OPTIONS - 4) != COOKIE
        || !usable_address(source_address)
        || (destination != BROADCAST_ADDRESS
            && (!usable_address(destination)
                || (destination != offered_address && destination != configured_address)))
    {
        return None;
    }

    let mut options = Options::default();
    options.read(&frame[bootp + OPTIONS..udp + udp_length], true)?;
    if let Some(overload) = options.get(OVERLOAD) {
        let &[fields] = overload else {
            return None;
        };
        if !(1..=3).contains(&fields) {
            return None;
        }
        if fields & 1 != 0 {
            options.read(&frame[bootp + FILE_FIELD..bootp + OPTIONS - 4], false)?;
        }
        if fields & 2 != 0 {
            options.read(&frame[bootp + SERVER_NAME_FIELD..bootp + FILE_FIELD], false)?;
        }
    }
    if let Some(id) = options.get(CLIENT_ID)
        && (id.len() != 7 || id[0] != 1 || id[1..] != expected_mac)
    {
        return None;
    }
    let &[kind] = options.get(MESSAGE_TYPE)? else {
        return None;
    };
    let server_id = options.integer(SERVER_ID)?;
    if !matches!(kind, OFFER | ACK | NAK) || !usable_address(server_id) {
        return None;
    }
    Some(Reply {
        kind,
        server_id,
        offered_address,
        source_address,
        source_mac,
        options,
    })
}

pub(super) struct Reply {
    pub(super) kind: u8,
    pub(super) server_id: u32,
    pub(super) offered_address: u32,
    pub(super) source_address: u32,
    pub(super) source_mac: MacAddress,
    options: Options,
}

impl Reply {
    pub(super) fn lease_seconds(&self) -> Option<u64> {
        self.options.integer(LEASE).map(u64::from)
    }

    pub(super) fn renewal_seconds(&self) -> Option<u64> {
        self.options.integer(RENEWAL_TIME).map(u64::from)
    }

    pub(super) fn rebinding_seconds(&self) -> Option<u64> {
        self.options.integer(REBINDING_TIME).map(u64::from)
    }

    pub(super) fn prefix_length(&self, address: u32) -> Option<u8> {
        if self.options.get(MASK).is_none() {
            return Some(match address >> 24 {
                0..=127 => 8,
                128..=191 => 16,
                _ => 24,
            });
        }
        let mask = self.options.integer(MASK)?;
        let prefix = mask.count_ones() as u8;
        (prefix != 0 && network_mask(prefix) == mask).then_some(prefix)
    }

    pub(super) fn dns(&self) -> Option<Vec<u32>> {
        self.options.address_list(DNS)
    }

    pub(super) fn routes(&self) -> Option<Vec<Route>> {
        if let Some(mut classless) = self.options.get(CLASSLESS_ROUTES) {
            if classless.is_empty() {
                return None;
            }
            let mut routes = Vec::new();
            while let Some((&prefix_length, rest)) = classless.split_first() {
                let octets = usize::from(prefix_length).div_ceil(8);
                if prefix_length > 32 || rest.len() < octets + 4 {
                    return None;
                }
                let mut destination = [0; 4];
                destination[..octets].copy_from_slice(&rest[..octets]);
                let gateway = read_u32(rest, octets);
                if gateway != 0 && !usable_address(gateway) {
                    return None;
                }
                routes.push(Route {
                    destination: u32::from_be_bytes(destination) & network_mask(prefix_length),
                    prefix_length,
                    gateway,
                });
                classless = &rest[octets + 4..];
            }
            Some(routes)
        } else {
            Some(
                self.options
                    .address_list(ROUTER)?
                    .into_iter()
                    .map(|gateway| Route { destination: 0, prefix_length: 0, gateway })
                    .collect(),
            )
        }
    }
}

#[derive(Default)]
struct Options {
    data: [Option<Vec<u8>>; 11],
}

impl Options {
    fn index(number: u8) -> Option<usize> {
        Some(match number {
            MASK => 0,
            ROUTER => 1,
            DNS => 2,
            LEASE => 3,
            OVERLOAD => 4,
            MESSAGE_TYPE => 5,
            SERVER_ID => 6,
            RENEWAL_TIME => 7,
            REBINDING_TIME => 8,
            CLIENT_ID => 9,
            CLASSLESS_ROUTES => 10,
            _ => return None,
        })
    }

    fn read(&mut self, mut bytes: &[u8], primary: bool) -> Option<()> {
        while let Some((&number, rest)) = bytes.split_first() {
            bytes = rest;
            match number {
                0 => {}
                END => return Some(()),
                _ => {
                    let (&length, values) = bytes.split_first()?;
                    let (value, next) = values.split_at_checked(usize::from(length))?;
                    if (primary || number != OVERLOAD)
                        && let Some(index) = Self::index(number)
                    {
                        self.data[index].get_or_insert_with(Vec::new).extend_from_slice(value);
                    }
                    bytes = next;
                }
            }
        }
        None
    }

    fn get(&self, option: u8) -> Option<&[u8]> {
        self.data[Self::index(option)?].as_deref()
    }

    fn integer(&self, option: u8) -> Option<u32> {
        match self.get(option) {
            None => Some(0),
            Some(bytes) => Some(u32::from_be_bytes(bytes.try_into().ok()?)),
        }
    }

    fn address_list(&self, option: u8) -> Option<Vec<u32>> {
        let Some(bytes) = self.get(option) else {
            return Some(Vec::new());
        };
        if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
            return None;
        }
        Some(
            bytes
                .chunks_exact(4)
                .map(|item| read_u32(item, 0))
                .filter(|&address| usable_address(address))
                .collect(),
        )
    }
}

pub(super) fn udp_checksum(frame: &[u8], ip: usize, udp: usize, length: usize) -> u16 {
    let pseudo_header = checksum(&frame[ip + 12..ip + 20], 17 + length as u32);
    checksum(&frame[udp..udp + length], u32::from(pseudo_header))
}

pub(super) fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut words = bytes.chunks_exact(2);
    let mut sum = words
        .by_ref()
        .fold(initial, |sum, word| sum + u32::from(read_u16(word, 0)));
    if let [tail] = words.remainder() {
        sum += u32::from(*tail) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}
