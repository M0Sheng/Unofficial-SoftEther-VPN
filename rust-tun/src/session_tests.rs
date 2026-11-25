use super::*;

const ETHERNET: i32 = 7;
const TUN: i32 = 9;
const READABLE: i16 = 1;
const WRITABLE: i16 = 4;
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 42];
const ROUTER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const ADDRESS: u32 = u32::from_be_bytes([192, 0, 2, 42]);
const ROUTER: u32 = u32::from_be_bytes([192, 0, 2, 1]);
const DNS: u32 = u32::from_be_bytes([198, 51, 100, 53]);
const BOOTP: usize = 42;
const DHCP_OPTIONS: usize = BOOTP + 240;

#[derive(Default)]
struct FakeIo {
    frames: VecDeque<Vec<u8>>,
    packets: VecDeque<Vec<u8>>,
    writes: Vec<(i32, Vec<u8>)>,
    polls: Vec<[i32; 2]>,
}

impl batch::PacketIo for FakeIo {
    fn poll(&mut self, descriptors: [i32; 2], events: [i16; 2]) -> Result<[i16; 2], i32> {
        assert_eq!(descriptors[0], ETHERNET);
        assert!(matches!(descriptors[1], -1 | TUN));
        self.polls.push(descriptors);

        let mut frame_events = events[0] & WRITABLE;
        if !self.frames.is_empty() {
            frame_events |= READABLE;
        }
        let mut tun_events = 0;
        if descriptors[1] == TUN {
            tun_events = events[1] & WRITABLE;
            if !self.packets.is_empty() {
                tun_events |= READABLE;
            }
        }
        Ok([frame_events, tun_events])
    }

    fn read(&mut self, descriptor: i32, bytes: &mut [u8]) -> Result<usize, i32> {
        let input = match descriptor {
            ETHERNET => &mut self.frames,
            TUN => &mut self.packets,
            _ => panic!("unexpected descriptor {descriptor}"),
        };
        let packet = input.pop_front().ok_or(batch::EAGAIN)?;
        bytes[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn write(&mut self, descriptor: i32, bytes: &[u8], kind: batch::Kind) -> Result<usize, i32> {
        assert!(matches!((descriptor, kind), (ETHERNET, batch::Kind::Ethernet) | (TUN, batch::Kind::Tun)));
        self.writes.push((descriptor, bytes.to_vec()));
        Ok(bytes.len())
    }
}

fn options(flags: u32) -> Options {
    let mut bytes = MAC.to_vec();
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    for word in [1500u32, flags, 0, 0, 0] {
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    Options::decode(&bytes).unwrap()
}

fn step(session: &mut Session, io: &mut FakeIo, now: u64, tun: i32) -> Vec<u32> {
    let mut state = [0u8; 16_384];
    session.step(io, ETHERNET, tun, 1500, false, now, &mut state).unwrap();
    state.chunks_exact(4).take(16).map(|word| u32::from_ne_bytes(word.try_into().unwrap())).collect()
}

fn ipv4_packet(source: u32, destination: u32, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = next;
    packet[12..16].copy_from_slice(&source.to_be_bytes());
    packet[16..20].copy_from_slice(&destination.to_be_bytes());
    let mut sum: u32 = packet.chunks_exact(2)
        .map(|pair| u32::from(pair[0]) * 256 + u32::from(pair[1]))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn frame(destination: [u8; 6], ether_type: [u8; 2], payload: &[u8]) -> Vec<u8> {
    [destination.as_slice(), &ROUTER_MAC, &ether_type, payload].concat()
}

fn dhcp_reply(xid: [u8; 4], kind: u8) -> Vec<u8> {
    let mut bootp = vec![0; 240];
    bootp[..3].copy_from_slice(&[2, 1, 6]);
    bootp[4..8].copy_from_slice(&xid);
    bootp[16..20].copy_from_slice(&ADDRESS.to_be_bytes());
    bootp[28..34].copy_from_slice(&MAC);
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootp.extend_from_slice(&[53, 1, kind]);
    for (tag, value) in [(54, ROUTER), (51, 120), (1, 0xffff_ff00), (3, ROUTER), (6, DNS)] {
        bootp.extend_from_slice(&[tag, 4]);
        bootp.extend_from_slice(&value.to_be_bytes());
    }
    bootp.push(255);
    let mut udp = vec![0, 67, 0, 68, 0, 0, 0, 0];
    udp[4..6].copy_from_slice(&((8 + bootp.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&bootp);
    frame([0xff; 6], [0x08, 0], &ipv4_packet(ROUTER, u32::MAX, 17, &udp))
}

fn dhcp_request_type(ethernet: &[u8]) -> Option<u8> {
    if ethernet.get(12..14) != Some(&[0x08, 0]) || ethernet.get(34..38) != Some(&[0, 68, 0, 67]) {
        return None;
    }
    let mut options = ethernet.get(DHCP_OPTIONS..)?;
    while let Some((&tag, tail)) = options.split_first() {
        options = tail;
        match tag {
            0 => {}
            255 => return None,
            _ => {
                let (&length, tail) = options.split_first()?;
                let (value, rest) = tail.split_at_checked(usize::from(length))?;
                if tag == 53 && value.len() == 1 {
                    return Some(value[0]);
                }
                options = rest;
            }
        }
    }
    None
}

#[test]
fn session_acquires_a_lease_forwards_both_directions_and_releases_it() {
    let mut session = Session::new(options(0), 0).unwrap();
    let mut io = FakeIo::default();
    assert_eq!(&step(&mut session, &mut io, 0, -1)[..5], &[0, 0, 1, 0, 0]);
    assert!(io.polls.is_empty() && io.writes.is_empty());

    let outgoing = ipv4_packet(ADDRESS, ROUTER, 1, &[8, 0, 0, 0, 0, 1, 0, 1]);
    io.packets.push_back(outgoing.clone());
    assert_eq!(&step(&mut session, &mut io, 1, TUN)[..3], &[0, 0, 0]);
    let (fd, discover) = io.writes.last().unwrap();
    assert_eq!(*fd, ETHERNET);
    assert_eq!(dhcp_request_type(discover), Some(1));
    let xid = discover[BOOTP + 4..BOOTP + 8].try_into().unwrap();

    io.frames.push_back(dhcp_reply(xid, 2));
    step(&mut session, &mut io, 2, TUN);
    step(&mut session, &mut io, 3, TUN);
    assert_eq!(dhcp_request_type(&io.writes.last().unwrap().1), Some(3));
    io.frames.push_back(dhcp_reply(xid, 5));
    step(&mut session, &mut io, 10, TUN);

    // Advance beyond each bounded, randomized ARP probe interval.
    for now in [1010, 3010, 5010] {
        assert_eq!(step(&mut session, &mut io, now, TUN)[2], 0);
    }
    let status = step(&mut session, &mut io, 7010, TUN);
    assert_eq!(&status[..13], &[0, 0, 1, 1, 0, ADDRESS, 24, 1, 1, DNS, 0, 0, ROUTER]);
    assert!(io.polls.iter().all(|&fds| fds == [ETHERNET, -1]));
    assert_eq!(io.packets.len(), 1);
    assert_eq!(io.writes.iter().filter(|(_, frame)| frame[12..14] == [0x08, 6]).count(), 3);

    assert_eq!(&step(&mut session, &mut io, 7020, TUN)[..3], &[0, outgoing.len() as u32, 0]);
    assert_eq!(io.polls.last(), Some(&[ETHERNET, TUN]));
    let mut arp = vec![0, 1, 0x08, 0, 6, 4, 0, 2];
    arp.extend_from_slice(&ROUTER_MAC);
    arp.extend_from_slice(&ROUTER.to_be_bytes());
    arp.extend_from_slice(&MAC);
    arp.extend_from_slice(&ADDRESS.to_be_bytes());
    io.frames.push_back(frame(MAC, [0x08, 6], &arp));
    let incoming = ipv4_packet(ROUTER, ADDRESS, 1, &[0, 0, 0, 0, 0, 1, 0, 1]);
    io.frames.push_back(frame(MAC, [0x08, 0], &incoming));
    step(&mut session, &mut io, 7030, TUN);
    assert_eq!(&step(&mut session, &mut io, 7040, TUN)[..3], &[incoming.len() as u32, 0, 0]);
    assert!(io.writes.iter().any(|(fd, frame)|
        *fd == ETHERNET && frame[..6] == ROUTER_MAC && frame[14..] == outgoing));
    assert_eq!(io.writes.last(), Some(&(TUN, incoming)));

    session.stop(&mut io, ETHERNET, 7050);
    let (fd, release) = io.writes.last().unwrap();
    assert_eq!(*fd, ETHERNET);
    assert_eq!(release[..6], ROUTER_MAC);
    assert_eq!(dhcp_request_type(release), Some(7));
}

#[test]
fn session_reports_ipv6_discovery_and_timeout_with_no_tun() {
    let mut session = Session::new(options(3), 0).unwrap();
    let mut io = FakeIo::default();
    assert_eq!(&step(&mut session, &mut io, 0, -1)[..5], &[0, 0, 1, 0, 1]);
    for now in [1, 1_000, 5_000, 9_000] {
        assert_eq!(step(&mut session, &mut io, now, -1)[2], 0);
    }
    let messages: Vec<_> = io.writes.iter().filter_map(|(_, frame)|
        (frame[12..14] == [0x86, 0xdd]).then(|| (frame[20], frame[54]))).collect();
    // The first and third frames are MLD reports with a Hop-by-Hop header.
    assert_eq!(messages, [(0, 58), (58, 135), (0, 58), (58, 133), (58, 133), (58, 133)]);
    assert_eq!(&step(&mut session, &mut io, 13_000, -1)[..5], &[0, 0, 1, 0, 5]);
    assert!(io.polls.iter().all(|&fds| fds == [ETHERNET, -1]));
    session.stop(&mut io, ETHERNET, 13_001);
}
