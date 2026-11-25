#[cfg(any(target_os = "android", test))]
mod batch {
    pub const SLOT_SIZE: usize = 1608;
    pub const MAX_PACKETS: usize = 48;
    pub const ARENA_SIZE: usize = SLOT_SIZE * MAX_PACKETS;
    const HEADER_SIZE: usize = 4;
    const MAX_PACKET_SIZE: usize = 1600;
    const MIN_FRAME_SIZE: usize = 14;

    pub const EAGAIN: i32 = 11;
    const EBADF: i32 = 9;
    pub const EINTR: i32 = 4;
    pub const EINVAL: i32 = 22;
    pub const EIO: i32 = 5;
    const EPIPE: i32 = 32;

    const POLLIN: i16 = 0x01;
    const POLLOUT: i16 = 0x04;
    const POLLERR: i16 = 0x08;
    const POLLHUP: i16 = 0x10;
    const POLLNVAL: i16 = 0x20;
    pub const FRAME_WRITABLE: i32 = 1 << 12;
    pub const TUN_WRITABLE: i32 = 1 << 13;

    #[derive(Clone, Copy)]
    pub enum Kind {
        Ethernet,
        Tun,
    }

    impl Kind {
        fn minimum(self) -> usize {
            match self {
                Self::Ethernet => MIN_FRAME_SIZE,
                Self::Tun => 1,
            }
        }

        fn receive_limit(self) -> usize {
            match self {
                Self::Ethernet => MAX_PACKET_SIZE + 1,
                Self::Tun => MAX_PACKET_SIZE,
            }
        }

        fn accepts_size(self, length: usize) -> bool {
            (self.minimum()..=MAX_PACKET_SIZE).contains(&length)
        }
    }

    pub trait PacketIo {
        fn poll(&mut self, descriptors: [i32; 2], events: [i16; 2]) -> Result<[i16; 2], i32>;
        fn read(&mut self, descriptor: i32, payload: &mut [u8]) -> Result<usize, i32>;
        fn write(&mut self, descriptor: i32, payload: &[u8], kind: Kind) -> Result<usize, i32>;
    }

    pub fn poll_read(
        io: &mut impl PacketIo,
        descriptors: [i32; 2],
        pending: [bool; 2],
        frames: &mut [u8],
        packets: &mut [u8],
    ) -> Result<i32, i32> {
        validate(descriptors, frames, packets)?;
        let events = pending.map(|write| if write { POLLIN | POLLOUT } else { POLLIN });
        let ready = match io.poll(descriptors, events) {
            Ok(result) => result,
            Err(EINTR) => return Ok(0),
            Err(error) => return Err(error),
        };
        check_ready(ready[0])?;
        if descriptors[1] >= 0 {
            check_ready(ready[1])?;
        }
        let frame_count = if ready[0] & POLLIN != 0 {
            read_batch(io, descriptors[0], frames, Kind::Ethernet)?
        } else {
            0
        };
        let packet_count = if descriptors[1] >= 0 && ready[1] & POLLIN != 0 {
            read_batch(io, descriptors[1], packets, Kind::Tun)?
        } else {
            0
        };
        let mut result = pack_counts(frame_count, packet_count);
        if ready[0] & POLLOUT != 0 {
            result |= FRAME_WRITABLE;
        }
        if descriptors[1] >= 0 && ready[1] & POLLOUT != 0 {
            result |= TUN_WRITABLE;
        }
        Ok(result)
    }

    pub fn records(arena: &[u8], count: usize) -> impl Iterator<Item = &[u8]> {
        arena.chunks_exact(SLOT_SIZE).take(count).map(|slot| {
            let length = u32::from_ne_bytes(slot[..HEADER_SIZE].try_into().unwrap()) as usize;
            &slot[HEADER_SIZE..HEADER_SIZE + length]
        })
    }

    fn validate(descriptors: [i32; 2], frames: &[u8], packets: &[u8]) -> Result<(), i32> {
        if descriptors[0] < 0
            || descriptors[1] < -1
            || descriptors[0] == descriptors[1]
            || frames.len() < ARENA_SIZE
            || packets.len() < ARENA_SIZE
        {
            return Err(EINVAL);
        }
        Ok(())
    }

    fn check_ready(events: i16) -> Result<(), i32> {
        if events & POLLNVAL != 0 {
            Err(EBADF)
        } else if events & POLLERR != 0 {
            Err(EIO)
        } else if events & POLLHUP != 0 {
            Err(EPIPE)
        } else {
            Ok(())
        }
    }

    fn pack_counts(frames: usize, packets: usize) -> i32 {
        (frames | (packets << 6)) as i32
    }

    fn read_batch(
        io: &mut impl PacketIo,
        descriptor: i32,
        arena: &mut [u8],
        kind: Kind,
    ) -> Result<usize, i32> {
        let mut count = 0;
        for slot in arena.chunks_exact_mut(SLOT_SIZE).take(MAX_PACKETS) {
            let payload = &mut slot[HEADER_SIZE..HEADER_SIZE + kind.receive_limit()];
            let length = match io.read(descriptor, payload) {
                Ok(0) => return Err(EPIPE),
                Ok(length) if kind.accepts_size(length) => length,
                Ok(_) | Err(EAGAIN | EINTR) => break,
                Err(error) => return Err(error),
            };
            slot[..HEADER_SIZE].copy_from_slice(&(length as u32).to_ne_bytes());
            count += 1;
        }
        Ok(count)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::VecDeque;

        const FRAME_FD: i32 = 7;
        const TUN_FD: i32 = 9;

        struct FakeIo {
            ready: Result<[i16; 2], i32>,
            read_queue: [VecDeque<Vec<u8>>; 2],
        }

        impl FakeIo {
            fn new(ready: Result<[i16; 2], i32>) -> Self {
                Self {
                    ready,
                    read_queue: Default::default(),
                }
            }
        }

        impl PacketIo for FakeIo {
            fn poll(&mut self, _: [i32; 2], _: [i16; 2]) -> Result<[i16; 2], i32> {
                self.ready
            }

            fn read(&mut self, descriptor: i32, payload: &mut [u8]) -> Result<usize, i32> {
                let queue = &mut self.read_queue[usize::from(descriptor == TUN_FD)];
                let packet = queue.pop_front().ok_or(EAGAIN)?;
                let size = packet.len().min(payload.len());
                payload[..size].copy_from_slice(&packet[..size]);
                Ok(size)
            }

            fn write(&mut self, _: i32, _: &[u8], _: Kind) -> Result<usize, i32> {
                unreachable!("poll_read never writes")
            }
        }

        #[test]
        fn collects_bounded_batches_from_both_descriptors() {
            let mut io = FakeIo::new(Ok([POLLIN | POLLOUT, POLLIN | POLLOUT]));
            let mut frames = vec![0; ARENA_SIZE];
            let mut packets = vec![0; ARENA_SIZE];
            for index in 0..MAX_PACKETS + 1 {
                io.read_queue[0].push_back(vec![index as u8; 46]);
            }
            io.read_queue[1].push_back(vec![0x45; 40]);
            let result = poll_read(
                &mut io, [FRAME_FD, TUN_FD], [true, true], &mut frames, &mut packets,
            );
            assert_eq!(result, Ok(pack_counts(MAX_PACKETS, 1) | FRAME_WRITABLE | TUN_WRITABLE));
            assert_eq!(io.read_queue[0].len(), 1);
            assert_eq!(&frames[..HEADER_SIZE], &46u32.to_ne_bytes());
            assert_eq!(&packets[HEADER_SIZE..HEADER_SIZE + 40], &[0x45; 40]);
            assert_eq!(frames[(MAX_PACKETS - 1) * SLOT_SIZE + HEADER_SIZE], 47);
        }

        #[test]
        fn discards_invalid_frames_and_retries_remaining_records_next_round() {
            let mut io = FakeIo::new(Ok([POLLIN | POLLOUT, POLLIN | POLLOUT]));
            let mut frames = vec![0; ARENA_SIZE];
            let mut packets = vec![0; ARENA_SIZE];
            io.read_queue[0].push_back(vec![0; MAX_PACKET_SIZE + 1]);
            io.read_queue[0].push_back(vec![0; MIN_FRAME_SIZE - 1]);
            io.read_queue[0].push_back(vec![0xfe; MIN_FRAME_SIZE]);
            io.read_queue[1].push_back(vec![0x45; 20]);
            for expected in [FRAME_WRITABLE, FRAME_WRITABLE, FRAME_WRITABLE | 1] {
                assert_eq!(
                    poll_read(&mut io, [FRAME_FD, -1], [true, false], &mut frames, &mut packets),
                    Ok(expected)
                );
            }
            assert_eq!(io.read_queue[1].len(), 1);
            assert_eq!(frames[HEADER_SIZE], 0xfe);
        }

        #[test]
        fn checks_errors_and_never_reads_a_closed_descriptor() {
            let mut io = FakeIo::new(Err(EINTR));
            let mut frames = vec![0; ARENA_SIZE];
            let mut packets = vec![0; ARENA_SIZE];
            let mut read = |io: &mut FakeIo| {
                poll_read(io, [FRAME_FD, TUN_FD], [false, false], &mut frames, &mut packets)
            };
            assert_eq!(read(&mut io), Ok(0));
            io.ready = Ok([POLLIN, POLLHUP]);
            io.read_queue[0].push_back(vec![0; 18]);
            assert_eq!(read(&mut io), Err(EPIPE));
            assert_eq!(io.read_queue[0].len(), 1);
            io.ready = Ok([POLLNVAL, 0]);
            assert_eq!(read(&mut io), Err(EBADF));
            io.ready = Ok([0, POLLIN]);
            io.read_queue[1].push_back(Vec::new());
            assert_eq!(read(&mut io), Err(EPIPE));
        }


    }
}

#[cfg(any(target_os = "android", test))]
mod ipv4;
#[cfg(any(target_os = "android", test))]
mod ipv6;
#[cfg(any(target_os = "android", test))]
mod session;
#[cfg(target_os = "android")]
mod android {
    use super::{batch::{EINVAL, EIO, Kind, PacketIo}, session::{Options, Session}};
    use std::{
        ffi::{c_int, c_short, c_uint, c_void},
        io, slice,
    };

    const MSG_NOSIGNAL: c_int = 0x4000;
    const POLL_TIMEOUT_MILLIS: c_int = 20;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }

    unsafe extern "C" {
        // Bionic defines nfds_t as unsigned int.
        fn poll(fds: *mut PollFd, count: c_uint, millis: c_int) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        fn send(fd: c_int, buf: *const c_void, count: usize, flags: c_int) -> isize;
    }

    fn errno() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(EIO)
    }

    struct AndroidIo;

    impl PacketIo for AndroidIo {
        fn poll(&mut self, descriptors: [i32; 2], events: [i16; 2]) -> Result<[i16; 2], i32> {
            let mut fds = [
                PollFd { fd: descriptors[0], events: events[0], revents: 0 },
                PollFd { fd: descriptors[1], events: events[1], revents: 0 },
            ];
            // Bionic ignores negative poll descriptors. The array is writable for the call.
            let result = unsafe { poll(fds.as_mut_ptr(), 2, POLL_TIMEOUT_MILLIS) };
            if result < 0 {
                Err(errno())
            } else {
                Ok([fds[0].revents, fds[1].revents])
            }
        }

        fn read(&mut self, descriptor: i32, payload: &mut [u8]) -> Result<usize, i32> {
            // The destination is a valid writable slice for the syscall.
            let size = unsafe { read(descriptor, payload.as_mut_ptr().cast(), payload.len()) };
            if size < 0 { Err(errno()) } else { Ok(size as usize) }
        }

        fn write(&mut self, descriptor: i32, payload: &[u8], kind: Kind) -> Result<usize, i32> {
            // The data is borrowed until the syscall finishes. Suppress SIGPIPE on the socket.
            let size = unsafe {
                match kind {
                    Kind::Ethernet => send(descriptor, payload.as_ptr().cast(), payload.len(), MSG_NOSIGNAL),
                    Kind::Tun => write(descriptor, payload.as_ptr().cast(), payload.len()),
                }
            };
            if size < 0 { Err(errno()) } else { Ok(size as usize) }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn softether_tun_create(
        input: *const u8, capacity: usize, now: u64,
    ) -> *mut Session {
        const MAX_OPTIONS: usize = 34 + 512 * 17;
        if input.is_null() || !(34..=MAX_OPTIONS).contains(&capacity) {
            return std::ptr::null_mut();
        }
        // JNI owns the direct buffer for this call. Options copies the supplied settings.
        let bytes = unsafe { slice::from_raw_parts(input, capacity) };
        Options::decode(bytes).and_then(|settings| Session::new(settings, now))
            .map_or(std::ptr::null_mut(), |session| Box::into_raw(Box::new(session)))
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn softether_tun_step(
        session: *mut Session, frame_fd: c_int, tun_fd: c_int, mtu: c_int, reset: c_int, now: u64,
        status: *mut u8, capacity: usize,
    ) -> c_int {
        const SNAPSHOT_BYTES: usize = 16_384;
        if session.is_null() || status.is_null() || capacity < SNAPSHOT_BYTES
            || frame_fd < 0 || tun_fd < -1 || frame_fd == tun_fd || mtu < 0
        {
            return -EINVAL;
        }
        // The packet worker owns the session exclusively until stop. The buffer is disjoint.
        let (session, bytes) = unsafe { (&mut *session, slice::from_raw_parts_mut(status, SNAPSHOT_BYTES)) };
        session.step(&mut AndroidIo, frame_fd, tun_fd, mtu as usize, reset != 0, now, bytes)
            .map_or_else(|error| -error, |_| 0)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn softether_tun_stop(session: *mut Session, frame_fd: c_int, now: u64) {
        if !session.is_null() {
            // This takes ownership once, after the Kotlin worker has stopped polling.
            let mut session = unsafe { Box::from_raw(session) };
            session.stop(&mut AndroidIo, frame_fd, now);
        }
    }
}
