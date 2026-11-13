use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const TCP_PING_PORTS: [u16; 3] = [80, 443, 22];

pub enum TcpOutcome {
    Open(f64),
    Refused(f64),
    Unreachable,
}

pub fn tcp_probe(ip: Ipv4Addr, port: u16, timeout: Duration) -> TcpOutcome {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => TcpOutcome::Open(start.elapsed().as_secs_f64() * 1000.0),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            TcpOutcome::Refused(start.elapsed().as_secs_f64() * 1000.0)
        }
        Err(_) => TcpOutcome::Unreachable,
    }
}

/// A refused connection still proves the host is up: it answered with a reset.
pub fn tcp_ping(ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
    let per_port = Duration::from_millis((timeout.as_millis() as u64 / TCP_PING_PORTS.len() as u64).max(120));
    for port in TCP_PING_PORTS {
        match tcp_probe(ip, port, per_port) {
            TcpOutcome::Open(ms) | TcpOutcome::Refused(ms) => return Some(ms),
            TcpOutcome::Unreachable => continue,
        }
    }
    None
}

pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()?;
    if name == ip.to_string() {
        None
    } else {
        Some(name)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    #[repr(C)]
    struct IpOptionInformation {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }

    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut u8,
        options: IpOptionInformation,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(handle: *mut c_void) -> i32;
        fn IcmpSendEcho(
            handle: *mut c_void,
            destination: u32,
            request_data: *const u8,
            request_size: u16,
            request_options: *const IpOptionInformation,
            reply_buffer: *mut u8,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    pub struct IcmpInner {
        handle: *mut c_void,
    }

    impl Drop for IcmpInner {
        fn drop(&mut self) {
            unsafe { IcmpCloseHandle(self.handle) };
        }
    }

    impl IcmpInner {
        pub fn new() -> Option<Self> {
            let handle = unsafe { IcmpCreateFile() };
            if handle.is_null() || handle as isize == -1 {
                None
            } else {
                Some(Self { handle })
            }
        }

        pub fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
            let payload = [0x61u8; 32];
            let options = IpOptionInformation {
                ttl: 128,
                tos: 0,
                flags: 0,
                options_size: 0,
                options_data: std::ptr::null_mut(),
            };
            let words = (std::mem::size_of::<IcmpEchoReply>() + payload.len() + 16).div_ceil(8);
            let mut buffer = vec![0u64; words];
            let destination = u32::from_ne_bytes(ip.octets());
            let start = Instant::now();
            let replies = unsafe {
                IcmpSendEcho(
                    self.handle,
                    destination,
                    payload.as_ptr(),
                    payload.len() as u16,
                    &options,
                    buffer.as_mut_ptr() as *mut u8,
                    (words * 8) as u32,
                    timeout.as_millis().max(1) as u32,
                )
            };
            if replies == 0 {
                return None;
            }
            let reply = unsafe { &*(buffer.as_ptr() as *const IcmpEchoReply) };
            if reply.status != 0 {
                return None;
            }
            let reported = reply.round_trip_time as f64;
            Some(if reported > 0.0 {
                reported
            } else {
                (start.elapsed().as_secs_f64() * 1000.0).max(0.1)
            })
        }
    }
}

#[cfg(all(unix, not(target_os = "android")))]
mod imp {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    pub struct IcmpInner {
        socket: UdpSocket,
        id: u16,
        seq: u16,
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    impl IcmpInner {
        pub fn new() -> Option<Self> {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
                .or_else(|_| Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)))
                .ok()?;
            let id = (std::process::id() & 0xffff) as u16;
            Some(Self {
                socket: socket.into(),
                id,
                seq: 0,
            })
        }

        pub fn ping(&mut self, ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
            self.seq = self.seq.wrapping_add(1);
            let mut packet = vec![0u8; 40];
            packet[0] = 8;
            packet[4..6].copy_from_slice(&self.id.to_be_bytes());
            packet[6..8].copy_from_slice(&self.seq.to_be_bytes());
            for (i, byte) in packet[8..].iter_mut().enumerate() {
                *byte = b'a' + (i % 26) as u8;
            }
            let sum = checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());

            let target = SocketAddr::new(IpAddr::V4(ip), 0);
            let start = Instant::now();
            self.socket.send_to(&packet, target).ok()?;
            let deadline = start + timeout;
            let mut buffer = [0u8; 1024];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return None;
                }
                self.socket.set_read_timeout(Some(left)).ok()?;
                let (len, from) = self.socket.recv_from(&mut buffer).ok()?;
                let offset = if len > 20 && buffer[0] >> 4 == 4 {
                    ((buffer[0] & 0x0f) as usize) * 4
                } else {
                    0
                };
                if len < offset + 8 || buffer[offset] != 0 {
                    continue;
                }
                let seq = u16::from_be_bytes([buffer[offset + 6], buffer[offset + 7]]);
                if seq != self.seq {
                    continue;
                }
                if from.ip() != IpAddr::V4(ip) {
                    continue;
                }
                return Some((start.elapsed().as_secs_f64() * 1000.0).max(0.1));
            }
        }
    }
}

#[cfg(target_os = "android")]
mod imp {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    pub struct IcmpInner;

    impl IcmpInner {
        pub fn new() -> Option<Self> {
            None
        }
        pub fn ping(&mut self, _ip: Ipv4Addr, _timeout: Duration) -> Option<f64> {
            None
        }
    }
}

pub struct Icmp(Option<imp::IcmpInner>);

impl Icmp {
    pub fn new() -> Self {
        Self(imp::IcmpInner::new())
    }

    pub fn available(&self) -> bool {
        self.0.is_some()
    }

    pub fn ping(&mut self, ip: Ipv4Addr, timeout: Duration) -> Option<f64> {
        self.0.as_mut()?.ping(ip, timeout)
    }
}