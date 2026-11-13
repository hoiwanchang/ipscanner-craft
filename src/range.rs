use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize)]
pub struct TargetRange {
    pub start: u32,
    pub end: u32,
    pub label: String,
}

impl TargetRange {
    pub fn count(&self) -> u64 {
        self.end as u64 - self.start as u64 + 1
    }

    pub fn first(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.start)
    }

    pub fn last(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.end)
    }
}

fn ipv4(text: &str) -> Result<u32, String> {
    text.trim()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| format!("\"{}\" is not a valid IPv4 address", text.trim()))
}

/// The end field also accepts a bare last octet, so 192.168.0.1 .. 254 works.
pub fn parse_range(start: &str, end: &str) -> Result<TargetRange, String> {
    let first = ipv4(start)?;
    let end_text = end.trim();
    let last = if !end_text.is_empty() && end_text.chars().all(|c| c.is_ascii_digit()) && !end_text.contains('.') {
        let octet: u32 = end_text
            .parse()
            .map_err(|_| format!("\"{end_text}\" is not a valid last octet"))?;
        if octet > 255 {
            return Err(format!("Last octet {octet} is above 255"));
        }
        (first & 0xffff_ff00) | octet
    } else {
        ipv4(end_text)?
    };
    if last < first {
        return Err("The end of the range is before its start".into());
    }
    Ok(TargetRange {
        start: first,
        end: last,
        label: format!("{} - {}", Ipv4Addr::from(first), Ipv4Addr::from(last)),
    })
}

pub fn parse_cidr(text: &str) -> Result<TargetRange, String> {
    let text = text.trim();
    let (address, bits) = match text.split_once('/') {
        Some((a, b)) => {
            let bits: u32 = b
                .trim()
                .parse()
                .map_err(|_| format!("\"{b}\" is not a valid prefix length"))?;
            if bits > 32 {
                return Err(format!("Prefix length {bits} is above 32"));
            }
            (a, bits)
        }
        None => (text, 32),
    };
    let address = ipv4(address)?;
    let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    let network = address & mask;
    let broadcast = network | !mask;
    Ok(TargetRange {
        start: network,
        end: broadcast,
        label: format!("{}/{bits}", Ipv4Addr::from(network)),
    })
}

/// Guess the machine's own /24 so the app opens on a range worth scanning.
pub fn local_subnet() -> TargetRange {
    let local = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .ok()
        .and_then(|addr| match addr.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
    let base = u32::from(local) & 0xffff_ff00;
    TargetRange {
        start: base + 1,
        end: base + 254,
        label: format!("{} - {}", Ipv4Addr::from(base + 1), Ipv4Addr::from(base + 254)),
    }
}