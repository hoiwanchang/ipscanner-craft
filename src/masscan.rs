//! masscan bridge: spawns an external masscan process and turns its
//! grepable output into HostResult rows. masscan is optional — if the
//! binary or the Npcap driver is missing this path reports an error and
//! the caller falls back to the built-in engine.
//!
//! Why a bridge instead of vendoring the code: masscan is GPLv2, this
//! project stays Apache-2.0; process isolation also keeps raw-socket
//! driver crashes from taking the app down.

use crate::range::TargetRange;
use crate::scan::{HostResult, ScanOptions};
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Where we look for the masscan binary, in order.
fn candidate_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(p) = std::env::var("IPSCAN_MASSCAN") {
        v.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["masscan.exe", "masscan"] {
                v.push(dir.join(name));
            }
        }
    }
    v.push(PathBuf::from(r"C:\Tools\masscan\masscan.exe"));
    v
}

pub fn find_masscan() -> Option<PathBuf> {
    candidate_paths().into_iter().find(|p| p.exists())
}

pub fn available() -> bool {
    find_masscan().is_some()
}

/// True when the Npcap/WinPcap driver masscan needs is present.
pub fn driver_present() -> bool {
    PathBuf::new().join(r"C:\Windows\System32\drivers\npcap.sys").exists()
        || PathBuf::new()
            .join(r"C:\Windows\System32\drivers\npfsimp.sys")
            .exists()
        || PathBuf::new().join(r"C:\Windows\System32\wpcap.dll").exists()
}

/// Best-guess default gateway — masscan needs it as --router.
fn detect_gateway() -> Option<Ipv4Addr> {
    #[cfg(windows)]
    {
        let out = Command::new("ipconfig").args(["/all"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with("Default Gateway") || l.starts_with("默认网关") {
                if let Some(ip) = l
                    .split(':')
                    .nth(1)
                    .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
                {
                    if !ip.is_unspecified() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        let out = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut after_via = false;
        for word in text.split_whitespace() {
            if after_via {
                if let Ok(ip) = word.parse::<Ipv4Addr>() {
                    return Some(ip);
                }
            }
            after_via = word == "via";
        }
    }
    None
}

fn local_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:53").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

/// Kills the child when dropped, whatever exit path we take.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run one masscan pass and return live hosts as rows.
/// Dead addresses are simply absent from the output (like Angry's "alive only" view).
pub fn run(
    options: &ScanOptions,
    range: &TargetRange,
    max_hosts: u64,
    stop: &AtomicBool,
) -> Result<Vec<HostResult>, String> {
    let exe = find_masscan()
        .ok_or("masscan.exe not found — set IPSCAN_MASSCAN or install to C:\\Tools\\masscan\\")?;
    if !driver_present() {
        return Err("Npcap driver not installed — masscan needs it (npcap.com, tick \"Install Npcap in WinPcap API-compatible Mode\")".into());
    }
    let gateway = detect_gateway().ok_or("could not detect the default gateway for --router")?;
    let source_ip = local_ipv4().ok_or("could not detect the local IPv4 address")?;

    let ports_arg = {
        let mut list = options.ports.clone();
        if list.is_empty() {
            list.push(80);
        }
        list.sort_unstable();
        list.dedup();
        // masscan understands 8000-8100 natively — send ranges, not 1024 singles
        let mut groups: Vec<String> = Vec::new();
        let (mut start, mut prev) = (list[0], list[0]);
        for &p in &list[1..] {
            if p == prev + 1 {
                prev = p;
                continue;
            }
            groups.push(if start == prev { start.to_string() } else { format!("{start}-{prev}") });
            start = p;
            prev = p;
        }
        groups.push(if start == prev { start.to_string() } else { format!("{start}-{prev}") });
        groups.join(",")
    };
    let range_arg = format!("{}-{}", range.first(), range.last());
    // threads map loosely to packets/sec: 1k pps per "thread", cap 100k
    let rate = (options.threads as u64 * 1_000).clamp(1_000, 100_000);
    let wait = (options.timeout_ms as u64 / 1000).clamp(3, 120);

    let mut child = Command::new(&exe)
        .args([
            "--output-format",
            "grepable",
            "--wait",
            &wait.to_string(),
            "--rate",
            &rate.to_string(),
            "--min-hosts",
            "1",
            "--router",
            &gateway.to_string(),
            "--source-ip",
            &source_ip.to_string(),
            "-p",
            &ports_arg,
            &range_arg,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start masscan: {e}"))?;

    let stdout = child.stdout.take().ok_or("masscan stdout missing")?;
    let guard = Guard(child);
    let started = Instant::now();

    // ip_num -> (open ports, first answer ms)
    let mut hosts: std::collections::BTreeMap<u32, (Vec<u16>, f64)> = Default::default();
    let mut lines = BufReader::new(stdout).lines();
    let mut timed_out = false;

    loop {
        if stop.load(Ordering::Relaxed) || started.elapsed().as_secs() > wait * 2 + 30 {
            timed_out = true;
            break; // guard drops below and kills the child
        }
        let line = match lines.next() {
            None => break, // stdout closed: masscan exited
            Some(Err(_)) => break,
            Some(Ok(l)) => l,
        };
        // Host 192.168.1.1 () appears(0.010s): ports 80 open 443 open
        let rest = match line.strip_prefix("Host ") {
            Some(r) => r,
            None => continue,
        };
        let mut it = rest.split_whitespace();
        let ip: Ipv4Addr = match it.next().and_then(|t| t.parse().ok()) {
            Some(ip) => ip,
            None => continue,
        };
        let idx = match line.find("ports ") {
            Some(i) => i + 6,
            None => continue,
        };
        let ms = match (line.find('('), line.find("s):")) {
            (Some(a), Some(b)) if b > a => {
                line[a + 1..b].parse::<f64>().map(|v| v * 1000.0).unwrap_or(0.0)
            }
            _ => started.elapsed().as_secs_f64() * 1000.0,
        };
        let entry = hosts.entry(u32::from(ip)).or_insert((Vec::new(), ms));
        let toks: Vec<&str> = line[idx..].split_whitespace().collect();
        for w in toks.windows(2) {
            if w[1] == "open" {
                if let Ok(p) = w[0].parse::<u16>() {
                    if !entry.0.contains(&p) {
                        entry.0.push(p);
                    }
                }
            }
        }
        if hosts.len() as u64 >= max_hosts {
            break;
        }
    }
    drop(guard);

    let mut rows: Vec<HostResult> = hosts
        .into_iter()
        .map(|(num, (mut ports, ms))| {
            ports.sort_unstable();
            HostResult {
                ip: Ipv4Addr::from(num).to_string(),
                ip_num: num,
                hostname: String::new(),
                alive: true,
                ping_ms: Some(ms),
                method: "masscan".into(),
                open_ports: ports,
                ports_scanned: true,
            }
        })
        .collect();

    if options.resolve_hostnames {
        for row in &mut rows {
            if let Ok(ip) = row.ip.parse() {
                row.hostname = crate::net::reverse_dns(ip).unwrap_or_default();
            }
        }
    }
    if timed_out && rows.is_empty() {
        return Err("masscan was stopped before it produced results".into());
    }
    Ok(rows)
}
