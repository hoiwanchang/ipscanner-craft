use crate::net::{self, Icmp, TcpOutcome};
use crate::range::TargetRange;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub threads: u32,
    pub timeout_ms: u32,
    pub ping_method: String,
    pub ports: Vec<u16>,
    pub resolve_hostnames: bool,
    pub scan_ports: bool,
    pub ports_alive_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    pub ip: String,
    pub ip_num: u32,
    pub hostname: String,
    pub alive: bool,
    pub ping_ms: Option<f64>,
    pub method: String,
    pub open_ports: Vec<u16>,
    pub ports_scanned: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RowsBatch {
    id: u64,
    rows: Vec<HostResult>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    id: u64,
    scanned: u64,
    total: u64,
    alive: u64,
    dead: u64,
    running: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Finished {
    id: u64,
    cancelled: bool,
    elapsed_ms: u128,
    scanned: u64,
    alive: u64,
}

fn probe_host(ip: Ipv4Addr, options: &ScanOptions, icmp: &mut Icmp) -> HostResult {
    let timeout = Duration::from_millis(options.timeout_ms.clamp(50, 30_000) as u64);
    let icmp_only = options.ping_method == "icmp";
    let mut alive = false;
    let mut ping_ms = None;
    let mut method = String::new();

    if options.ping_method != "tcp" {
        if let Some(ms) = icmp.ping(ip, timeout) {
            alive = true;
            ping_ms = Some(ms);
            method = "ICMP".into();
        }
    }
    if !alive && options.ping_method == "icmp-tcp" {
        if let Some(ms) = net::tcp_ping(ip, timeout) {
            alive = true;
            ping_ms = Some(ms);
            method = "TCP".into();
        }
    }

    let mut open_ports = Vec::new();
    let mut ports_scanned = false;
    // "ICMP only" means the engine must never open a TCP socket to the target.
    if !icmp_only
        && options.scan_ports
        && !options.ports.is_empty()
        && (alive || !options.ports_alive_only)
    {
        ports_scanned = true;
        let (answered, ports) = probe_ports_parallel(ip, &options.ports, timeout);
        open_ports = ports;
        if !alive && answered {
            // any RST/SYN-ACK proves the host is up
            alive = true;
            method = "TCP".into();
        }
    }

    let hostname = if options.resolve_hostnames && alive {
        net::reverse_dns(ip).unwrap_or_default()
    } else {
        String::new()
    };

    HostResult {
        ip: ip.to_string(),
        ip_num: u32::from(ip),
        hostname,
        alive,
        ping_ms,
        method,
        open_ports,
        ports_scanned,
    }
}

pub fn probe_one(ip: Ipv4Addr, options: &ScanOptions) -> HostResult {
    probe_host(ip, options, &mut Icmp::new())
}

/// Ports run in parallel inside one host, in bounded waves: worst case is
/// ceil(ports/wave) x timeout, never one OS thread per port on a /8 range.
/// Returns (answered, open ports).
/// "answered" = any port drew a RST or SYN-ACK, which proves the host is up.
fn probe_ports_parallel(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> (bool, Vec<u16>) {
    const WAVE: usize = 48;
    #[derive(Clone, Copy)]
    enum Slot {
        Open,
        ClosedAnswered,
        Silent,
    }
    let mut answered = false;
    let mut open = Vec::new();
    for chunk in ports.chunks(WAVE) {
        let (tx, rx) = mpsc::channel::<(u16, Slot)>();
        let mut handles = Vec::with_capacity(chunk.len());
        for &port in chunk {
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                let slot = match net::tcp_probe(ip, port, timeout) {
                    TcpOutcome::Open(_) => Slot::Open,
                    TcpOutcome::Refused(_) => Slot::ClosedAnswered,
                    TcpOutcome::Unreachable => Slot::Silent,
                };
                let _ = tx.send((port, slot));
            }));
        }
        drop(tx);
        for (port, slot) in rx.iter() {
            match slot {
                Slot::Open => open.push(port),
                Slot::ClosedAnswered => answered = true,
                Slot::Silent => {}
            }
        }
        for h in handles {
            let _ = h.join();
        }
    }
    open.sort_unstable();
    (answered, open)
}

/// Headless batch scan — no Tauri dependency, for the MCP server and CLI.
pub fn scan_batch(
    options: ScanOptions,
    range: TargetRange,
    max_hosts: u64,
    stop: Arc<AtomicBool>,
) -> Vec<HostResult> {
    if options.ping_method == "masscan" {
        return crate::masscan::run(&options, &range, max_hosts, &stop).unwrap_or_default();
    }
    let total = range.count().min(max_hosts.max(1));
    let workers = (options.threads.clamp(1, crate::MAX_CONCURRENT_THREADS) as u64).min(total) as usize;
    let cursor = Arc::new(AtomicU64::new(range.start as u64));
    let end = range.start as u64 + total - 1;
    let (tx, rx) = mpsc::channel::<HostResult>();

    for _ in 0..workers {
        let cursor = Arc::clone(&cursor);
        let stop = Arc::clone(&stop);
        let tx = tx.clone();
        let options = options.clone();
        std::thread::spawn(move || {
            let mut icmp = Icmp::new();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let next = cursor.fetch_add(1, Ordering::Relaxed);
                if next > end {
                    break;
                }
                let row = probe_host(Ipv4Addr::from(next as u32), &options, &mut icmp);
                if tx.send(row).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut rows = Vec::new();
    while let Ok(row) = rx.recv() {
        rows.push(row);
    }
    rows.sort_by_key(|r| r.ip_num);
    rows
}

pub fn spawn(app: AppHandle, id: u64, options: ScanOptions, range: TargetRange, stop: Arc<AtomicBool>) {
    if options.ping_method == "masscan" {
        spawn_masscan(app, id, options, range, stop);
        return;
    }
    let total = range.count();
    let workers = (options.threads.clamp(1, crate::MAX_CONCURRENT_THREADS) as u64).min(total) as usize;
    let cursor = Arc::new(AtomicU64::new(range.start as u64));
    let end = range.end as u64;
    let (tx, rx) = mpsc::channel::<HostResult>();

    for _ in 0..workers {
        let cursor = Arc::clone(&cursor);
        let stop = Arc::clone(&stop);
        let tx = tx.clone();
        let options = options.clone();
        std::thread::spawn(move || {
            let mut icmp = Icmp::new();
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let next = cursor.fetch_add(1, Ordering::Relaxed);
                if next > end {
                    break;
                }
                let row = probe_host(Ipv4Addr::from(next as u32), &options, &mut icmp);
                if tx.send(row).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    std::thread::spawn(move || {
        let started = Instant::now();
        let mut scanned = 0u64;
        let mut alive = 0u64;
        let mut batch: Vec<HostResult> = Vec::new();

        let progress = |scanned: u64, alive: u64, running: bool| Progress {
            id,
            scanned,
            total,
            alive,
            dead: scanned - alive,
            running,
        };
        let send_rows = |app: &AppHandle, rows: Vec<HostResult>| {
            let _ = app.emit("scan://rows", RowsBatch { id, rows });
        };

        loop {
            match rx.recv_timeout(Duration::from_millis(80)) {
                Ok(row) => {
                    scanned += 1;
                    if row.alive {
                        alive += 1;
                    }
                    batch.push(row);
                    if batch.len() >= 48 {
                        send_rows(&app, std::mem::take(&mut batch));
                        let _ = app.emit("scan://progress", progress(scanned, alive, true));
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !batch.is_empty() {
                        send_rows(&app, std::mem::take(&mut batch));
                    }
                    let _ = app.emit("scan://progress", progress(scanned, alive, true));
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        if !batch.is_empty() {
            send_rows(&app, batch);
        }
        let _ = app.emit("scan://progress", progress(scanned, alive, false));
        let _ = app.emit(
            "scan://done",
            Finished {
                id,
                cancelled: stop.load(Ordering::Relaxed),
                elapsed_ms: started.elapsed().as_millis(),
                scanned,
                alive,
            },
        );
    });
}

/// masscan path: one process blast, then rows + done events. masscan only
/// reports answering hosts, so the dead ones simply never appear.
fn spawn_masscan(
    app: AppHandle,
    id: u64,
    options: ScanOptions,
    range: TargetRange,
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let started = Instant::now();
        let total = range.count();
        match crate::masscan::run(&options, &range, total, &stop) {
            Ok(rows) => {
                let alive = rows.len() as u64;
                for chunk in rows.chunks(200) {
                    let _ = app.emit(
                        "scan://rows",
                        RowsBatch {
                            id,
                            rows: chunk.to_vec(),
                        },
                    );
                }
                let scanned = if stop.load(Ordering::Relaxed) {
                    0
                } else {
                    total
                };
                let _ = app.emit(
                    "scan://progress",
                    Progress {
                        id,
                        scanned,
                        total,
                        alive,
                        dead: scanned.saturating_sub(alive),
                        running: false,
                    },
                );
                let _ = app.emit(
                    "scan://done",
                    Finished {
                        id,
                        cancelled: stop.load(Ordering::Relaxed),
                        elapsed_ms: started.elapsed().as_millis(),
                        scanned,
                        alive,
                    },
                );
            }
            Err(error) => {
                let _ = app.emit(
                    "scan://error",
                    serde_json::json!({"id": id, "error": error}),
                );
            }
        }
    });
}