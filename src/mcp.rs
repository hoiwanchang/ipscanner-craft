use crate::net::Icmp;
use crate::range;
use crate::scan::{self, ScanOptions};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::{schemars, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const DEFAULT_THREADS: u32 = 100; // dev/test concurrency cap <= 100 to avoid IP bans
pub const MAX_THREADS: u32 = 100;
const DEFAULT_TIMEOUT: u32 = 1000;
fn default_ports() -> PortsSpec {
    PortsSpec::List(vec![80, 443, 22])
}
pub const MAX_HOSTS_HARD_CAP: u64 = 65_536;
const DEFAULT_MAX_HOSTS: u64 = 4096;
pub const MCP_MAX_PORTS: usize = 1024;

/// Ports accept either a JSON array [80,443] or a range string
/// "80,443,8000-8100" — the string form keeps large scans compact.
/// Ports are digits only; any char that is not a digit and not a range
/// joiner separates — so Chinese commas ，、fullwidth, slashes, pipes, tabs
/// etc. all work without switching the IME. -~–— (and fullwidth ～) join ranges.
pub fn parse_port_text(text: &str) -> Vec<u16> {
    let is_range = |c: char| matches!(c, '-' | '~' | '\u{ff5e}' | '–' | '—');
    let mut seen = std::collections::BTreeSet::new();
    let mut token = String::new();
    let flush = |token: &mut String, seen: &mut std::collections::BTreeSet<u16>| {
        if token.is_empty() {
            return;
        }
        let parts: String = token.chars().filter(|c| c.is_ascii_digit() || is_range(*c)).collect();
        if let Some((a, b)) = parts.split_once(is_range) {
            if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                let lo = a.clamp(1, 65535).min(b.clamp(1, 65535));
                let hi = b.clamp(1, 65535).max(a.clamp(1, 65535));
                let mut p = lo;
                while p <= hi && seen.len() < MCP_MAX_PORTS {
                    seen.insert(p as u16);
                    p += 1;
                }
            }
        } else if let Ok(p) = parts.parse::<u16>() {
            if p >= 1 {
                seen.insert(p);
            }
        }
        token.clear();
    };
    for ch in text.chars() {
        if ch.is_ascii_digit() || is_range(ch) {
            token.push(ch);
        } else {
            flush(&mut token, &mut seen);
        }
    }
    flush(&mut token, &mut seen);
    seen.into_iter().collect()
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum PortsSpec {
    List(Vec<u16>),
    Text(String),
}

impl PortsSpec {
    pub fn expand(&self) -> Vec<u16> {
        let mut seen = std::collections::BTreeSet::new();
        match self {
            PortsSpec::List(v) => {
                for &p in v {
                    if (1..=65535).contains(&p) {
                        seen.insert(p);
                        if seen.len() >= MCP_MAX_PORTS {
                            break;
                        }
                    }
                }
            }
            PortsSpec::Text(text) => {
                for p in parse_port_text(text) {
                    seen.insert(p);
                }
            }
        }
        seen.into_iter().collect()
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanRequest {
    /// Target: CIDR (192.168.1.1/24), range (192.168.1.1-192.168.1.254),
    /// shorthand range (192.168.1.1-254) or a single IP. Stock default
    /// network is 192.168.1.1/24; the sanctioned test target is
    /// 172.18.13.80/32 (single host, safe for automated dev runs).
    pub target: String,
    /// Concurrent worker threads, 1-100 (hard cap, anti-IP-ban). Default 100.
    pub threads: u32,
    /// Per-probe timeout in milliseconds, 50-30000. Default 1000.
    pub timeout_ms: u32,
    /// Ping method: "auto" (ICMP then TCP), "icmp" (no TCP sockets at all —
    /// port scanning is disabled) or "tcp". Default "auto".
    pub ping_method: String,
    /// TCP ports to check on live hosts, e.g. [80,443] or "80,443,8000-8100".
    /// Default "80,443,22". Up to 1024 distinct ports.
    pub ports: PortsSpec,
    /// Scan the ports above on each host. Default true.
    pub scan_ports: bool,
    /// Reverse-resolve hostnames for live hosts. Default true.
    pub resolve_hostnames: bool,
    /// Only return live hosts. Default false (return everything).
    pub alive_only: bool,
    /// Safety cap on addresses probed; scanning stops after this many.
    /// Default 4096, hard cap 65536.
    pub max_hosts: u64,
}

impl Default for ScanRequest {
    fn default() -> Self {
        ScanRequest {
            target: String::new(),
            threads: DEFAULT_THREADS,
            timeout_ms: DEFAULT_TIMEOUT,
            ping_method: "auto".into(),
            ports: default_ports(),
            scan_ports: true,
            resolve_hostnames: true,
            alive_only: false,
            max_hosts: DEFAULT_MAX_HOSTS,
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ProbeRequest {
    /// A single IPv4 address, e.g. 192.168.1.1
    pub target: String,
    /// TCP ports to check, e.g. [80,443] or "80,443,8000-8100". Default "80,443,22".
    pub ports: PortsSpec,
    /// Per-probe timeout in milliseconds. Default 1000.
    pub timeout_ms: u32,
    /// Ping method: "auto", "icmp" or "tcp". Default "auto".
    pub ping_method: String,
}

impl Default for ProbeRequest {
    fn default() -> Self {
        ProbeRequest {
            target: String::new(),
            ports: default_ports(),
            timeout_ms: DEFAULT_TIMEOUT,
            ping_method: "auto".into(),
        }
    }
}

fn resolve_target(text: &str) -> Result<range::TargetRange, String> {
    let text = if text.trim().is_empty() {
        crate::DEFAULT_CIDR // stock default: 192.168.1.1/24
    } else {
        text.trim()
    };
    if text.contains('/') {
        return range::parse_cidr(text);
    }
    if let Some((start, end)) = text.split_once('-') {
        return range::parse_range(start, end);
    }
    if text.parse::<Ipv4Addr>().is_ok() {
        return range::parse_range(text, text);
    }
    Err(format!("could not understand target \"{text}\" (use CIDR, a range or a single IPv4)"))
}

fn build_options(
    threads: u32,
    timeout_ms: u32,
    ping_method: &str,
    ports: &PortsSpec,
    scan_ports: bool,
    resolve_hostnames: bool,
) -> ScanOptions {
    let mut options = ScanOptions {
        threads: threads.clamp(1, MAX_THREADS),
        timeout_ms: timeout_ms.clamp(50, 30_000),
        ping_method: match ping_method.trim().to_lowercase().as_str() {
            "" | "auto" => "icmp-tcp".into(),
            other => other.into(),
        },
        ports: {
            let mut p = ports.expand();
            p.truncate(MCP_MAX_PORTS);
            p
        },
        resolve_hostnames,
        scan_ports,
        ports_alive_only: true,
    };
    if options.ping_method == "masscan" {
        if !crate::masscan::available() || !crate::masscan::driver_present() {
            options.ping_method = "icmp-tcp".into();
        }
    } else if !matches!(options.ping_method.as_str(), "tcp" | "masscan")
        && !Icmp::new().available()
    {
        options.ping_method = "tcp".into();
    }
    options
}

#[derive(Debug, Clone)]
pub struct IpScanServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl IpScanServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Scan an IPv4 network: ping hosts over a CIDR block or address range, detect open TCP ports and resolve hostnames. Returns JSON rows (ip, hostname, alive, pingMs, method, openPorts) plus a summary. Use max_hosts to keep large ranges bounded."
    )]
    async fn scan_network(
        &self,
        Parameters(request): Parameters<ScanRequest>,
    ) -> Result<String, String> {
        let range = resolve_target(&request.target)?;
        let total = range.count();
        let capped = total.min(request.max_hosts.clamp(1, MAX_HOSTS_HARD_CAP));
        let options = build_options(
            request.threads,
            request.timeout_ms,
            &request.ping_method,
            &request.ports,
            request.scan_ports,
            request.resolve_hostnames,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let started = std::time::Instant::now();
        let mut rows =
            tokio::task::spawn_blocking(move || scan::scan_batch(options, range, capped, stop))
                .await
                .map_err(|e| format!("scan task failed: {e}"))?;
        let alive = rows.iter().filter(|r| r.alive).count();
        if request.alive_only {
            rows.retain(|r| r.alive);
        }
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "target": request.target,
            "rangeLabel": format!("{} - {}", rows.first().map(|r| r.ip.clone()).unwrap_or_default(), rows.last().map(|r| r.ip.clone()).unwrap_or_default()),
            "scanned": capped,
            "rangeTotal": total,
            "truncated": capped < total,
            "alive": alive,
            "returned": rows.len(),
            "elapsedMs": started.elapsed().as_millis(),
            "hosts": rows,
        }))
        .map_err(|e| e.to_string())?)
    }

    #[tool(
        description = "Probe a single IPv4 host now: ping it (ICMP with TCP fallback) and check TCP ports. Much cheaper than scan_network for one host. Returns one JSON row."
    )]
    async fn probe_host(
        &self,
        Parameters(request): Parameters<ProbeRequest>,
    ) -> Result<String, String> {
        let ip: Ipv4Addr = request
            .target
            .trim()
            .parse()
            .map_err(|_| format!("\"{}\" is not a valid IPv4 address", request.target))?;
        let options = build_options(
            1,
            request.timeout_ms,
            &request.ping_method,
            &request.ports,
            true,
            true,
        );
        let row = tokio::task::spawn_blocking(move || scan::probe_one(ip, &options))
            .await
            .map_err(|e| format!("probe task failed: {e}"))?;
        Ok(serde_json::to_string_pretty(&row).map_err(|e| e.to_string())?)
    }

    #[tool(
        description = "Report the local machine's network context: detected local subnet, whether ICMP is available, scanner version. Call this first to choose sensible scan targets."
    )]
    fn local_info(&self) -> String {
        let subnet = range::local_subnet();
        serde_json::to_string_pretty(&serde_json::json!({
            "localSubnet": {
                "first": subnet.first().to_string(),
                "last": subnet.last().to_string(),
                "count": subnet.count(),
                "label": subnet.label,
            },
            "icmpAvailable": Icmp::new().available(),
            "version": env!("CARGO_PKG_VERSION"),
            "policy": {
                "defaultNetwork": crate::DEFAULT_CIDR,
                "testTarget": crate::TEST_TARGET,
                "maxThreads": MAX_THREADS,
                "note": "dev/test runs must stay on testTarget with threads <= max_threads to avoid IP bans",
            },
        }))
        .unwrap_or_default()
    }
}

impl Default for IpScanServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for IpScanServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "ipscanner-craft MCP: scan IPv4 ranges and CIDR blocks with ICMP/TCP ping, \
                 detect open ports and resolve hostnames. Stock default network is \
                 192.168.1.1/24; for automated dev/test use target 172.18.13.80/32 and \
                 keep threads <= 100 (hard cap) to avoid IP bans. Call local_info first.",
            )
    }
}

/// Serve the MCP protocol over stdio. All logging must go to stderr.
pub async fn serve_stdio() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = IpScanServer::new();
    eprintln!(
        "ipscan-mcp {}: serving {} tools on stdio",
        env!("CARGO_PKG_VERSION"),
        service.tool_router.list_all().len()
    );
    let server = <IpScanServer as ServiceExt<rmcp::RoleServer>>::serve(
        service,
        rmcp::transport::stdio(),
    )
    .await?;
    server.waiting().await?;
    Ok(())
}
