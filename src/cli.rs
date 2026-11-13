//! Headless command line interface: `ip-scanner.exe cli [scan] <target> [options]`
//! or the dedicated `ipscanner-craft-cli.exe`. Shares the engine, defaults and the
//! concurrency cap with the GUI and the MCP server. No Tauri, no WebView2.

use crate::export;
use crate::mcp::PortsSpec;
use crate::net::Icmp;
use crate::range;
use crate::scan::{self, ScanOptions};
use std::io::Write;
use std::process::ExitCode;

const HELP: &str = r#"ipscanner-craft CLI (same engine as the GUI and the MCP server)

Usage:
  ipscanner-craft-cli [scan] TARGET [options]
  ipscanner-craft-cli TARGET [options]              (leading "scan" optional)

TARGET
  192.168.1.1/24 | 192.168.1.1-192.168.1.254 | 192.168.1.1-254 | single IP
  Omit TARGET to use the stock default network (192.168.1.1/24).

OPTIONS
  --tcp-ports SPEC     Ports to check, e.g. 22,80,443 or "8000-8100".
                       Default 80,443,22. Use "none" to skip port checks.
  --method M           icmp-tcp | icmp | tcp | masscan   (default icmp-tcp)
  --threads N          Concurrent workers, 1-100 hard cap. Default 50.
  --timeout MS         Per-probe timeout, 50-30000 ms. Default 1000.
  --format F           text | csv | json                          (default text)
  --out PATH           Write to file instead of stdout.
  --alive-only         Report live hosts only.
  --no-hostnames       Skip reverse DNS (faster).
  --max-hosts N        Safety cap on addresses probed. Default 4096 (max 65536).
  --version | -V       Print version.
  --help  | -h         Print this help.

Examples:
  ipscanner-craft-cli 172.18.13.80/32
  ipscanner-craft-cli 192.168.1.1-254 --tcp-ports 22,80,443,8000-8100 --format json --out scan.json
  ipscanner-craft-cli 10.0.0.0/24 --alive-only --no-hostnames --threads 100
"#;

struct Args {
    target: String,
    ports: PortsSpec,
    skip_ports: bool,
    method: String,
    threads: u32,
    timeout_ms: u32,
    format: String,
    out: Option<String>,
    alive_only: bool,
    hostnames: bool,
    max_hosts: u64,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            target: String::new(),
            ports: PortsSpec::Text("80,443,22".into()),
            skip_ports: false,
            method: "icmp-tcp".into(),
            threads: 50,
            timeout_ms: 1000,
            format: "text".into(),
            out: None,
            alive_only: false,
            hostnames: true,
            max_hosts: 4096,
        }
    }
}

fn parse_args(argv: &[String]) -> Result<Option<Args>, (String, bool)> {
    let mut args = Args::default();
    let mut i = 0usize;
    // optional subcommand
    if argv.get(i).map(|s| s.as_str()) == Some("cli") || argv.get(i).map(|s| s.as_str()) == Some("scan") {
        i += 1;
        if argv.get(i).map(|s| s.as_str()) == Some("scan") {
            i += 1;
        }
    }
    let mut target_seen = false;
    // returns the value following the current flag, advancing i
    let value_of = |i: &mut usize, flag: &str| -> Result<String, (String, bool)> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| (format!("{flag} needs a value"), true))
    };
    while i < argv.len() {
        let token = argv[i].clone();
        match token.as_str() {
            "-h" | "--help" => return Err((HELP.into(), false)),
            "-V" | "--version" => {
                return Err((format!("ipscanner-craft-cli {}\n", env!("CARGO_PKG_VERSION")), false))
            }
            "--tcp-ports" => {
                let spec = value_of(&mut i, "--tcp-ports")?;
                if spec.eq_ignore_ascii_case("none") {
                    args.skip_ports = true;
                } else {
                    args.ports = PortsSpec::Text(spec);
                }
            }
            "--method" => args.method = value_of(&mut i, "--method")?,
            "--threads" => {
                let v = value_of(&mut i, "--threads")?;
                args.threads = v.parse().map_err(|_| ("--threads expects a number".to_string(), true))?;
            }
            "--timeout" => {
                let v = value_of(&mut i, "--timeout")?;
                args.timeout_ms =
                    v.parse().map_err(|_| ("--timeout expects milliseconds".to_string(), true))?;
            }
            "--format" => args.format = value_of(&mut i, "--format")?.to_lowercase(),
            "--out" => args.out = Some(value_of(&mut i, "--out")?),
            "--max-hosts" => {
                let v = value_of(&mut i, "--max-hosts")?;
                args.max_hosts =
                    v.parse().map_err(|_| ("--max-hosts expects a number".to_string(), true))?;
            }
            "--alive-only" => args.alive_only = true,
            "--no-hostnames" => args.hostnames = false,
            other => {
                if other.starts_with("--") {
                    return Err((format!("unknown option: {other}\n\n{HELP}"), true));
                }
                if target_seen {
                    return Err((format!("unexpected extra argument: {other}"), true));
                }
                args.target = other.into();
                target_seen = true;
            }
        }
        i += 1;
    }
    if !matches!(args.format.as_str(), "text" | "csv" | "json") {
        return Err((format!("unknown --format: {}", args.format), true));
    }
    if args.target.trim().is_empty() {
        args.target = crate::DEFAULT_CIDR.into();
    }
    Ok(Some(args))
}

fn build_scan_options(args: &Args) -> Result<ScanOptions, String> {
    let mut ports = args.ports.expand();
    if ports.len() > crate::mcp::MCP_MAX_PORTS {
        ports.truncate(crate::mcp::MCP_MAX_PORTS);
    }
    let mut options = ScanOptions {
        threads: args.threads.clamp(1, crate::MAX_CONCURRENT_THREADS),
        timeout_ms: args.timeout_ms.clamp(50, 30_000),
        ping_method: args.method.clone(),
        ports,
        resolve_hostnames: args.hostnames,
        scan_ports: !args.skip_ports,
        ports_alive_only: true,
    };
    // same fallback policy as the GUI
    if options.ping_method == "masscan" && (!crate::masscan::available() || !crate::masscan::driver_present()) {
        options.ping_method = "icmp-tcp".into();
    }
    if !matches!(options.ping_method.as_str(), "tcp" | "masscan") && !Icmp::new().available() {
        options.ping_method = "tcp".into();
    }
    if options.ping_method == "icmp" {
        options.scan_ports = false;
    }
    if !matches!(
        options.ping_method.as_str(),
        "icmp-tcp" | "icmp" | "tcp" | "masscan"
    ) {
        return Err(format!("unknown --method: {}", args.method));
    }
    Ok(options)
}

fn text_table(rows: &[scan::HostResult], range_label: &str, elapsed_ms: u128) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<16} {:<24} {:<6} {:>8}  {:<8} {}\n",
        "IP", "Hostname", "State", "Ping", "Method", "Open ports"
    ));
    out.push_str(&"-".repeat(88));
    out.push('\n');
    for r in rows {
        let state = if r.alive { "alive" } else { "dead" };
        let ping = match r.ping_ms {
            Some(ms) if ms < 10.0 => format!("{ms:.1} ms"),
            Some(ms) => format!("{} ms", ms.round() as i64),
            None => String::new(),
        };
        let ports = if !r.ports_scanned {
            String::new()
        } else {
            export::compress_ports(&r.open_ports)
        };
        let host = if r.hostname.len() > 24 {
            r.hostname[..24].to_string()
        } else {
            r.hostname.clone()
        };
        out.push_str(&format!(
            "{:<16} {:<24} {:<6} {:>8}  {:<8} {}\n",
            r.ip, host, state, ping, r.method, ports
        ));
    }
    let alive = rows.iter().filter(|r| r.alive).count();
    out.push_str(&format!(
        "\n{range_label}: {} host(s) listed, {alive} alive, {:.1}s\n",
        rows.len(),
        elapsed_ms as f64 / 1000.0
    ));
    out
}

pub fn dispatch(argv: &[String]) -> ExitCode {
    // A parse error carrying is_error=false is really --help/--version.
    if let Err((message, is_error)) = parse_args(argv) {
        if is_error {
            let _ = writeln!(std::io::stderr(), "{message}");
            return ExitCode::FAILURE;
        }
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(message.as_bytes());
        let _ = stdout.flush();
        return ExitCode::SUCCESS;
    }
    match run(argv) {
        Ok(text) => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
            ExitCode::SUCCESS
        }
        Err((message, _)) => {
            let _ = writeln!(std::io::stderr(), "{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(argv: &[String]) -> Result<String, (String, bool)> {
    let args = match parse_args(argv) {
        Ok(Some(args)) => args,
        Ok(None) => unreachable!(),
        Err((message, is_error)) => return Err((message, is_error)),
    };
    let resolved = if args.target.trim().contains('/') {
        range::parse_cidr(&args.target)
    } else if let Some((s, e)) = args.target.split_once('-') {
        range::parse_range(s, e)
    } else {
        let t = args.target.trim().to_string();
        range::parse_range(&t, &t)
    }
    .map_err(|e| (format!("bad target: {e}"), true))?;

    let options = build_scan_options(&args).map_err(|e| (e, true))?;
    let max_hosts = args.max_hosts.clamp(1, crate::mcp::MAX_HOSTS_HARD_CAP);
    let label = resolved.label.clone();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started = std::time::Instant::now();
    let mut rows =
        scan::scan_batch(options.clone(), resolved, max_hosts, std::sync::Arc::clone(&stop));
    let elapsed_ms = started.elapsed().as_millis();
    if args.alive_only {
        rows.retain(|r| r.alive);
    }

    if args.format == "csv" {
        let text = csv_text(&rows, &options.ports);
        return write_output(args.out, text);
    }
    if args.format == "json" {
        let document = serde_json::json!({
            "generator": format!("ipscanner-craft-cli {}", env!("CARGO_PKG_VERSION")),
            "range": label,
            "scannedPorts": options.ports,
            "elapsedMs": elapsed_ms,
            "hostCount": rows.len(),
            "aliveCount": rows.iter().filter(|r| r.alive).count(),
            "hosts": rows,
        });
        let text = serde_json::to_string_pretty(&document)
            .map_err(|e| (format!("json error: {e}"), true))?;
        return write_output(args.out, text);
    }
    write_output(args.out, text_table(&rows, &label, elapsed_ms))
}

fn csv_text(rows: &[scan::HostResult], ports: &[u16]) -> String {
    // reuse the GUI exporter by round-tripping through a temp buffer file
    // is overkill; build the same shape in memory instead.
    let detailed = ports.len() <= crate::export::PER_PORT_COLUMN_MAX;
    let mut out = String::from("IP,Hostname,Status,Ping (ms),Method,Open ports");
    if detailed {
        for p in ports {
            out.push_str(&format!(",Port {p}"));
        }
    }
    out.push('\n');
    for r in rows {
        let ping = r.ping_ms.map(|ms| format!("{ms:.1}")).unwrap_or_default();
        let open = if detailed {
            r.open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            export::compress_ports(&r.open_ports)
        };
        let mut cells: Vec<String> = vec![
            r.ip.clone(),
            r.hostname.clone(),
            if r.alive { "alive" } else { "dead" }.into(),
            ping,
            r.method.clone(),
            open,
        ];
        for cell in &mut cells {
            if cell.contains([',', '"']) {
                *cell = format!("\"{}\"", cell.replace('"', "\"\""));
            }
        }
        out.push_str(&cells.join(","));
        if detailed {
            for p in ports {
                let state = if !r.ports_scanned {
                    ""
                } else if r.open_ports.contains(p) {
                    "open"
                } else {
                    "closed"
                };
                out.push(',');
                out.push_str(state);
            }
        }
        out.push('\n');
    }
    out
}

fn write_output(path: Option<String>, text: String) -> Result<String, (String, bool)> {
    match path {
        None => Ok(text),
        Some(p) => {
            std::fs::write(&p, text).map_err(|e| (format!("could not write {p}: {e}"), true))?;
            Ok(format!("saved: {p}\n"))
        }
    }
}
