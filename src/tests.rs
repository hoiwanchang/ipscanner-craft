use crate::net::{self, Icmp, TcpOutcome};
use crate::range;
use crate::scan::{self, ScanOptions};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

fn options(ports: Vec<u16>) -> ScanOptions {
    ScanOptions {
        threads: 4,
        timeout_ms: 800,
        ping_method: "icmp-tcp".into(),
        ports,
        resolve_hostnames: true,
        scan_ports: true,
        ports_alive_only: true,
    }
}

#[test]
fn range_accepts_two_addresses() {
    let parsed = range::parse_range("192.168.0.10", "192.168.0.20").unwrap();
    assert_eq!(parsed.count(), 11);
    assert_eq!(parsed.first(), Ipv4Addr::new(192, 168, 0, 10));
    assert_eq!(parsed.last(), Ipv4Addr::new(192, 168, 0, 20));
}

#[test]
fn range_accepts_a_bare_last_octet() {
    let parsed = range::parse_range("10.0.0.5", "9").unwrap();
    assert_eq!(parsed.count(), 5);
    assert_eq!(parsed.last(), Ipv4Addr::new(10, 0, 0, 9));
}

#[test]
fn range_rejects_backwards_and_nonsense() {
    assert!(range::parse_range("10.0.0.9", "10.0.0.1").is_err());
    assert!(range::parse_range("10.0.0.1", "300").is_err());
    assert!(range::parse_range("not-an-ip", "10.0.0.1").is_err());
}

#[test]
fn cidr_covers_the_whole_block() {
    let parsed = range::parse_cidr("192.168.5.77/24").unwrap();
    assert_eq!(parsed.count(), 256);
    assert_eq!(parsed.first(), Ipv4Addr::new(192, 168, 5, 0));
    assert_eq!(parsed.last(), Ipv4Addr::new(192, 168, 5, 255));

    let single = range::parse_cidr("10.1.2.3").unwrap();
    assert_eq!(single.count(), 1);

    let wide = range::parse_cidr("10.0.0.0/8").unwrap();
    assert_eq!(wide.count(), 16_777_216);

    assert!(range::parse_cidr("10.0.0.0/33").is_err());
}

#[test]
fn icmp_reaches_loopback_without_admin_rights() {
    let mut icmp = Icmp::new();
    assert!(icmp.available(), "ICMP should be usable on this machine");
    let answer = icmp.ping(Ipv4Addr::LOCALHOST, Duration::from_millis(1500));
    assert!(answer.is_some(), "loopback did not answer ICMP");
    assert!(answer.unwrap() < 1000.0);
}

#[test]
fn tcp_sees_an_open_port() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    match net::tcp_probe(Ipv4Addr::LOCALHOST, port, Duration::from_millis(1500)) {
        TcpOutcome::Open(ms) => assert!(ms < 1500.0),
        _ => panic!("a listening port was not reported open"),
    }
}

#[test]
fn a_full_probe_fills_every_column() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let row = scan::probe_one(Ipv4Addr::LOCALHOST, &options(vec![port, 1]));
    assert!(row.alive, "loopback should be alive");
    assert_eq!(row.ip, "127.0.0.1");
    assert!(row.ports_scanned);
    assert!(row.open_ports.contains(&port));
    assert!(!row.open_ports.contains(&1));
    assert!(row.ping_ms.is_some());
    assert!(!row.method.is_empty());
}

#[test]
fn exports_write_both_formats() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let rows = vec![scan::probe_one(Ipv4Addr::LOCALHOST, &options(vec![port]))];
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");

    let csv_path = folder.join("test-export.csv");
    crate::export::write_csv(&csv_path, &rows, &[port]).unwrap();
    let csv = std::fs::read_to_string(&csv_path).unwrap();
    assert!(csv.contains("IP,Hostname,Status,Ping (ms),Method,Open ports"));
    assert!(csv.contains(&format!(",Port {port}")));
    assert!(csv.contains("127.0.0.1"));
    assert!(csv.contains(",open"));

    let json_path = folder.join("test-export.json");
    crate::export::write_json(&json_path, &rows, &[port], "127.0.0.1 - 127.0.0.1").unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
    assert_eq!(value["hostCount"], 1);
    assert_eq!(value["aliveCount"], 1);
    assert_eq!(value["hosts"][0]["ip"], "127.0.0.1");
    assert_eq!(value["hosts"][0]["openPorts"][0], port);
}

#[test]
fn csv_quotes_awkward_values() {
    let mut row = scan::probe_one(Ipv4Addr::LOCALHOST, &options(vec![]));
    row.hostname = "a,b\"c".into();
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    let path = folder.join("test-quoting.csv");
    crate::export::write_csv(&path, &[row], &[]).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"a,b\"\"c\""));
}

#[test]
fn port_compression_merges_ranges() {
    assert_eq!(crate::export::compress_ports(&[]), "");
    assert_eq!(crate::export::compress_ports(&[443, 22, 80]), "22, 80, 443");
    assert_eq!(
        crate::export::compress_ports(&[8003, 8000, 8001, 8002, 9, 65535]),
        "9, 8000-8003, 65535"
    );
}

#[test]
fn port_parsing_accepts_any_delimiter() {
    use crate::mcp::parse_port_text;
    // ASCII, spaces, semicolons
    assert_eq!(parse_port_text("80 443;22"), vec![22, 80, 443]);
    // Chinese full-width comma and enumeration comma
    assert_eq!(parse_port_text("80，443、22"), vec![22, 80, 443]);
    // arbitrary punctuation as separators
    assert_eq!(parse_port_text("80/443|22、8080"), vec![22, 80, 443, 8080]);
    // ranges with hyphen and tilde, mixed with CJK commas
    assert_eq!(parse_port_text("8000-8002，70~71"), vec![70, 71, 8000, 8001, 8002]);
    // reversed range still expands, out-of-range clamps/drops
    assert_eq!(parse_port_text("10-8"), vec![8, 9, 10]);
    assert_eq!(parse_port_text("0，70000"), Vec::<u16>::new()); // 0 invalid, 70000 unparseable as u16
    // dedup + sort
    assert_eq!(parse_port_text("443，80，443"), vec![80, 443]);
}

#[test]
fn csv_drops_per_port_columns_when_wide() {
    let wide: Vec<u16> = (1..=25).collect();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut opts = options(vec![port]);
    opts.scan_ports = true;
    let mut row = scan::probe_one(Ipv4Addr::LOCALHOST, &opts);
    row.open_ports = vec![port];
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    let path = folder.join("test-wide.csv");
    crate::export::write_csv(&path, &[row], &wide).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains(",Port 1,"),
        "wide checks must not emit per-port columns"
    );
    assert!(text.contains(&port.to_string()));
}