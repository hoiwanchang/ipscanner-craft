use crate::scan::HostResult;
use std::io::Write;
use std::path::Path;

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// "80 443 8000 8001 8002" -> "80, 443, 8000-8002" for dense exports.
pub fn compress_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    let mut groups: Vec<String> = Vec::new();
    let (mut start, mut prev) = (sorted[0], sorted[0]);
    for &p in &sorted[1..] {
        if p == prev.saturating_add(1) {
            prev = p;
            continue;
        }
        groups.push(if start == prev { start.to_string() } else { format!("{start}-{prev}") });
        start = p;
        prev = p;
    }
    groups.push(if start == prev { start.to_string() } else { format!("{start}-{prev}") });
    groups.join(", ")
}

/// One column per checked port only while the list stays short; wider checks
/// collapse into the single compressed "Open ports" view. Kept in sync with
/// SUMMARY_COLUMN_THRESHOLD on the frontend.
pub const PER_PORT_COLUMN_MAX: usize = 8;

fn per_port_columns(ports: &[u16]) -> bool {
    ports.len() <= PER_PORT_COLUMN_MAX
}

pub fn write_csv(path: &Path, rows: &[HostResult], ports: &[u16]) -> Result<(), String> {
    let detailed = per_port_columns(ports);
    let mut out = String::from("\u{feff}IP,Hostname,Status,Ping (ms),Method,Open ports");
    if detailed {
        for port in ports {
            out.push_str(&format!(",Port {port}"));
        }
    }
    out.push('\n');

    for row in rows {
        let ping = row
            .ping_ms
            .map(|ms| format!("{ms:.1}"))
            .unwrap_or_default();
        let open = if detailed {
            row.open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            compress_ports(&row.open_ports)
        };
        let cells = [
            row.ip.clone(),
            row.hostname.clone(),
            if row.alive { "alive" } else { "dead" }.to_string(),
            ping,
            row.method.clone(),
            open,
        ];
        out.push_str(
            &cells
                .iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        if detailed {
            for port in ports {
                let state = if !row.ports_scanned {
                    ""
                } else if row.open_ports.contains(port) {
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

    let file = std::fs::File::create(path).map_err(|e| format!("Could not create the file: {e}"))?;
    let mut writer = std::io::BufWriter::new(file);
    writer
        .write_all(out.as_bytes())
        .map_err(|e| format!("Could not write the file: {e}"))?;
    writer.flush().map_err(|e| format!("Could not finish the file: {e}"))?;
    Ok(())
}

pub fn write_json(
    path: &Path,
    rows: &[HostResult],
    ports: &[u16],
    range: &str,
) -> Result<(), String> {
    let document = serde_json::json!({
        "generator": "ipscanner-craft 1.0.0",
        "range": range,
        "scannedPorts": ports,
        "hostCount": rows.len(),
        "aliveCount": rows.iter().filter(|r| r.alive).count(),
        "hosts": rows,
    });
    let text = serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("Could not write the file: {e}"))
}