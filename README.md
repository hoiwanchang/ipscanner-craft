# ipscanner-craft

Fast, portable IPv4 network scanner — **GUI + CLI + MCP server** in one codebase, built with Tauri 2 + Rust.

Think Angry IP Scanner, plus a scriptable CLI, an AI-ready MCP server, optional [masscan](https://github.com/robertdavidgraham/masscan)-powered SYN blasts, and a truly portable build (settings travel with the folder).

## Features

- **Three frontends, one engine**
  - 🖥️ Desktop GUI (range / CIDR input, live result table, sorting, filtering, detail view, CSV/JSON export)
  - ⌨️ Headless CLI (`ipscanner-craft-cli`) with `text | csv | json` output — pipe-friendly, exit codes, `--out`
  - 🤖 MCP server (`ipscanner-craft-mcp`, stdio) — let AI agents scan your network via `scan_network` / `probe_host` / `local_info` / `list_adapters`
- **Flexible host discovery**: ICMP ping, TCP SYN-style fallback, combined mode, or raw-socket masscan (optional, via Npcap on Windows)
- **Parallel port checks** with wave scheduling — port ranges like `8000-8100` (up to 1024 ports) finish in ~1 timeout, not N
- **Smart result display**: per-port columns for small checks; an aggregated `Opening Ports` column with compressed ranges (`22, 80, 8000-8003`) for wide ones
- **Any delimiter for port lists** — digits only matter, so `22，80、443/8080` with Chinese punctuation parses fine; no IME switching needed
- **Reverse DNS**, hostname display, progress events, stop/resume, host rescan
- **Portable**: WebView2 profile and all settings live in `.\data` beside the exe — copy the folder anywhere
- **Safe by design**: hard concurrency cap (100), per-run host cap, stock default target `192.168.1.1/24`

## Download

Grab a build from the [Releases page](https://github.com/hoiwanchang/ipscanner-craft/releases):

| Platform | Artifacts |
|---|---|
| Windows x64 | `ipscanner-craft_*_x64_zh-CN.msi` installer · `ipscanner-craft-portable-win64.zip` (GUI + CLI + MCP, no install) |
| Linux x64 | `.deb`, `.rpm`, `.AppImage` |
| macOS (Apple silicon + Intel) | universal `.dmg` / `.app` |
| Android (arm64 / armv7 / x86_64) | `app-*-release-unsigned.apk` (sideload; see below) |
| Any OS | standalone `ipscanner-craft-cli-<target>` / `ipscanner-craft-mcp-<target>` binaries |

**Android APKs are unsigned** (debug key) — fine for adb/sideload on your own devices. Play Store needs a signed AAB; add keystore secrets and switch the workflow to `--aab`.

> **macOS**: the build is unsigned — first launch needs right-click → Open, or `xattr -d com.apple.quarantine ipscanner-craft.app`.

## CLI

```bash
ipscanner-craft-cli 192.168.1.1-254                       # scan the stock /24
ipscanner-craft-cli 10.0.0.5                                # single host
ipscanner-craft-cli 192.168.1.0/24 --tcp-ports 22,80,443,8000-8100 --format json --out scan.json
ipscanner-craft-cli 192.168.1.1-254 --alive-only --no-hostnames --threads 100 --format csv
```

| Option | Meaning | Default |
|---|---|---|
| `--tcp-ports SPEC` | ports/ranges; any non-digit splits, `-`/`~` join ranges; `none` disables | `80,443,22` |
| `--method M` | `icmp-tcp` \| `icmp` \| `tcp` \| `masscan` | `icmp-tcp` |
| `--threads N` | concurrent workers (hard cap 100) | 50 |
| `--timeout MS` | per-probe timeout | 1000 |
| `--format F` | `text` \| `csv` \| `json` | text |
| `--out PATH` | write to file instead of stdout | — |
| `--alive-only` | live hosts only | off |
| `--no-hostnames` | skip reverse DNS | off |
| `--max-hosts N` | safety cap | 4096 |

Exit codes: `0` success (incl. `--help`/`--version`), `1` on error.

## MCP (AI agents)

```json
{
  "mcpServers": {
    "ipscanner-craft": {
      "command": "/path/to/ipscanner-craft-mcp"
    }
  }
}
```

Tools: `scan_network` (CIDR/range scan, ports, hostnames), `probe_host` (single IP), `local_info` (your subnet + policy). `local_info.policy` advertises the scan guardrails; requests above the cap are clamped, never rejected mid-scan.

## masscan mode (optional)

The raw-socket mode shells out to a bundled [masscan](https://github.com/robertdavidgraham/masscan) (GPLv2 — kept out-of-process on purpose, so this project stays Apache-2.0).

- **Windows**: install [Npcap](https://npcap.com) (tick *WinPcap API-compatible Mode*) and run as Administrator; put `masscan.exe` next to the app or set `IPSCAN_MASSCAN`.
- **Linux/macOS**: `masscan` on PATH; root or `CAP_NET_RAW` required.
- Missing any prerequisite? The scanner silently falls back to the built-in ICMP/TCP engine and the GUI greys the option out.

⚠️ **Network etiquette**: high-rate SYN blasts trip NAC/port-security on managed campus or corporate Wi-Fi (ask me how I know). Scan networks you own or are allowed to test, keep `--threads` modest, and avoid masscan rates on shared infrastructure.

## Development

```bash
# prerequisites: Rust 1.88+, Node 20+, Tauri 2 system deps
cd frontend && npm install
npm run dev               # GUI with hot reload
cargo test --lib          # engine unit tests

# release builds
npm run build                                  # frontend bundle
cargo build --release --bins                   # CLI + MCP
npx @tauri-apps/cli build                      # desktop installers
```

Layout: `src/scan.rs` engine · `src/net.rs` raw ICMP/TCP probes · `src/range.rs` parser · `src/masscan.rs` process bridge · `src/cli.rs` CLI · `src/mcp.rs` MCP server · `src/export.rs` CSV/JSON · `frontend/` Vue 3 + TS.

## Credits & license

Inspired by the classic [Angry IP Scanner](https://angryip.org/). Licensed under Apache-2.0. The optional masscan bridge runs a separate GPLv2 binary out of process and does not link or copy its code.
