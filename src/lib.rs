pub mod cli;
pub mod export;
pub mod mcp;
pub mod masscan;
pub mod net;
pub mod range;
pub mod scan;

#[cfg(test)]
mod tests;

use base64::Engine;
use net::Icmp;
use range::TargetRange;
use scan::{HostResult, ScanOptions};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};

#[derive(Default)]
struct AppState {
    stop: Mutex<Option<Arc<AtomicBool>>>,
    screenshot: Mutex<Option<PathBuf>>,
}

/// Project scan policy (2026-11-13): the stock network to scan is
/// 192.168.1.0/24, the sanctioned dev-test target is a single host, and no
/// scan — ours or the agent's — may exceed 100 concurrent probes in dev,
/// so switches and NAC never get provoked into blocking us.
pub const DEFAULT_START: &str = "192.168.1.1";
pub const DEFAULT_END: &str = "192.168.1.254";
pub const DEFAULT_CIDR: &str = "192.168.1.1/24";
pub const TEST_TARGET: &str = "172.18.13.80/32";
pub const MAX_CONCURRENT_THREADS: u32 = 100;

fn sanitise(options: &mut ScanOptions) {
    options.threads = options.threads.clamp(1, MAX_CONCURRENT_THREADS);
    options.timeout_ms = options.timeout_ms.clamp(50, 30_000);
    options.ports.truncate(1024);
    if options.ping_method == "masscan" && (!masscan::available() || !masscan::driver_present()) {
        options.ping_method = "icmp-tcp".into();
    }
    if !matches!(options.ping_method.as_str(), "tcp" | "masscan") && !Icmp::new().available() {
        options.ping_method = "tcp".into();
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetInput {
    mode: String,
    start: String,
    end: String,
    cidr: String,
}

impl TargetInput {
    fn resolve(&self) -> Result<TargetRange, String> {
        match self.mode.as_str() {
            "cidr" => range::parse_cidr(&self.cidr),
            _ => range::parse_range(&self.start, &self.end),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    os: String,
    mobile: bool,
    icmp_available: bool,
    masscan_available: bool,
    masscan_driver: bool,
    default_start: String,
    default_end: String,
    default_cidr: String,
    test_target: String,
    max_threads: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RangePreview {
    ok: bool,
    count: u64,
    label: String,
    error: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartInfo {
    id: u64,
    total: u64,
    label: String,
    ping_method: String,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        mobile: cfg!(any(target_os = "android", target_os = "ios")),
        icmp_available: Icmp::new().available(),
        masscan_available: masscan::available(),
        masscan_driver: masscan::driver_present(),
        default_start: DEFAULT_START.to_string(),
        default_end: DEFAULT_END.to_string(),
        default_cidr: DEFAULT_CIDR.to_string(),
        test_target: TEST_TARGET.to_string(),
        max_threads: MAX_CONCURRENT_THREADS,
    }
}

#[tauri::command]
fn preview_range(target: TargetInput) -> RangePreview {
    match target.resolve() {
        Ok(resolved) => RangePreview {
            ok: true,
            count: resolved.count(),
            label: resolved.label,
            error: String::new(),
        },
        Err(error) => RangePreview {
            ok: false,
            count: 0,
            label: String::new(),
            error,
        },
    }
}

#[tauri::command]
fn start_scan(
    app: AppHandle,
    state: State<AppState>,
    id: u64,
    target: TargetInput,
    mut options: ScanOptions,
) -> Result<StartInfo, String> {
    let resolved = target.resolve()?;
    sanitise(&mut options);

    if let Some(previous) = state.stop.lock().unwrap().take() {
        previous.store(true, Ordering::Relaxed);
    }
    let stop = Arc::new(AtomicBool::new(false));
    *state.stop.lock().unwrap() = Some(Arc::clone(&stop));

    let info = StartInfo {
        id,
        total: resolved.count(),
        label: resolved.label.clone(),
        ping_method: options.ping_method.clone(),
    };
    scan::spawn(app, id, options, resolved, stop);
    Ok(info)
}

#[tauri::command]
async fn rescan_host(ip: String, mut options: ScanOptions) -> Result<HostResult, String> {
    let address: Ipv4Addr = ip.parse().map_err(|_| format!("\"{ip}\" is not an IPv4 address"))?;
    sanitise(&mut options);
    tauri::async_runtime::spawn_blocking(move || scan::probe_one(address, &options))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_scan(state: State<AppState>) {
    if let Some(stop) = state.stop.lock().unwrap().as_ref() {
        stop.store(true, Ordering::Relaxed);
    }
}

#[tauri::command]
fn export_results(
    path: String,
    format: String,
    rows: Vec<HostResult>,
    ports: Vec<u16>,
    range: String,
) -> Result<String, String> {
    let destination = PathBuf::from(&path);
    if let Some(parent) = destination.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Could not create the folder: {e}"))?;
        }
    }
    match format.as_str() {
        "json" => export::write_json(&destination, &rows, &ports, &range)?,
        _ => export::write_csv(&destination, &rows, &ports)?,
    }
    Ok(destination.to_string_lossy().to_string())
}

fn is_safe_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !host.contains("..")
        && !host.starts_with(['-', '.'])
        && !host.ends_with(['-', '.'])
}

#[tauri::command]
fn open_in_browser(host: String, port: u16, https: bool) -> Result<(), String> {
    if !is_safe_host(&host) {
        return Err("That host name cannot be opened in a browser".into());
    }
    let scheme = if https { "https" } else { "http" };
    let default_port = (https && port == 443) || (!https && port == 80);
    let url = if default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };

    #[cfg(windows)]
    let result = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", &url])
        .spawn();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
    let result = std::process::Command::new("xdg-open").arg(&url).spawn();
    #[cfg(target_os = "android")]
    let result: Result<std::process::Child, std::io::Error> =
        Err(std::io::Error::other("Opening a browser is not available on this device"));

    result.map(|_| ()).map_err(|e| format!("Could not open the browser: {e}"))
}

#[tauri::command]
fn screenshot_target(state: State<AppState>) -> Option<String> {
    state
        .screenshot
        .lock()
        .unwrap()
        .as_ref()
        .map(|path| path.to_string_lossy().to_string())
}

#[tauri::command]
fn save_screenshot(app: AppHandle, state: State<AppState>, data: String) -> Result<(), String> {
    let path = state
        .screenshot
        .lock()
        .unwrap()
        .clone()
        .ok_or("No screenshot was requested")?;
    let payload = data.split_once(',').map(|(_, rest)| rest).unwrap_or(&data);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .map_err(|e| format!("The picture data was unreadable: {e}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    std::fs::write(&path, &bytes).map_err(|e| format!("Could not save the picture: {e}"))?;
    *state.screenshot.lock().unwrap() = None;
    app.exit(0);
    Ok(())
}

fn screenshot_argument() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--screenshot" {
            return args.next().map(PathBuf::from);
        }
        if let Some(value) = arg.strip_prefix("--screenshot=") {
            return Some(PathBuf::from(value));
        }
    }
    None
}

/// Occluded Chromium windows stop painting; these flags keep the picture coming
/// while the window sits behind everything else during a check.
#[cfg(windows)]
fn keep_painting_while_hidden() {
    let extra = "--disable-features=CalculateNativeWinOcclusion --disable-backgrounding-occluded-windows --disable-renderer-backgrounding --disable-background-timer-throttling";
    let existing = std::env::var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").unwrap_or_default();
    std::env::set_var(
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
        format!("{existing} {extra}").trim().to_string(),
    );
}

/// Where the portable WebView2 profile lives: <exe dir>\data. Created lazily
/// by the WebView2 loader; we only compute and prepare the path here.
#[cfg(windows)]
fn portable_data_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.join("data");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let screenshot = screenshot_argument();
    let headless_check = screenshot.is_some();
    #[cfg(windows)]
    if headless_check {
        keep_painting_while_hidden();
    }

    // Portable mode: keep the WebView2 profile (and therefore the frontend's
    // localStorage settings) beside the exe in .\data, not in %LOCALAPPDATA%,
    // so copying the folder to another machine carries the user's settings.
    // Opt out by setting IPSCAN_NO_PORTABLE=1.
    #[cfg(windows)]
    let portable_dir: Option<PathBuf> = if std::env::var_os("IPSCAN_NO_PORTABLE").is_some() {
        None
    } else {
        portable_data_dir()
    };

    let state = AppState {
        screenshot: Mutex::new(screenshot),
        ..AppState::default()
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(move |app| {
            let mut window = tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("ipscanner-craft")
            .inner_size(1120.0, 720.0)
            .min_inner_size(760.0, 480.0);
            #[cfg(windows)]
            if let Some(dir) = portable_dir.clone() {
                window = window.data_directory(dir);
            }
            if headless_check {
                #[cfg(desktop)]
                {
                    window = window.focused(false);
                }
                #[cfg(windows)]
                {
                    window = window.always_on_bottom(true);
                }
            }
            window.build()?;

            if headless_check {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(40));
                    let pending = handle
                        .state::<AppState>()
                        .screenshot
                        .lock()
                        .unwrap()
                        .clone();
                    if pending.is_some() {
                        eprintln!("screenshot was not produced in time");
                        handle.exit(1);
                    }
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            preview_range,
            start_scan,
            stop_scan,
            rescan_host,
            export_results,
            open_in_browser,
            screenshot_target,
            save_screenshot
        ])
        .run(tauri::generate_context!())
        .expect("could not start the scanner");
}