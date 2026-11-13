//! Headless CLI entry point: ipscan-cli scan <target> [options]

use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    ipscanner_craft_lib::cli::dispatch(&argv)
}
