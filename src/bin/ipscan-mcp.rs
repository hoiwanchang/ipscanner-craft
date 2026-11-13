//! Standalone MCP server binary: speaks JSON-RPC over stdio, logs to stderr.

#[tokio::main]
async fn main() {
    if let Err(e) = ipscanner_craft_lib::mcp::serve_stdio().await {
        eprintln!("ipscan-mcp exited: {e}");
        std::process::exit(1);
    }
}
