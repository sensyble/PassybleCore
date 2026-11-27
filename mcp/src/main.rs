//! `passyble-mcp`: the Passyble connector for AI tools, an MCP server over stdio
//! (docs/AI_TOOLS.md). Installed beside the Passyble app; Claude Code, Codex and other MCP clients
//! start it. Only MCP messages go to stdout; diagnostics go to stderr.

use std::process::ExitCode;

use passyble_mcp::{process, serve, McpServer, PipeLink};

fn main() -> ExitCode {
    // The secrets of a command pass through its memory, as the credentials the native host relays
    // pass through the host's: no crash dumps, and (Windows, macOS) no other process of the user
    // reading it (pass_agent::harden; release builds). The commands it starts inherit "no crash
    // dumps" (the error mode on Windows, RLIMIT_CORE elsewhere), which suits processes holding
    // secrets in their environment; their memory is theirs to protect.
    pass_agent::harden::harden_process();
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--version" | "-V") => {
            println!("passyble-mcp {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!(
                "passyble-mcp {}: the Passyble connector for AI tools.\n\
                 An MCP server over stdio: add it to Claude Code, Codex or another MCP client\n\
                 (Passyble: Settings, AI tools). The Passyble app must be running.",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        Some(other) => {
            eprintln!("passyble-mcp: unknown argument {other} (try --help)");
            return ExitCode::from(2);
        }
        None => {}
    }
    let Ok(exe) = std::env::current_exe() else {
        eprintln!("passyble-mcp: can't find its own location");
        return ExitCode::FAILURE;
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    let server = McpServer::new(
        Box::new(PipeLink::beside(&exe)),
        process::client_program(),
        cwd,
    );
    let stdin = std::io::stdin();
    serve(server, stdin.lock(), std::io::stdout());
    ExitCode::SUCCESS
}
