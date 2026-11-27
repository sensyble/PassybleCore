# passyble-mcp

The Passyble connector for AI tools: an MCP server over stdio that Claude Code, Codex, Claude Desktop and other MCP
clients start. It offers `run_with_secret` (run a command with secrets from shared items in environment variables;
output masked), `list_items` (the shared items, no values) and `reveal_secret` (one value, approved every time). It
holds no secrets between calls and asks the desktop app's agent for everything over the agent's pipe or socket
(`ai.*`, docs/PROTOCOL.md §2). User guide and design: [docs/AI_TOOLS.md](../docs/AI_TOOLS.md).

* Installed beside `Pass.exe` (Windows) or `/usr/bin/Pass` (Linux .deb, .rpm) as a Tauri `externalBin`, built by
  `Windows/installer/build-native-host.ps1` and `Linux/installer/before-bundle.sh` with the native host.
* The agent accepts it only from that place and only for `ai.*` (`ipc::Server::start_restricted_with_ai`); it talks
  only to a pipe served by the `Pass.exe` beside it (`ipc::server_is_allowed`).
* stdout carries MCP messages only; diagnostics go to stderr. `--version` and `--help` print and exit.

Tests: `cargo test -p passyble-mcp` (masking, `PATH` lookup, JSON-RPC, and `tests/e2e.rs`: the MCP server against a
test agent with a fake `Ui` over a pipe of its own, running this test binary as the command; plus the real binary
over stdio). The tests never touch a running Passyble: they rename the pipe (`USERNAME`, `XDG_RUNTIME_DIR`).
