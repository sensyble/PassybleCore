//! `passyble-mcp`: the Passyble connector for AI tools (docs/AI_TOOLS.md). An MCP server over
//! stdio that Claude Code, Codex, Claude Desktop or any other MCP client starts. It offers three
//! tools and asks the Passyble desktop app (the agent, over its pipe or socket) for everything:
//!
//! * `list_items`: the items the user marked "Available to AI tools" (no secrets).
//! * `run_with_secret`: runs a command with secrets in environment variables after the user
//!   approved it in the app, and returns its output with every secret value concealed
//!   ([`mask`]). The AI never sees the values. The way to use a secret.
//! * `reveal_secret`: returns one value to the AI, which the user must approve every time.
//!
//! JSON-RPC 2.0 is hand-rolled (MCP needs `initialize`, `ping`, `tools/list`, `tools/call` and
//! the `notifications/cancelled` notification), so the connector pulls in no MCP framework.

pub mod mask;
pub mod process;
pub mod run;

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// The server's name in `initialize` (and the name the setup instructions register it under).
pub const SERVER_NAME: &str = "passyble";
/// MCP protocol versions this server speaks, newest first. A client asking for another one gets
/// the newest.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Bytes of each output stream returned to the AI (after concealing).
pub const OUTPUT_CAP: usize = 100_000;
/// A command's time limit when the AI names none, and the longest it may ask for (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
pub const MAX_TIMEOUT_SECS: u64 = 600;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const INSTRUCTIONS: &str = "Passyble is the user's password manager. Call list_items to see the items the user shared \
with AI tools, and run_with_secret to run a command with their secrets in environment variables: you never see the \
values, and secret values in the output are concealed. Use reveal_secret only when the user explicitly asks to see a \
value. The user approves uses in the Passyble app, which shows them the exact command.";

/// An error from the agent (its `error.code` and `error.message`), or `agent_unavailable` when
/// it can't be reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentError {
    pub code: String,
    pub message: String,
}

impl AgentError {
    pub fn unavailable(message: impl Into<String>) -> AgentError {
        AgentError {
            code: "agent_unavailable".into(),
            message: message.into(),
        }
    }
}

/// How the connector reaches the agent: one request, one answer.
pub trait AgentLink: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, AgentError>;
}

/// One request over a fresh connection to the agent (one JSON object per line), and its answer.
/// The answer may carry secrets: the line read is cleared from memory once parsed.
pub fn call_over<S: Read + Write>(
    stream: &mut S,
    method: &str,
    params: Value,
) -> Result<Value, AgentError> {
    let request = json!({ "id": 1, "method": method, "params": params }).to_string();
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .and_then(|_| stream.flush())
        .map_err(|e| AgentError::unavailable(format!("lost the connection to Passyble: {e}")))?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = Zeroizing::new(String::new());
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => {
                return Err(AgentError::unavailable(
                    "Passyble closed the connection without answering",
                ))
            }
            Ok(_) => {}
        }
        let Ok(mut reply) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if reply.get("id") != Some(&json!(1)) {
            continue;
        }
        if let Some(error) = reply.get("error") {
            return Err(AgentError {
                code: error["code"].as_str().unwrap_or("internal").to_string(),
                message: error["message"].as_str().unwrap_or_default().to_string(),
            });
        }
        return Ok(reply
            .get_mut("result")
            .map(Value::take)
            .unwrap_or(Value::Null));
    }
}

/// The real link: the agent's pipe or socket, but only when the process serving it runs one of
/// `allowed_servers` (the Passyble app installed beside this connector), checked like the native
/// host checks it (`pass_agent::ipc::server_is_allowed`). Another program that created the pipe
/// first gets nothing (and the connector never sends it a secret anyway: secrets only travel
/// from the agent to the connector).
pub struct PipeLink {
    allowed_servers: Vec<PathBuf>,
}

impl PipeLink {
    pub fn new(allowed_servers: Vec<PathBuf>) -> PipeLink {
        PipeLink { allowed_servers }
    }

    /// The Passyble app beside `exe` (`Pass.exe` on Windows, `Pass` elsewhere).
    pub fn beside(exe: &Path) -> PipeLink {
        let app = if cfg!(windows) { "Pass.exe" } else { "Pass" };
        PipeLink::new(vec![exe.with_file_name(app)])
    }
}

impl AgentLink for PipeLink {
    fn call(&self, method: &str, params: Value) -> Result<Value, AgentError> {
        let mut stream = pass_agent::ipc::connect()
            .map_err(|_| AgentError::unavailable("Passyble isn't running"))?;
        if !pass_agent::ipc::server_is_allowed(&stream, &self.allowed_servers) {
            return Err(AgentError::unavailable(
                "the Passyble pipe is held by another program, not by the Passyble app installed beside this connector",
            ));
        }
        call_over(&mut stream, method, params)
    }
}

/// What a tool call answers: text for the AI, and whether it is an error.
struct ToolResult {
    text: String,
    is_error: bool,
}

impl ToolResult {
    fn ok(text: impl Into<String>) -> ToolResult {
        ToolResult {
            text: text.into(),
            is_error: false,
        }
    }

    fn error(text: impl Into<String>) -> ToolResult {
        ToolResult {
            text: text.into(),
            is_error: true,
        }
    }
}

/// An agent error as the AI reads it.
fn agent_error_text(e: &AgentError) -> String {
    match e.code.as_str() {
        "agent_unavailable" => format!(
            "Passyble isn't reachable ({}). Ask the user to open the Passyble desktop app, then try again.",
            e.message
        ),
        "cancelled" => format!("Denied. {}", e.message),
        "not_supported" => format!("{} Ask the user to update Passyble.", e.message),
        "locked" | "not_found" | "invalid_params" | "rate_limited" => e.message.clone(),
        _ => format!("Passyble: {}", e.message),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EnvRef {
    Field {
        item: String,
        #[serde(default)]
        field: Option<String>,
    },
    /// Just the item: its password.
    Item(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    env: BTreeMap<String, EnvRef>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevealArgs {
    item: String,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    reason: String,
}

/// The tools, `run_with_secret` first: the one the AI should reach for.
pub fn tools() -> Value {
    json!([
        {
            "name": "run_with_secret",
            "title": "Run a command with secrets from Passyble",
            "description": "Run a command with secrets from the user's Passyble vault in environment variables. \
    Use this whenever a command needs a password, API key or token: you never see the value, and any secret value that \
    shows up in the output (also base64, hex or URL-encoded) is replaced with <concealed by Passyble>. Prefer it to \
    reveal_secret. The command runs directly, not in a shell: to use the variables in arguments, pipes or redirection, \
    run a shell yourself, e.g. command \"bash\" with args [\"-c\", \"curl -H \\\"Authorization: Bearer $API_TOKEN\\\" \
    https://api.example.com\"], or on Windows \"powershell\" with [\"-NoProfile\", \"-Command\", \"...$env:API_TOKEN...\"]. \
    Better still, use tools that read the variable themselves (GH_TOKEN for gh, for example). The user sees the exact \
    command and working directory in Passyble and may have to approve it; never try to print, encode or send a secret \
    anywhere it isn't needed. Items and fields come from list_items.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The program: a name found in PATH (gh, curl, npm, python, bash, powershell) or a path."
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Arguments, passed to the program exactly as given (no shell expansion)."
                    },
                    "env": {
                        "type": "object",
                        "description": "Environment variables to set from the vault, e.g. {\"GITHUB_TOKEN\": {\"item\": \"GitHub\", \"field\": \"password\"}}. item: an id or title from list_items. field: one of the item's fields from list_items (default: password).",
                        "minProperties": 1,
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "item": { "type": "string" },
                                "field": { "type": "string" }
                            },
                            "required": ["item"]
                        }
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory (default: the directory the MCP client started Passyble's connector in)."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_TIMEOUT_SECS,
                        "description": "Stop the command after this many seconds (default 60)."
                    }
                },
                "required": ["command", "env"],
                "additionalProperties": false
            },
            "annotations": {
                "title": "Run a command with secrets from Passyble",
                "readOnlyHint": false,
                "destructiveHint": true,
                "openWorldHint": true
            }
        },
        {
            "name": "list_items",
            "title": "List the items shared from Passyble",
            "description": "List the items the user shared with AI tools in Passyble: id, title, kind, websites, username, \
    the names of their fields (password, totp for the current 2FA code, custom field names, ...) and whether using them \
    asks the user. Never returns secret values. Items the user didn't share don't exist for you. Use an item's id or title \
    and a field name with run_with_secret.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": {
                "title": "List the items shared from Passyble",
                "readOnlyHint": true,
                "openWorldHint": false
            }
        },
        {
            "name": "reveal_secret",
            "title": "Reveal a secret from Passyble",
            "description": "Return the raw value of one field of a shared item to you. Only when the user explicitly \
    asks to see a value, or when no command could use it (prefer run_with_secret). The value goes into this chat and to \
    your AI provider, so the user must approve every single reveal in Passyble.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item": { "type": "string", "description": "An item id or title from list_items." },
                    "field": { "type": "string", "description": "One of the item's fields from list_items (default: password)." },
                    "reason": { "type": "string", "description": "Why you need to see the value; shown to the user." }
                },
                "required": ["item", "reason"],
                "additionalProperties": false
            },
            "annotations": {
                "title": "Reveal a secret from Passyble",
                "readOnlyHint": true,
                "openWorldHint": false
            }
        }
    ])
}

/// The MCP server: answers JSON-RPC messages ([`McpServer::handle_message`]); [`serve`] runs it
/// over stdio.
pub struct McpServer {
    link: Box<dyn AgentLink>,
    /// The program that started the connector ([`process::client_program`]).
    process: String,
    /// The working directory commands run in when the AI names none.
    default_cwd: PathBuf,
    /// `clientInfo` from `initialize`.
    client: Mutex<Value>,
    /// Cancel flags of the tool calls in progress, by JSON-RPC id.
    running: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

impl McpServer {
    pub fn new(link: Box<dyn AgentLink>, process: String, default_cwd: PathBuf) -> Arc<McpServer> {
        Arc::new(McpServer {
            link,
            process,
            default_cwd,
            client: Mutex::new(json!({})),
            running: Mutex::default(),
        })
    }

    /// The client as the agent's prompts and log name it.
    fn client(&self) -> Value {
        let info = self
            .client
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let text = |k: &str| {
            info.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        json!({
            "name": text("name"),
            "title": text("title"),
            "version": text("version"),
            "process": self.process,
        })
    }

    /// One line from the client: a message or a batch. `None`: nothing to answer (notifications,
    /// responses).
    pub fn handle_line(&self, line: &str) -> Option<String> {
        let message: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    rpc_error(Value::Null, -32700, format!("parse error: {e}")).to_string(),
                )
            }
        };
        match message {
            Value::Array(batch) => {
                if batch.is_empty() {
                    return Some(rpc_error(Value::Null, -32600, "empty batch").to_string());
                }
                let replies: Vec<Value> = batch
                    .iter()
                    .filter_map(|m| self.handle_message(m))
                    .collect();
                (!replies.is_empty()).then(|| Value::Array(replies).to_string())
            }
            m => self.handle_message(&m).map(|r| r.to_string()),
        }
    }

    /// One JSON-RPC message; `None` for notifications and responses.
    pub fn handle_message(&self, message: &Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(rpc_error(Value::Null, -32600, "not a JSON-RPC message"));
        };
        let id = object.get("id").cloned().filter(|id| !id.is_null());
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            // A response to a request of ours (we send none) or garbage with an id.
            return id.map(|id| rpc_error(id, -32600, "no method"));
        };
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        let Some(id) = id else {
            if method == "notifications/cancelled" {
                if let Some(request) = params.get("requestId") {
                    self.cancel(request);
                }
            }
            return None;
        };
        Some(match method {
            "initialize" => {
                if let Some(info) = params.get("clientInfo").filter(|i| i.is_object()) {
                    *self.client.lock().unwrap_or_else(|p| p.into_inner()) = info.clone();
                }
                let asked = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let version = PROTOCOL_VERSIONS
                    .iter()
                    .find(|v| **v == asked)
                    .unwrap_or(&PROTOCOL_VERSIONS[0]);
                rpc_result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": { "tools": { "listChanged": false } },
                        "serverInfo": { "name": SERVER_NAME, "title": "Passyble", "version": VERSION },
                        "instructions": INSTRUCTIONS,
                    }),
                )
            }
            "ping" => rpc_result(id, json!({})),
            "tools/list" => rpc_result(id, json!({ "tools": tools() })),
            "tools/call" => self.call_tool(id, &params),
            other => rpc_error(id, -32601, format!("method not found: {other}")),
        })
    }

    fn cancel(&self, request: &Value) {
        if let Some(flag) = self
            .running
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&request.to_string())
        {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn call_tool(&self, id: Value, params: &Value) -> Value {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let key = id.to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        self.running
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key.clone(), cancel.clone());
        let result = match name {
            "list_items" => Some(self.list_items()),
            "run_with_secret" => Some(self.run_with_secret(arguments, &cancel)),
            "reveal_secret" => Some(self.reveal_secret(arguments)),
            _ => None,
        };
        self.running
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
        match result {
            Some(r) => rpc_result(
                id,
                json!({ "content": [{ "type": "text", "text": r.text }], "isError": r.is_error }),
            ),
            None => rpc_error(id, -32602, format!("unknown tool: {name}")),
        }
    }

    fn list_items(&self) -> ToolResult {
        match self
            .link
            .call("ai.list", json!({ "client": self.client() }))
        {
            Err(e) => ToolResult::error(agent_error_text(&e)),
            Ok(result) => {
                let items = result.get("items").cloned().unwrap_or_else(|| json!([]));
                if items.as_array().is_none_or(Vec::is_empty) {
                    return ToolResult::ok(
                        "The user hasn't shared any items with AI tools. In Passyble they can turn on \
\"Available to AI tools\" in an item's editor.",
                    );
                }
                ToolResult::ok(
                    serde_json::to_string_pretty(&json!({ "items": items })).unwrap_or_default(),
                )
            }
        }
    }

    fn reveal_secret(&self, arguments: Value) -> ToolResult {
        let args: RevealArgs = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::error(format!("Invalid arguments: {e}")),
        };
        let params = json!({
            "client": self.client(),
            "item": args.item,
            "field": args.field.unwrap_or_else(|| "password".into()),
            "reason": args.reason,
        });
        match self.link.call("ai.reveal", params) {
            Err(e) => ToolResult::error(agent_error_text(&e)),
            Ok(mut result) => {
                let field = result["field"].as_str().unwrap_or("value").to_string();
                let value = Zeroizing::new(match result.get_mut("value").map(Value::take) {
                    Some(Value::String(s)) => s,
                    _ => String::new(),
                });
                ToolResult::ok(format!(
                    "The user approved showing you \"{field}\" of {}. Don't repeat it unless needed:\n{}",
                    args.item,
                    value.as_str()
                ))
            }
        }
    }

    fn run_with_secret(&self, arguments: Value, cancel: &AtomicBool) -> ToolResult {
        let args: RunArgs = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::error(format!("Invalid arguments: {e}")),
        };
        if args.env.is_empty() {
            return ToolResult::error(
                "env is empty: name at least one environment variable and the item (and field) it gets.",
            );
        }
        let cwd = match &args.cwd {
            Some(dir) if !dir.trim().is_empty() => self.default_cwd.join(dir.trim()),
            _ => self.default_cwd.clone(),
        };
        if !cwd.is_dir() {
            return ToolResult::error(format!(
                "The working directory {} doesn't exist.",
                cwd.display()
            ));
        }
        let cwd = process::display_path(&cwd);
        let Some(program) = process::resolve_program(&args.command, &cwd) else {
            return ToolResult::error(format!(
                "Command not found: {}. Give a program in PATH or a path to it (the working directory isn't searched).",
                args.command
            ));
        };
        let program = process::display_path(&program);
        let timeout_secs = args
            .timeout_secs
            .unwrap_or(DEFAULT_TIMEOUT_SECS)
            .clamp(1, MAX_TIMEOUT_SECS);
        let env: Vec<Value> = args
            .env
            .iter()
            .map(|(name, r)| {
                let (item, field) = match r {
                    EnvRef::Field { item, field } => (item.clone(), field.clone()),
                    EnvRef::Item(item) => (item.clone(), None),
                };
                json!({ "name": name, "item": item, "field": field.unwrap_or_else(|| "password".into()) })
            })
            .collect();
        let params = json!({
            "client": self.client(),
            "env": env,
            "command": args.command,
            "program": program.to_string_lossy(),
            "args": args.args,
            "cwd": cwd.to_string_lossy(),
            "timeout_secs": timeout_secs,
        });
        let mut approved = match self.link.call("ai.run", params) {
            Ok(r) => r,
            Err(e) => return ToolResult::error(agent_error_text(&e)),
        };
        let request = approved["request"].as_u64().unwrap_or(0);
        let timeout_secs = approved["timeout_secs"].as_u64().unwrap_or(timeout_secs);
        let mut values: Vec<(String, Zeroizing<String>)> = Vec::new();
        if let Some(Value::Object(map)) = approved.get_mut("env").map(Value::take) {
            for (name, value) in map {
                if let Value::String(s) = value {
                    values.push((name, Zeroizing::new(s)));
                }
            }
        }
        drop(approved);
        let masker = mask::Masker::new(&values.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>());
        let spec = run::RunSpec {
            program: program.clone(),
            args: args.args,
            cwd,
            env: values,
            timeout: Duration::from_secs(timeout_secs),
            keep: OUTPUT_CAP + masker.longest(),
        };
        let done = |outcome: &str, exit_code: Option<i32>| {
            let _ = self.link.call(
                "ai.run_done",
                json!({ "request": request, "outcome": outcome, "exit_code": exit_code }),
            );
        };
        let output = match run::run(spec, cancel) {
            Ok(o) => o,
            Err(e) => {
                done("failed", None);
                return ToolResult::error(format!("Could not start {}: {e}", program.display()));
            }
        };
        let (outcome, code) = match output.ending {
            run::Ending::Exited(code) => ("finished", code),
            run::Ending::TimedOut => ("timed_out", None),
            run::Ending::Cancelled => ("cancelled", None),
        };
        done(outcome, code);
        format_output(&masker, &output, timeout_secs)
    }
}

/// The text for the AI: how it ended, then stdout and stderr, concealed and capped.
fn format_output(masker: &mask::Masker, output: &run::RunOutput, timeout_secs: u64) -> ToolResult {
    let secs = output.elapsed.as_secs_f64();
    let (head, is_error) = match output.ending {
        run::Ending::Exited(Some(code)) => (format!("Exit code {code} ({secs:.1} s)."), code != 0),
        run::Ending::Exited(None) => (format!("Ended by a signal ({secs:.1} s)."), true),
        run::Ending::TimedOut => (
            format!("Stopped after the {timeout_secs} s time limit."),
            true,
        ),
        run::Ending::Cancelled => ("Cancelled.".to_string(), true),
    };
    let mut text = head;
    let mut concealed = false;
    for (name, data, total) in [
        ("stdout", &output.stdout, output.stdout_total),
        ("stderr", &output.stderr, output.stderr_total),
    ] {
        if total == 0 {
            continue;
        }
        let masked = Zeroizing::new(masker.mask(data));
        concealed |= masked.len() != data.len() || masked.as_slice() != data.as_slice();
        let shown = &masked[..masked.len().min(OUTPUT_CAP)];
        text.push_str(&format!("\n{name}:\n{}", String::from_utf8_lossy(shown)));
        if total > shown.len() && total > OUTPUT_CAP {
            text.push_str(&format!(
                "\n[{name} truncated: showing the first {} of {total} bytes]",
                shown.len()
            ));
        }
    }
    if output.stdout_total == 0 && output.stderr_total == 0 {
        text.push_str("\n(no output)");
    }
    if concealed {
        text.push_str(&format!(
            "\nValues from Passyble in the output are shown as {}.",
            mask::MASK
        ));
    }
    ToolResult { text, is_error }
}

/// Runs `server` over a line-based transport (stdio): each `tools/call` on its own thread, so a
/// long command or a pending approval doesn't hold up `ping` or a cancellation. Returns when the
/// input ends.
pub fn serve<R: BufRead, W: Write + Send + 'static>(server: Arc<McpServer>, input: R, output: W) {
    let output = Arc::new(Mutex::new(output));
    let write = |output: &Arc<Mutex<W>>, line: String| {
        let mut out = output.lock().unwrap_or_else(|p| p.into_inner());
        let _ = out
            .write_all(line.as_bytes())
            .and_then(|_| out.write_all(b"\n"))
            .and_then(|_| out.flush());
    };
    let mut workers = Vec::new();
    for line in input.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let is_call = serde_json::from_str::<Value>(&line)
            .ok()
            .is_some_and(|m| m.get("method").and_then(Value::as_str) == Some("tools/call"));
        if is_call {
            let server = server.clone();
            let output = output.clone();
            workers.push(std::thread::spawn(move || {
                if let Some(reply) = server.handle_line(&line) {
                    write(&output, reply);
                }
            }));
        } else if let Some(reply) = server.handle_line(&line) {
            write(&output, reply);
        }
        workers.retain(|w| !w.is_finished());
    }
    // The client closed stdin: let the calls in progress answer (their commands have limits).
    for worker in workers {
        let _ = worker.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoAgent;

    impl AgentLink for NoAgent {
        fn call(&self, _method: &str, _params: Value) -> Result<Value, AgentError> {
            Err(AgentError::unavailable("Passyble isn't running"))
        }
    }

    fn server() -> Arc<McpServer> {
        McpServer::new(Box::new(NoAgent), "test.exe".into(), std::env::temp_dir())
    }

    #[test]
    fn json_rpc_basics() {
        let s = server();
        let reply: Value = serde_json::from_str(&s.handle_line("{").unwrap()).unwrap();
        assert_eq!(reply["error"]["code"], -32700);
        let reply: Value = serde_json::from_str(
            &s.handle_line(r#"{"jsonrpc":"2.0","id":7,"method":"nope"}"#)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (reply["id"].clone(), reply["error"]["code"].clone()),
            (json!(7), json!(-32601))
        );
        assert!(s
            .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .is_none());
        let reply: Value = serde_json::from_str(
            &s.handle_line(
                r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"x"}]"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reply, json!([{ "jsonrpc": "2.0", "id": 1, "result": {} }]));
    }

    #[test]
    fn initialize_negotiates_the_version() {
        let s = server();
        for (asked, got) in [
            ("2025-06-18", "2025-06-18"),
            ("2024-11-05", "2024-11-05"),
            ("1999-01-01", PROTOCOL_VERSIONS[0]),
        ] {
            let reply = s
                .handle_message(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": { "protocolVersion": asked, "capabilities": {},
                        "clientInfo": { "name": "claude-code", "version": "2.1" } } }))
                .unwrap();
            assert_eq!(reply["result"]["protocolVersion"], got);
            assert_eq!(reply["result"]["serverInfo"]["name"], SERVER_NAME);
            assert!(reply["result"]["capabilities"]["tools"].is_object());
        }
        assert_eq!(s.client()["name"], "claude-code");
        assert_eq!(s.client()["process"], "test.exe");
    }

    #[test]
    fn tools_steer_toward_run_with_secret() {
        let tools = tools();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["run_with_secret", "list_items", "reveal_secret"]);
        let reveal = tools[2]["description"].as_str().unwrap();
        assert!(reveal.contains("prefer run_with_secret"));
        assert!(reveal.contains("AI provider"));
        assert!(tools[0]["description"]
            .as_str()
            .unwrap()
            .contains("Prefer it to reveal_secret"));
    }

    #[test]
    fn an_unreachable_agent_is_a_clean_tool_error() {
        let s = server();
        let reply = s
            .handle_message(
                &json!({ "jsonrpc": "2.0", "id": "a", "method": "tools/call",
                "params": { "name": "list_items", "arguments": {} } }),
            )
            .unwrap();
        assert_eq!(reply["result"]["isError"], true);
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Passyble isn't reachable"), "{text}");
        let reply = s
            .handle_message(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "bogus", "arguments": {} } }))
            .unwrap();
        assert_eq!(reply["error"]["code"], -32602);
        let reply = s
            .handle_message(&json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": "run_with_secret", "arguments": { "command": "x", "env": {} } } }))
            .unwrap();
        assert_eq!(reply["result"]["isError"], true);
    }
}
