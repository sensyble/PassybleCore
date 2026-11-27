//! The connector end to end: MCP messages into `McpServer`, over the agent's real pipe (or unix
//! socket) to a desktop agent with a test vault and a fake `Ui`, and real child processes (this
//! test binary itself, in the `child_*` helper tests below).
//!
//! The agent's pipe is named after the user: this test renames the user (Windows `USERNAME`) or
//! moves the socket (`XDG_RUNTIME_DIR`), so it never meets a running Passyble.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use pass_agent::{
    Agent, AgentConfig, AiDecision, AiOutcome, AiRevealRequest, AiRunRequest, Consent,
    PasskeyChoice, Ui,
};
use pass_core::{AiAccess, CustomField, FieldKind, Item};
use passyble_mcp::{call_over, mask::MASK, AgentError, AgentLink, McpServer};
use serde_json::{json, Value};

const DEPLOY: &str = "ghp_T0pS3cretDeployValue_9f8e7d";
const API_KEY: &str = "sk-live-0123456789abcdefXYZ";
const AUTO: &str = "auto/Token+value with spaces";
const BANK: &str = "bank-password-never-shared";

/// Helper for the commands the tests run: prints the secret it got, as it is and encoded, when
/// started by the connector (the variable is set); does nothing in a normal test run.
#[test]
fn child_print() {
    let Ok(token) = std::env::var("DEPLOY_TOKEN").or_else(|_| std::env::var("AUTO_TOKEN")) else {
        return;
    };
    println!("marker-start");
    println!("raw: {token}");
    println!("base64: {}", STANDARD.encode(&token));
    println!("basic: {}", STANDARD.encode(format!("user:{token}")));
    let hex: String = token.bytes().map(|b| format!("{b:02x}")).collect();
    println!("hex: {hex}");
    let url: String = token
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    println!("url: {url}");
    if let Ok(key) = std::env::var("API_KEY") {
        println!("key: {key}");
    }
    eprintln!("stderr raw: {token}");
    println!("marker-end");
}

/// Helper: sleeps far past any test's time limit when started by the connector.
#[test]
fn child_sleep() {
    if std::env::var("SLEEPY_TOKEN").is_ok() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[derive(Default)]
struct TestUi {
    agent: Mutex<Option<Weak<Agent>>>,
    unlocks: Mutex<usize>,
    run_answers: Mutex<VecDeque<AiDecision>>,
    run_prompts: Mutex<Vec<AiRunRequest>>,
    reveal_answers: Mutex<VecDeque<bool>>,
    reveal_prompts: Mutex<Vec<AiRevealRequest>>,
}

impl Ui for TestUi {
    fn request_unlock(&self) -> bool {
        *self.unlocks.lock().unwrap() += 1;
        let agent = self.agent.lock().unwrap().as_ref().and_then(Weak::upgrade);
        agent.is_some_and(|a| a.unlock("master").is_ok())
    }
    fn confirm_passkey_create(&self, _rp_id: &str, _user_name: &str) -> Consent {
        Consent::Deny
    }
    fn choose_passkey(&self, _rp_id: &str, _options: &[PasskeyChoice]) -> Option<usize> {
        None
    }
    fn show_totp_popup(&self, _item_id: &str, _title: &str) {}
    fn notify_lock_state(&self, _locked: bool) {}
    fn confirm_ai_run(&self, request: &AiRunRequest) -> Option<AiDecision> {
        self.run_prompts.lock().unwrap().push(request.clone());
        Some(
            self.run_answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(AiDecision::Deny),
        )
    }
    fn confirm_ai_reveal(&self, request: &AiRevealRequest) -> Option<bool> {
        self.reveal_prompts.lock().unwrap().push(request.clone());
        Some(
            self.reveal_answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(false),
        )
    }
}

/// The agent's pipe without the server check (the test agent isn't `Pass.exe`): the same line
/// protocol as the connector's `PipeLink`.
struct TestLink;

impl AgentLink for TestLink {
    fn call(&self, method: &str, params: Value) -> Result<Value, AgentError> {
        let mut stream = pass_agent::ipc::connect()
            .map_err(|e| AgentError::unavailable(format!("no test agent: {e}")))?;
        call_over(&mut stream, method, params)
    }
}

fn item(title: &str, password: &str, access: Option<AiAccess>) -> Item {
    let mut item = Item {
        title: title.into(),
        username: format!("{}-user", title.to_lowercase().replace(' ', "-")),
        password: password.into(),
        urls: vec![format!(
            "https://{}.example",
            title.to_lowercase().replace(' ', "")
        )],
        ..Default::default()
    };
    item.set_ai_access(access);
    item
}

struct Session {
    mcp: Arc<McpServer>,
    next: u64,
}

impl Session {
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        self.mcp
            .handle_message(
                &json!({ "jsonrpc": "2.0", "id": self.next, "method": method, "params": params }),
            )
            .expect("a reply")
    }

    /// A tool call: (text, isError).
    fn tool(&mut self, name: &str, arguments: Value) -> (String, bool) {
        let reply = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        let result = &reply["result"];
        assert!(result.is_object(), "{reply}");
        (
            result["content"][0]["text"].as_str().unwrap().to_string(),
            result["isError"].as_bool().unwrap(),
        )
    }
}

fn child_args(test: &str) -> Vec<String> {
    [test, "--exact", "--nocapture", "--test-threads=1"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn assert_no_secrets(text: &str) {
    for secret in [DEPLOY, API_KEY, AUTO, BANK] {
        assert!(!text.contains(secret), "{secret} in {text}");
        let b64 = STANDARD.encode(secret);
        assert!(
            !text.contains(&b64[..b64.len() - 4]),
            "base64 of {secret} in {text}"
        );
        let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
        assert!(!text.contains(&hex), "hex of {secret} in {text}");
    }
}

#[test]
fn mcp_end_to_end() {
    // A pipe or socket of our own.
    let runtime = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    std::env::set_var(
        "USERNAME",
        format!("passyble-mcp-test-{}", std::process::id()),
    );
    #[cfg(unix)]
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());

    let dir = tempfile::tempdir().unwrap();
    let ui = Arc::new(TestUi::default());
    let agent = Agent::new(
        AgentConfig::new(
            dir.path().join("pass.vault"),
            "laptop".into(),
            Duration::from_secs(900),
        ),
        ui.clone(),
    );
    *ui.agent.lock().unwrap() = Some(Arc::downgrade(&agent));
    agent.create_vault("master").unwrap();
    let vault = agent.vault().unwrap();
    let mut deploy = item("Deploy API", DEPLOY, None);
    deploy.fields.push(CustomField {
        name: "API key".into(),
        value: API_KEY.into(),
        kind: FieldKind::Hidden,
    });
    deploy.set_ai_access(Some(AiAccess::Ask));
    let deploy = vault.upsert(deploy).unwrap();
    let auto = vault
        .upsert(item("Auto Token", AUTO, Some(AiAccess::Allow)))
        .unwrap();
    vault.upsert(item("Private Bank", BANK, None)).unwrap();
    agent.save().unwrap();
    drop(vault);
    agent.lock();
    let _server = pass_agent::ipc::Server::start(agent.clone()).unwrap();

    let work = tempfile::tempdir().unwrap();
    let mcp = McpServer::new(
        Box::new(TestLink),
        "test-runner.exe".into(),
        work.path().to_path_buf(),
    );
    let mut s = Session { mcp, next: 0 };
    let me = std::env::current_exe().unwrap();
    let me = me.to_string_lossy().to_string();

    // initialize and the tools.
    let init = s.request(
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": { "name": "claude-code", "version": "2.1.0" } }),
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(s
        .mcp
        .handle_message(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .is_none());
    let tools = s.request("tools/list", json!({}));
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 3);

    // list_items while locked: the user is asked to unlock first; only shared items, no secrets.
    let (text, err) = s.tool("list_items", json!({}));
    assert!(!err, "{text}");
    assert_eq!(*ui.unlocks.lock().unwrap(), 1);
    assert!(
        text.contains("Deploy API") && text.contains("Auto Token"),
        "{text}"
    );
    assert!(
        text.contains("API key") && text.contains("\"password\""),
        "{text}"
    );
    assert!(
        !text.contains("Private Bank") && !text.contains("private-bank"),
        "{text}"
    );
    assert!(!text.contains(pass_core::AI_ACCESS_FIELD), "{text}");
    assert_no_secrets(&text);

    let run_deploy = |args: Vec<String>| {
        json!({
            "command": me,
            "args": args,
            "env": { "DEPLOY_TOKEN": { "item": "Deploy API" }, "API_KEY": { "item": deploy.id, "field": "API key" } },
        })
    };

    // Denied: a clean tool error, nothing ran.
    let (text, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(err && text.starts_with("Denied."), "{text}");
    {
        let prompts = ui.run_prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        let p = &prompts[0];
        assert_eq!(p.client.label(), "Claude Code (test-runner.exe)");
        assert_eq!(p.args, child_args("child_print"));
        assert!(p.command_line().contains("child_print --exact"));
        assert_eq!(
            std::path::Path::new(&p.cwd).canonicalize().unwrap(),
            work.path().canonicalize().unwrap()
        );
        assert_eq!(p.secrets.len(), 2);
        assert!(p
            .secrets
            .iter()
            .all(|u| u.asks && u.item_title == "Deploy API"));
        let envs: Vec<&str> = p.secrets.iter().map(|u| u.env.as_str()).collect();
        assert_eq!(envs, ["API_KEY", "DEPLOY_TOKEN"]);
    }
    assert!(!agent
        .ai_log()
        .iter()
        .any(|e| e.outcome == AiOutcome::Running || e.outcome == AiOutcome::Finished));

    // Allowed once: it runs, and the output has every secret concealed.
    ui.run_answers.lock().unwrap().push_back(AiDecision::Once);
    let (text, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(!err, "{text}");
    assert!(text.starts_with("Exit code 0"), "{text}");
    assert!(
        text.contains("marker-start") && text.contains("marker-end"),
        "{text}"
    );
    assert!(text.contains(&format!("raw: {MASK}")), "{text}");
    assert!(text.contains(&format!("key: {MASK}")), "{text}");
    assert!(text.contains(&format!("stderr raw: {MASK}")), "{text}");
    assert!(text.contains(&format!("base64: {MASK}")), "{text}");
    assert!(text.contains(&format!("hex: {MASK}")), "{text}");
    assert_no_secrets(&text);
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 2);

    // "Once" was for that command only: asked again, now "until the vault locks".
    ui.run_answers
        .lock()
        .unwrap()
        .push_back(AiDecision::UntilLock);
    let (text, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(!err, "{text}");
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 3);
    assert_eq!(agent.ai_grants().len(), 1);
    assert_eq!(
        agent.ai_grants()[0].client_key,
        "claude-code|test-runner.exe"
    );

    // The grant covers the next command of that client: no prompt.
    let (text, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(!err, "{text}");
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 3);
    assert_eq!(agent.ai_log()[0].approval, Some("grant"));

    // Another client (another program) doesn't have it.
    let other = McpServer::new(
        Box::new(TestLink),
        "codex.exe".into(),
        work.path().to_path_buf(),
    );
    let mut other = Session {
        mcp: other,
        next: 100,
    };
    other.request(
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "clientInfo": { "name": "codex-mcp-client", "version": "1" } }),
    );
    ui.run_answers.lock().unwrap().push_back(AiDecision::Once);
    let (text, err) = other.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(!err, "{text}");
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 4);
    assert_eq!(
        ui.run_prompts.lock().unwrap()[3].client.label(),
        "Codex (codex.exe)"
    );

    // "Allow without asking": no prompt, still logged.
    let (text, err) = s.tool(
        "run_with_secret",
        json!({ "command": me, "args": child_args("child_print"), "env": { "AUTO_TOKEN": { "item": "Auto Token" } } }),
    );
    assert!(!err, "{text}");
    assert!(text.contains(&format!("raw: {MASK}")), "{text}");
    assert_no_secrets(&text);
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 4);
    assert_eq!(agent.ai_log()[0].approval, Some("without_asking"));
    assert_eq!(agent.ai_log()[0].outcome, AiOutcome::Finished);
    assert_eq!(agent.ai_log()[0].exit_code, Some(0));

    // An item that isn't shared answers exactly like one that doesn't exist.
    let (bank, err) = s.tool(
        "run_with_secret",
        json!({ "command": me, "env": { "X": { "item": "Private Bank" } } }),
    );
    assert!(err);
    let (missing, _) = s.tool(
        "run_with_secret",
        json!({ "command": me, "env": { "X": { "item": "Nothing Here" } } }),
    );
    assert_eq!(
        bank.replace("Private Bank", "?"),
        missing.replace("Nothing Here", "?")
    );
    assert_no_secrets(&bank);

    // Reveal asks every time: even for "Allow without asking", even with a grant.
    let (text, err) = s.tool(
        "reveal_secret",
        json!({ "item": auto.id, "reason": "the user asked" }),
    );
    assert!(err && text.starts_with("Denied."), "{text}");
    ui.reveal_answers.lock().unwrap().push_back(true);
    let (text, err) = s.tool(
        "reveal_secret",
        json!({ "item": "Deploy API", "field": "password", "reason": "to paste it" }),
    );
    assert!(!err && text.ends_with(DEPLOY), "{text}");
    {
        let prompts = ui.reveal_prompts.lock().unwrap();
        assert_eq!(prompts.len(), 2);
        assert_eq!(prompts[1].reason, "to paste it");
        assert_eq!(prompts[1].field, "password");
    }

    // Locking ends the grant; a request while locked asks to unlock first, then asks again.
    agent.lock();
    assert!(agent.ai_grants().is_empty());
    ui.run_answers.lock().unwrap().push_back(AiDecision::Once);
    let (text, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(!err, "{text}");
    assert_eq!(*ui.unlocks.lock().unwrap(), 2);
    assert_eq!(ui.run_prompts.lock().unwrap().len(), 5);

    // The time limit stops the command (and its tree).
    let started = Instant::now();
    let (text, err) = s.tool(
        "run_with_secret",
        json!({ "command": me, "args": child_args("child_sleep"), "timeout_secs": 1,
            "env": { "SLEEPY_TOKEN": { "item": "Auto Token" } } }),
    );
    assert!(
        err && text.starts_with("Stopped after the 1 s time limit"),
        "{text}"
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(agent.ai_log()[0].outcome, AiOutcome::TimedOut);

    // Commands that can't run are clean errors.
    let (text, err) = s.tool(
        "run_with_secret",
        json!({ "command": "no-such-program-passyble", "env": { "X": { "item": "Auto Token" } } }),
    );
    assert!(err && text.starts_with("Command not found"), "{text}");
    let (text, err) = s.tool(
        "run_with_secret",
        json!({ "command": me, "env": { "PATH": { "item": "Auto Token" } } }),
    );
    assert!(err && text.contains("can't hold a secret"), "{text}");

    // The log has every request, and no secret anywhere.
    let log = agent.ai_log();
    let outcomes: Vec<AiOutcome> = log.iter().map(|e| e.outcome).collect();
    for want in [
        AiOutcome::Listed,
        AiOutcome::Denied,
        AiOutcome::Finished,
        AiOutcome::Revealed,
        AiOutcome::TimedOut,
    ] {
        assert!(outcomes.contains(&want), "{want:?} in {outcomes:?}");
    }
    assert_no_secrets(&serde_json::to_string(&log).unwrap());

    // Two more denials (three in all within two minutes): this client is refused without asking.
    let (_, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(err);
    let prompts = ui.run_prompts.lock().unwrap().len();
    let (text, err) = s.tool("run_with_secret", run_deploy(child_args("child_print")));
    assert!(err && text.contains("won't ask again"), "{text}");
    assert_eq!(ui.run_prompts.lock().unwrap().len(), prompts);
    drop(runtime);
}

/// The real binary over stdio: initialize, tools/list, and a clean error when no Passyble is
/// there (it only talks to the Passyble app installed beside it).
#[test]
fn the_binary_speaks_mcp_over_stdio() {
    let runtime = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_passyble-mcp"))
        .env(
            "USERNAME",
            format!("passyble-mcp-nobody-{}", std::process::id()),
        )
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut send = |v: Value| {
        stdin.write_all(format!("{v}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
    };
    send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } } }));
    let init: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(init["result"]["serverInfo"]["name"], "passyble");
    send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
    send(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let list: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(list["id"], 2);
    assert_eq!(list["result"]["tools"][0]["name"], "run_with_secret");
    send(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": { "name": "list_items", "arguments": {} } }));
    let call: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(call["id"], 3);
    assert_eq!(call["result"]["isError"], true);
    assert!(call["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Passyble isn't reachable"));
    drop(send);
    drop(stdin);
    assert!(child.wait().unwrap().success());
}
