//! Native Messaging host for the Pass browser extension (`com.sensyble.pass`).
//!
//! The browser starts this process and talks to it over stdin/stdout with 32-bit
//! native-endian length-prefixed JSON. It relays each message, unchanged, to the
//! desktop agent over local IPC, and relays the agent's responses and events back. It holds no
//! secrets and makes no decisions.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use interprocess::local_socket::traits::Stream as _;
use interprocess::local_socket::Stream;
use pass_agent::ipc::connect;
use pass_agent::timing;
use serde_json::{json, Value};

/// The browser caps host to extension messages at 1 MB.
const MAX_OUT: usize = 1024 * 1024;
/// Extension to host messages are capped at 4 GB by Chrome; we accept far less.
const MAX_IN: usize = 8 * 1024 * 1024;
/// How long the host waits for the desktop app it launched: 60 × 250 ms = 15 s.
const LAUNCH_POLLS: u32 = 60;
const LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(250);

fn read_message(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_IN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0; len];
    input.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_message(out: &Mutex<impl Write>, message: &[u8]) -> io::Result<()> {
    if message.len() > MAX_OUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    let mut out = out.lock().unwrap_or_else(|p| p.into_inner());
    out.write_all(&(message.len() as u32).to_ne_bytes())?;
    out.write_all(message)?;
    out.flush()
}

fn error_reply(request: &[u8], code: &str, message: &str) -> Vec<u8> {
    let id = serde_json::from_slice::<Value>(request)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .unwrap_or(Value::Null);
    json!({ "id": id, "error": { "code": code, "message": message } })
        .to_string()
        .into_bytes()
}

/// Tries to reach the agent, starting the desktop app once if it isn't running.
fn connect_agent() -> Option<Stream> {
    if let Some(stream) = try_connect() {
        return Some(stream);
    }
    if launch_app() {
        for _ in 0..LAUNCH_POLLS {
            thread::sleep(LAUNCH_POLL_INTERVAL);
            if let Some(stream) = try_connect() {
                return Some(stream);
            }
        }
    }
    None
}

/// The agent wasn't there at start: answers each request with `agent_unavailable`, but first tries
/// `connect` again, so a desktop app that comes up later (autostart after the browser, a slow
/// restart after an update) is found without the extension having to restart this host. Returns the
/// agent's stream and the request that is still to be relayed, or `None` once the browser closes the
/// port.
fn wait_for_agent<T>(
    input: &mut impl Read,
    out: &Mutex<impl Write>,
    mut connect: impl FnMut() -> Option<T>,
) -> Option<(T, Vec<u8>)> {
    while let Ok(Some(request)) = read_message(input) {
        if let Some(stream) = connect() {
            return Some((stream, request));
        }
        let reply = error_reply(
            &request,
            "agent_unavailable",
            "The Passyble desktop app is not running",
        );
        write_message(out, &reply).ok()?;
        time_unanswered(&request);
    }
    None
}

/// Requests relayed and not answered yet, while timing is on (`pass_agent::timing`).
static TIMED: Mutex<Vec<(Value, String, Arc<timing::Trace>)>> = Mutex::new(Vec::new());

/// A method or event name as it goes into a timing line: protocol names are short identifiers
/// (`logins.fill`, `lock_state`); anything else the browser might send is not written, so no
/// value from a message can end up in the file.
fn step_name(name: &str) -> &str {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        name
    } else {
        "(other)"
    }
}

fn time_request(request: &Value) -> Option<Arc<timing::Trace>> {
    if !timing::enabled() {
        return None;
    }
    let method = step_name(request.get("method")?.as_str()?).to_string();
    let id = request.get("id")?.clone();
    let trace = timing::Trace::begin(&format!("host: {method}: request from the browser"));
    let mut timed = TIMED.lock().unwrap_or_else(|p| p.into_inner());
    // Requests the agent never answered (it went away) don't pile up.
    if timed.len() >= 64 {
        timed.remove(0);
    }
    timed.push((id, method, trace.clone()));
    Some(trace)
}

/// A request answered `agent_unavailable` here (timing on only): one line, so the log shows requests
/// that never reached the agent.
fn time_unanswered(request: &[u8]) {
    if !timing::enabled() {
        return;
    }
    let Ok(value) = serde_json::from_slice::<Value>(request) else {
        return;
    };
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        timing::Trace::begin(&format!(
            "host: {}: error sent to the browser (agent_unavailable)",
            safe_method(method)
        ));
    }
}

/// `method` if it looks like a protocol method name (`passkey.find`), else `other`: a line never
/// carries what a request sent.
fn safe_method(method: &str) -> &str {
    let plain = !method.is_empty()
        && method.len() <= 48
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_');
    if plain {
        method
    } else {
        "other"
    }
}

fn time_reply(line: &str) {
    if !timing::enabled() {
        return;
    }
    let Ok(reply) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if let Some(event) = reply.get("event").and_then(Value::as_str) {
        let event = step_name(event);
        timing::Trace::begin(&format!("host: {event}: event sent to the browser"));
        return;
    }
    let Some(id) = reply.get("id") else { return };
    let mut timed = TIMED.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(at) = timed.iter().position(|(i, _, _)| i == id) {
        let (_, method, trace) = timed.remove(at);
        trace.mark(&answer_step(&method, &reply));
    }
}

/// The host's line for an answer: an error says its code (never its message).
fn answer_step(method: &str, reply: &Value) -> String {
    match reply.get("error") {
        None => format!("host: {method}: answer sent to the browser"),
        Some(error) => {
            let code = error.get("code").and_then(Value::as_str).unwrap_or("");
            format!(
                "host: {method}: error sent to the browser ({})",
                timing::safe_code(code)
            )
        }
    }
}

/// Forwards one request to the agent as a single line. False when the agent is gone.
fn relay(
    send: &mut impl Write,
    out: &Mutex<impl Write>,
    agent_pid: Option<u32>,
    request: &[u8],
) -> bool {
    // Re-serialise to guarantee a single line on the IPC channel.
    let (line, trace) = match serde_json::from_slice::<Value>(request) {
        Ok(value) => (value.to_string(), time_request(&value)),
        Err(_) => {
            let _ = write_message(
                out,
                &error_reply(request, "invalid_params", "malformed JSON"),
            );
            return true;
        }
    };
    foreground::allow(agent_pid);
    if send
        .write_all(line.as_bytes())
        .and_then(|_| send.write_all(b"\n"))
        .and_then(|_| send.flush())
        .is_err()
    {
        let _ = write_message(
            out,
            &error_reply(request, "agent_unavailable", "lost connection to Passyble"),
        );
        return false;
    }
    if let Some(trace) = trace {
        trace.mark("host: sent to the agent");
    }
    true
}

/// A connection to the agent, but only if the pipe belongs to the Pass app installed beside this
/// host: the pipe name is predictable, and a pipe created first by another program (or another
/// Windows user) would otherwise get every request, including passwords sent by `logins.save`.
fn try_connect() -> Option<Stream> {
    let stream = connect().ok()?;
    let app = app_path()?;
    pass_agent::ipc::server_is_allowed(&stream, &[app]).then_some(stream)
}

/// The desktop app beside this host (the installer puts them together). Linux AppImage: the
/// executable the running app recorded beside its staged copy of this host ([`appimage`]).
fn app_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    #[cfg(target_os = "linux")]
    if let Some((_, running)) = appimage::recorded(&exe) {
        return Some(running);
    }
    Some(exe.with_file_name(if cfg!(windows) {
        "Pass.exe"
    } else if cfg!(any(target_os = "macos", target_os = "linux")) {
        // Tauri's mainBinaryName beside this host: macOS Passyble.app/Contents/MacOS/Pass, Linux
        // /usr/bin/Pass beside /usr/bin/pass-native-host (.deb, .rpm).
        "Pass"
    } else {
        "pass-desktop"
    }))
}

/// Linux AppImage. An AppImage mounts at a new `/tmp/.mount_*` folder at every run, so the
/// browser's manifest can't point inside it: at every start the app copies this host to
/// `~/.local/share/Passyble/bin/` and writes [`APP_INFO_FILE`] beside it (`pass_linux::connector`
/// in `Linux/platform`, same format): two lines, the path to start (the `.AppImage` file) and the
/// executable the app runs from right now. The file says what this host starts, so it counts only
/// when it is a regular file of the current user that nobody else can write, in a folder nobody
/// else can write; anything else falls back to the app beside the host. It never widens access:
/// the agent's peer check (`pass_agent::ipc::server_is_allowed`) still has to find exactly the
/// recorded executable behind the socket.
#[cfg(any(target_os = "linux", test))]
mod appimage {
    use std::path::PathBuf;

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub const APP_INFO_FILE: &str = "pass-app";

    /// `(launch, running exe)` from the file's text: exactly two absolute paths, one per line.
    pub fn parse(text: &str) -> Option<(PathBuf, PathBuf)> {
        let lines: Vec<&str> = text.lines().collect();
        let [launch, exe] = lines.as_slice() else {
            return None;
        };
        let path = |line: &str| line.starts_with('/').then(|| PathBuf::from(line));
        Some((path(launch)?, path(exe)?))
    }

    /// The file (or its folder) belongs to this user and no group or other user can write it.
    pub fn trusted(mode: u32, owner: u32, me: u32) -> bool {
        owner == me && mode & 0o022 == 0
    }

    #[cfg(target_os = "linux")]
    pub fn recorded(host_exe: &std::path::Path) -> Option<(PathBuf, PathBuf)> {
        use std::os::unix::fs::MetadataExt;
        let dir = host_exe.parent()?;
        let file = dir.join(APP_INFO_FILE);
        // Not followed: a symlink is not a regular file. Most installs have no such file.
        let meta = std::fs::symlink_metadata(&file).ok()?;
        let me = std::fs::metadata("/proc/self").ok()?.uid();
        let dir_meta = std::fs::metadata(dir).ok()?;
        let safe = meta.is_file()
            && meta.len() <= 8 * 1024
            && trusted(meta.mode(), meta.uid(), me)
            && trusted(dir_meta.mode(), dir_meta.uid(), me);
        if !safe {
            eprintln!("pass-native-host: ignoring {file:?}: not a private file of this user");
            return None;
        }
        let paths = parse(&std::fs::read_to_string(&file).ok()?);
        if paths.is_none() {
            eprintln!("pass-native-host: ignoring {file:?}: not two absolute paths");
        }
        paths
    }
}

/// Starts `Pass.exe --background` from the host's own directory, so that it outlives this host: the
/// browser ends the host when it closes the port (an idle MV3 service worker closes it after ~30 s).
/// On Windows it first asks to break away from the host's job object, if any: a browser running in a
/// job (started by a launcher or a sandboxing tool, for example) has the host in it too, and a child
/// left in a kill-on-close job dies with it. A job without `JOB_OBJECT_LIMIT_BREAKAWAY_OK` refuses
/// breakaway (access denied): then the app is started without it.
fn launch_app() -> bool {
    let Some(app) = app_path() else {
        return false;
    };
    // AppImage: start the `.AppImage` file, not the executable of an old mount.
    #[cfg(target_os = "linux")]
    let app = std::env::current_exe()
        .ok()
        .and_then(|exe| appimage::recorded(&exe))
        .map_or(app, |(launch, _)| launch);
    let attempts: &[bool] = if cfg!(windows) {
        &[true, false]
    } else {
        &[false]
    };
    app.exists()
        && attempts
            .iter()
            .any(|&breakaway| launch_command(&app, breakaway).spawn().is_ok())
}

/// The command that starts the desktop app. Its stdin / stdout / stderr are null: the host's own are
/// the native messaging pipes, and an app holding them would keep the browser from seeing the host
/// exit (and could write into the extension's channel).
fn launch_command(app: &std::path::Path, breakaway: bool) -> std::process::Command {
    use std::process::Stdio;
    // macOS: Launch Services starts the app bundle on its own (not as a child of the browser's
    // host), without bringing it to the front. An app that is already running ignores `--args`;
    // then the agent is reached through the socket as usual.
    #[cfg(target_os = "macos")]
    let mut command = match open_args(app) {
        Some(args) => {
            let mut open = std::process::Command::new("/usr/bin/open");
            open.args(args);
            open
        }
        None => {
            let mut direct = std::process::Command::new(app);
            direct.arg("--background");
            direct
        }
    };
    #[cfg(not(target_os = "macos"))]
    let mut command = std::process::Command::new(app);
    #[cfg(not(target_os = "macos"))]
    command.arg("--background");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(launch_flags(breakaway));
    }
    #[cfg(not(windows))]
    let _ = breakaway;
    command
}

/// macOS: `open -g -a <Passyble.app> --args --background` for an app inside a bundle; `None` for a
/// bare executable (a development build).
#[cfg(any(target_os = "macos", test))]
fn open_args(app: &std::path::Path) -> Option<Vec<std::ffi::OsString>> {
    let bundle = app.ancestors().find(|dir| {
        dir.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
    })?;
    Some(vec![
        "-g".into(),
        "-a".into(),
        bundle.as_os_str().to_os_string(),
        "--args".into(),
        "--background".into(),
    ])
}

/// `CreateProcess` flags for the desktop app: its own process group (no Ctrl+C / Ctrl+Break from the
/// host's console) and, with `breakaway`, out of the host's job object.
#[cfg_attr(not(windows), allow(dead_code))]
fn launch_flags(breakaway: bool) -> u32 {
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    if breakaway {
        CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
    } else {
        CREATE_NEW_PROCESS_GROUP
    }
}

/// Unlock and passkey prompts need Pass in the foreground, but Windows only lets the foreground
/// process (the browser, which started this host) hand that right on. So the host grants it to
/// the agent's process before relaying each request.
#[cfg(windows)]
mod foreground {
    use interprocess::local_socket::Stream;
    use windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow;

    pub fn agent_pid(stream: &Stream) -> Option<u32> {
        pass_agent::ipc::server_process_id(stream)
    }

    pub fn allow(pid: Option<u32>) {
        if let Some(pid) = pid {
            // SAFETY: no pointers involved; failure (we aren't foreground) is harmless.
            unsafe {
                AllowSetForegroundWindow(pid);
            }
        }
    }
}

#[cfg(not(windows))]
mod foreground {
    use interprocess::local_socket::Stream;

    pub fn agent_pid(_stream: &Stream) -> Option<u32> {
        None
    }

    pub fn allow(_pid: Option<u32>) {}
}

fn main() -> ExitCode {
    // The credentials it relays pass through its memory: no crash dumps, and (Windows, macOS) no
    // other process of the user reading it (pass_agent::harden; release builds).
    pass_agent::harden::harden_process();
    timing::set_process("host");
    let stdout = Arc::new(Mutex::new(io::stdout()));
    let mut stdin = io::stdin().lock();

    // Only the first attempt launches the app. After that, every request tries to connect again (and
    // gets `agent_unavailable` while that fails), so the extension can show "open Pass" instead of
    // hanging, and works as soon as Pass is up.
    let (stream, pending) = match connect_agent() {
        Some(stream) => (stream, None),
        None => match wait_for_agent(&mut stdin, &*stdout, try_connect) {
            Some((stream, request)) => (stream, Some(request)),
            None => return ExitCode::SUCCESS,
        },
    };

    let agent_pid = foreground::agent_pid(&stream);
    let (recv, mut send) = stream.split();

    let out = stdout.clone();
    thread::spawn(move || {
        for line in BufReader::new(recv).lines() {
            let Ok(line) = line else { break };
            if write_message(&out, line.as_bytes()).is_err() {
                break;
            }
            time_reply(&line);
        }
        // The agent went away (app closed): exit so the extension reconnects on its next request.
        std::process::exit(0);
    });

    // The request that found the agent is answered by it, not with `agent_unavailable`.
    if let Some(request) = pending {
        if !relay(&mut send, &*stdout, agent_pid, &request) {
            return ExitCode::SUCCESS;
        }
    }
    while let Ok(Some(request)) = read_message(&mut stdin) {
        if !relay(&mut send, &*stdout, agent_pid, &request) {
            break;
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appimage_app_info_is_two_absolute_paths_from_a_private_file() {
        use std::path::PathBuf;
        let parsed =
            appimage::parse("/home/me/Apps/Passyble.AppImage\n/tmp/.mount_PassAb12/usr/bin/Pass\n");
        assert_eq!(
            parsed,
            Some((
                PathBuf::from("/home/me/Apps/Passyble.AppImage"),
                PathBuf::from("/tmp/.mount_PassAb12/usr/bin/Pass")
            ))
        );
        for bad in [
            "",
            "/home/me/Apps/Passyble.AppImage\n",
            "Passyble.AppImage\n/tmp/.mount_x/usr/bin/Pass\n",
            "/home/me/Apps/Passyble.AppImage\nusr/bin/Pass\n",
            "/a\n/b\n/c\n",
        ] {
            assert_eq!(appimage::parse(bad), None, "{bad:?}");
        }
        assert!(appimage::trusted(0o100600, 1000, 1000));
        assert!(appimage::trusted(0o40700, 1000, 1000));
        assert!(appimage::trusted(0o100644, 1000, 1000));
        assert!(!appimage::trusted(0o100600, 0, 1000), "another user's file");
        assert!(!appimage::trusted(0o100620, 1000, 1000), "group-writable");
        assert!(!appimage::trusted(0o40777, 1000, 1000), "other-writable");
    }

    #[test]
    fn timing_lines_name_protocol_methods_only() {
        assert_eq!(step_name("logins.fill"), "logins.fill");
        assert_eq!(step_name("lock_state"), "lock_state");
        for odd in [
            "",
            "pw: hunter2",
            "a
b",
            &"x".repeat(65),
            "héllo",
        ] {
            assert_eq!(step_name(odd), "(other)", "{odd:?}");
        }
    }

    #[test]
    fn framing_roundtrip() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&(5u32).to_ne_bytes());
        framed.extend_from_slice(b"{\"a\"}");
        let mut cursor = io::Cursor::new(framed);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), b"{\"a\"}");
        assert_eq!(read_message(&mut cursor).unwrap(), None);
    }

    #[test]
    fn error_reply_keeps_request_id() {
        let reply: Value =
            serde_json::from_slice(&error_reply(br#"{"id":42,"method":"status"}"#, "x", "y"))
                .unwrap();
        assert_eq!(reply["id"], 42);
        assert_eq!(reply["error"]["code"], "x");
    }

    #[test]
    fn timing_lines_name_an_answers_error_code_never_its_message() {
        let ok = json!({ "id": 1, "result": { "items": [] } });
        assert_eq!(
            answer_step("passkey.find", &ok),
            "host: passkey.find: answer sent to the browser"
        );
        let locked =
            json!({ "id": 1, "error": { "code": "locked", "message": "Vault is locked" } });
        assert_eq!(
            answer_step("passkey.find", &locked),
            "host: passkey.find: error sent to the browser (locked)"
        );
        let unavailable = error_reply(
            br#"{"id":2,"method":"passkey.get"}"#,
            "agent_unavailable",
            "The Passyble desktop app is not running",
        );
        let unavailable: Value = serde_json::from_slice(&unavailable).unwrap();
        assert_eq!(
            answer_step("passkey.get", &unavailable),
            "host: passkey.get: error sent to the browser (agent_unavailable)"
        );
        let odd =
            json!({ "id": 3, "error": { "code": "https://example.com/alice", "message": "x" } });
        assert_eq!(
            answer_step("passkey.get", &odd),
            "host: passkey.get: error sent to the browser (other)"
        );
        let none = json!({ "id": 4, "error": { "message": "no passkey for example.com" } });
        assert_eq!(
            answer_step("passkey.get", &none),
            "host: passkey.get: error sent to the browser (other)"
        );
        // A request answered here (the desktop app not running) names its method, if it is one.
        assert_eq!(safe_method("passkey.find"), "passkey.find");
        assert_eq!(safe_method("unlock.hello"), "unlock.hello");
        assert_eq!(safe_method("https://example.com"), "other");
        assert_eq!(safe_method(""), "other");
        assert_eq!(safe_method("Passkey Find"), "other");
    }

    fn framed(messages: &[&str]) -> io::Cursor<Vec<u8>> {
        let mut buf = Vec::new();
        for m in messages {
            buf.extend_from_slice(&(m.len() as u32).to_ne_bytes());
            buf.extend_from_slice(m.as_bytes());
        }
        io::Cursor::new(buf)
    }

    fn replies(out: Mutex<Vec<u8>>) -> Vec<Value> {
        let bytes = out.into_inner().unwrap();
        let mut cursor = io::Cursor::new(bytes);
        let mut all = Vec::new();
        while let Some(m) = read_message(&mut cursor).unwrap() {
            all.push(serde_json::from_slice(&m).unwrap());
        }
        all
    }

    #[test]
    fn waits_for_the_agent_and_hands_over_the_request_that_found_it() {
        let mut input = framed(&[
            r#"{"id":1,"method":"status"}"#,
            r#"{"id":2,"method":"logins.find"}"#,
            r#"{"id":3,"method":"logins.fill"}"#,
            r#"{"id":4,"method":"status"}"#,
        ]);
        let out = Mutex::new(Vec::new());
        let mut attempts = 0;
        let connected = wait_for_agent(&mut input, &out, || {
            attempts += 1;
            (attempts == 3).then_some("agent")
        });
        let (stream, request) = connected.unwrap();
        assert_eq!(stream, "agent");
        assert_eq!(request, br#"{"id":3,"method":"logins.fill"}"#);
        assert_eq!(attempts, 3, "one attempt per request");
        let replies = replies(out);
        assert_eq!(
            replies.len(),
            2,
            "only the requests before the agent came up"
        );
        for (reply, id) in replies.iter().zip([1, 2]) {
            assert_eq!(reply["id"], id);
            assert_eq!(reply["error"]["code"], "agent_unavailable");
        }
        // Request 4 is left for the relay.
        assert_eq!(
            read_message(&mut input).unwrap().unwrap(),
            br#"{"id":4,"method":"status"}"#
        );
    }

    #[test]
    fn without_the_agent_answers_every_request_until_the_browser_closes_the_port() {
        let mut input = framed(&[r#"{"id":7}"#, "not json"]);
        let out = Mutex::new(Vec::new());
        let connected = wait_for_agent(&mut input, &out, || None::<()>);
        assert!(connected.is_none());
        let replies = replies(out);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["id"], 7);
        assert_eq!(replies[1]["id"], Value::Null);
        assert!(replies
            .iter()
            .all(|r| r["error"]["code"] == "agent_unavailable"));
    }

    #[test]
    fn mac_opens_the_app_bundle_in_the_background() {
        let app = std::path::Path::new("/Applications/Passyble.app/Contents/MacOS/Pass");
        assert_eq!(
            open_args(app).unwrap(),
            [
                "-g",
                "-a",
                "/Applications/Passyble.app",
                "--args",
                "--background"
            ]
        );
        assert_eq!(
            open_args(std::path::Path::new("/usr/local/bin/pass-desktop")),
            None
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn launches_the_app_in_the_background_detached_from_this_host() {
        let app = std::path::Path::new("Pass.exe");
        for breakaway in [true, false] {
            let command = launch_command(app, breakaway);
            assert_eq!(command.get_program(), app.as_os_str());
            assert_eq!(command.get_args().collect::<Vec<_>>(), ["--background"]);
        }
        assert_eq!(
            launch_flags(true),
            0x0100_0200,
            "breakaway + new process group"
        );
        assert_eq!(
            launch_flags(false),
            0x0000_0200,
            "the fallback: new process group only"
        );
    }

    #[test]
    fn relay_sends_one_line_and_rejects_malformed_json() {
        let mut send = Vec::new();
        let out = Mutex::new(Vec::new());
        assert!(relay(
            &mut send,
            &out,
            None,
            b"{\"id\": 1,\n \"method\": \"status\"}"
        ));
        assert!(relay(&mut send, &out, None, b"{oops"));
        assert_eq!(send, b"{\"id\":1,\"method\":\"status\"}\n");
        let replies = replies(out);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["error"]["code"], "invalid_params");
    }
}
