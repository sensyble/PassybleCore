//! What the connector learns from the OS: the program that started it (for the approval prompt),
//! and where a command's program is.

use std::path::{Path, PathBuf};

/// Shells and launchers between the MCP client and this connector, skipped when naming the
/// client's program (`cmd /c passyble-mcp.exe` still names Claude Code's `claude.exe`).
const WRAPPERS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "conhost.exe",
    "bash.exe",
    "sh.exe",
    "wsl.exe",
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "env",
    "sudo",
];

/// The file name of the first program up the parent chain that isn't a shell ([`WRAPPERS`]), at
/// most four levels up; `""` if unknown.
pub fn client_program() -> String {
    let mut pid = std::process::id();
    for _ in 0..4 {
        let Some((parent, name)) = parent_of(pid) else {
            return String::new();
        };
        if !WRAPPERS.iter().any(|w| w.eq_ignore_ascii_case(&name)) {
            return name;
        }
        pid = parent;
    }
    String::new()
}

/// The parent of process `pid`: its id and executable file name.
#[cfg(windows)]
fn parent_of(pid: u32) -> Option<(u32, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    // SAFETY: plain Win32 calls on a snapshot handle that is closed before returning; `entry`
    // has its size set as the API requires.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entries: Vec<(u32, u32, String)> = Vec::new();
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snapshot, &mut entry);
        while ok != 0 {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            entries.push((
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                String::from_utf16_lossy(&entry.szExeFile[..len]),
            ));
            ok = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
        let parent = entries.iter().find(|e| e.0 == pid)?.1;
        let name = entries.iter().find(|e| e.0 == parent)?.2.clone();
        Some((parent, name))
    }
}

/// Linux: `/proc/<pid>/stat` names the parent, `/proc/<parent>/exe` (or `comm`) its program.
#[cfg(target_os = "linux")]
fn parent_of(pid: u32) -> Option<(u32, String)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`; comm may contain spaces and parentheses.
    let after = &stat[stat.rfind(')')? + 1..];
    let parent: u32 = after.split_whitespace().nth(1)?.parse().ok()?;
    let name = std::fs::read_link(format!("/proc/{parent}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .or_else(|| {
            std::fs::read_to_string(format!("/proc/{parent}/comm"))
                .ok()
                .map(|c| c.trim().to_string())
        })?;
    Some((parent, name))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn parent_of(_pid: u32) -> Option<(u32, String)> {
    None
}

/// The program `command` names: a path (relative to `cwd`), or a name looked up in `PATH`, never
/// in the working directory (a repository can't plant a `git.exe` that way). On Windows a name
/// without an extension also tries `PATHEXT` (`.COM;.EXE;.BAT;.CMD`), so `npm` finds `npm.cmd`.
pub fn resolve_program(command: &str, cwd: &Path) -> Option<PathBuf> {
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    let is_path = command.contains('/') || (cfg!(windows) && command.contains('\\'));
    if is_path {
        let path = cwd.join(command);
        return with_extensions(&path).into_iter().find(|p| runnable(p));
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .filter(|dir| dir.is_absolute())
        .flat_map(|dir| with_extensions(&dir.join(command)))
        .find(|p| runnable(p))
}

/// `path`, and on Windows without an extension, `path` with each `PATHEXT` extension.
fn with_extensions(path: &Path) -> Vec<PathBuf> {
    let mut out = vec![path.to_path_buf()];
    if cfg!(windows) && path.extension().is_none() {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        out = exts
            .split(';')
            .map(str::trim)
            .filter(|e| e.starts_with('.') && e.len() > 1)
            // Only what CreateProcess (and Rust's batch file support) can start.
            .filter(|e| [".com", ".exe", ".bat", ".cmd"].contains(&e.to_ascii_lowercase().as_str()))
            .map(|e| {
                let mut p = path.as_os_str().to_owned();
                p.push(e);
                PathBuf::from(p)
            })
            .collect();
    }
    out
}

fn runnable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// `path` resolved (symlinks, `..`), without Windows' `\\?\` prefix, for the prompt and the run.
pub fn display_path(path: &Path) -> PathBuf {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        Some(rest) => PathBuf::from(format!(r"\\{}", &rest[4..])),
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_programs_in_path_only() {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) { "tool.cmd" } else { "tool" };
        let tool = dir.path().join(name);
        std::fs::write(&tool, "echo hi").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // A path relative to the working directory.
        let found = resolve_program(&format!("./{name}"), dir.path()).unwrap();
        assert_eq!(display_path(&found), display_path(&tool));
        // A bare name is never looked for in the working directory.
        let elsewhere = tempfile::tempdir().unwrap();
        let saved = std::env::var_os("PATH");
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                if let Some(p) = &self.0 {
                    std::env::set_var("PATH", p);
                }
            }
        }
        let _restore = Restore(saved);
        std::env::set_var("PATH", elsewhere.path());
        assert!(resolve_program("tool", dir.path()).is_none());
        std::env::set_var("PATH", dir.path());
        let found = resolve_program("tool", elsewhere.path()).unwrap();
        assert_eq!(display_path(&found), display_path(&tool));
        assert!(resolve_program("", dir.path()).is_none());
        assert!(resolve_program("missing-tool", dir.path()).is_none());
    }

    #[test]
    fn names_a_parent() {
        // The test runner has a parent; whatever it is, it has a name or the lookup says "".
        let _ = client_program();
        #[cfg(any(windows, target_os = "linux"))]
        assert!(parent_of(std::process::id()).is_some());
    }
}
