//! Runs an AI tool's command with secrets in its environment, like `op run`: no shell, no secret
//! on any command line, stdin closed, stdout and stderr captured (up to a cap), a time limit, and
//! the whole process tree stopped when it runs over or the MCP client cancels.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// How often the wait loop looks at the child, the time limit and the cancel flag.
const POLL: Duration = Duration::from_millis(20);
/// How long output is still read after the command ended (a program it started in the background
/// may keep the pipes open; what came until then is returned).
const DRAIN: Duration = Duration::from_secs(2);

pub struct RunSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, Zeroizing<String>)>,
    pub timeout: Duration,
    /// Bytes kept per stream (the rest is read and dropped, and counted).
    pub keep: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// The command exited (`None`: ended by a signal).
    Exited(Option<i32>),
    TimedOut,
    Cancelled,
}

pub struct RunOutput {
    pub ending: Ending,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
    /// Bytes the command wrote to each stream in all.
    pub stdout_total: usize,
    pub stderr_total: usize,
    pub elapsed: Duration,
}

#[derive(Default)]
struct Capture {
    data: Zeroizing<Vec<u8>>,
    total: usize,
    done: bool,
}

fn reader(mut from: impl Read + Send + 'static, keep: usize) -> Arc<Mutex<Capture>> {
    let capture = Arc::new(Mutex::new(Capture::default()));
    let shared = capture.clone();
    let _ = thread::Builder::new()
        .name("passyble-mcp-output".into())
        .spawn(move || {
            let mut buf = Zeroizing::new(vec![0u8; 16 * 1024]);
            loop {
                match from.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut c = shared.lock().unwrap_or_else(|p| p.into_inner());
                        let room = keep.saturating_sub(c.data.len());
                        c.data.extend_from_slice(&buf[..n.min(room)]);
                        c.total += n;
                    }
                }
            }
            shared.lock().unwrap_or_else(|p| p.into_inner()).done = true;
        });
    capture
}

/// Runs `spec` until it exits, runs over its time limit or `cancel` is set.
pub fn run(spec: RunSpec, cancel: &AtomicBool) -> io::Result<RunOutput> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &spec.env {
        command.env(name, value.as_str());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window of its own when the MCP client has none (Claude Desktop).
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group, so the whole tree can be stopped.
        command.process_group(0);
    }
    let started = Instant::now();
    let spawned = command.spawn();
    // The `Command` holds copies of the values: gone as soon as the child has its own.
    drop(command);
    let mut child = spawned?;
    let tree = Tree::new(&child);
    let out = reader(child.stdout.take().expect("piped"), spec.keep);
    let err = reader(child.stderr.take().expect("piped"), spec.keep);

    let ending = loop {
        if let Some(status) = child.try_wait()? {
            break Ending::Exited(status.code());
        }
        if started.elapsed() >= spec.timeout {
            tree.kill(&mut child);
            break Ending::TimedOut;
        }
        if cancel.load(Ordering::SeqCst) {
            tree.kill(&mut child);
            break Ending::Cancelled;
        }
        thread::sleep(POLL);
    };
    let _ = child.wait();
    let drain_until = Instant::now() + DRAIN;
    let finished = |c: &Arc<Mutex<Capture>>| c.lock().unwrap_or_else(|p| p.into_inner()).done;
    while !(finished(&out) && finished(&err)) && Instant::now() < drain_until {
        thread::sleep(POLL);
    }
    let take = |c: &Arc<Mutex<Capture>>| {
        let mut c = c.lock().unwrap_or_else(|p| p.into_inner());
        (std::mem::take(&mut c.data), c.total)
    };
    let (stdout, stdout_total) = take(&out);
    let (stderr, stderr_total) = take(&err);
    Ok(RunOutput {
        ending,
        stdout,
        stderr,
        stdout_total,
        stderr_total,
        elapsed: started.elapsed(),
    })
}

/// The command and everything it started: a job object on Windows, the process group on unix.
#[cfg(windows)]
struct Tree(Option<windows_sys::Win32::Foundation::HANDLE>);

#[cfg(windows)]
impl Tree {
    fn new(child: &Child) -> Tree {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
        // SAFETY: plain Win32 calls; the child's handle is alive (we own `child`), the job handle
        // is closed on failure here or in `Drop`.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Tree(None);
            }
            if AssignProcessToJobObject(job, child.as_raw_handle()) == 0 {
                CloseHandle(job);
                return Tree(None);
            }
            Tree(Some(job))
        }
    }

    fn kill(&self, child: &mut Child) {
        if let Some(job) = self.0 {
            // SAFETY: `job` is the open job handle from `new`.
            unsafe {
                windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1);
            }
        }
        let _ = child.kill();
    }
}

#[cfg(windows)]
impl Drop for Tree {
    fn drop(&mut self) {
        if let Some(job) = self.0.take() {
            // SAFETY: closing the handle `new` opened. The job has no kill-on-close limit: a
            // program the command left running in the background keeps running.
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(job);
            }
        }
    }
}

#[cfg(unix)]
struct Tree(i32);

#[cfg(unix)]
impl Tree {
    fn new(child: &Child) -> Tree {
        Tree(child.id() as i32)
    }

    fn kill(&self, child: &mut Child) {
        // SAFETY: a signal to the process group the child leads (`process_group(0)`).
        unsafe {
            libc::kill(-self.0, libc::SIGKILL);
        }
        let _ = child.kill();
    }
}

#[cfg(not(any(windows, unix)))]
struct Tree;

#[cfg(not(any(windows, unix)))]
impl Tree {
    fn new(_child: &Child) -> Tree {
        Tree
    }
    fn kill(&self, child: &mut Child) {
        let _ = child.kill();
    }
}
