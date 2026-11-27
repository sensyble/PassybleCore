//! `pass_agent::Ui` for the desktop app. The agent calls these from IPC threads and expects them
//! to block until the user has answered, so each parks on a channel that a Tauri command
//! (`answer_prompt`, `unlock`, ...) resolves.
//!
//! Unlock requests go to Windows Hello first when it is ready for the active vault: the prompt window
//! shows "Unlock with Windows Hello" and the Hello dialog opens over it, pushed to the foreground
//! (`platform::win32::run_prompt`). If it doesn't get the foreground within 2 s, the prompt offers
//! "Use Windows Hello" / "Use master password" / Cancel, and those choices cancel the pending Hello
//! operation.
//!
//! A Windows passkey request on a locked vault (`passkey_provider`) shows Hello over Windows' passkey
//! dialog without a Passyble window; only when Hello can't show there does it use the prompt window.
//!
//! Requests from the extension's own unlock form (`unlock.hello`) and browser per-fill verifications
//! show Hello over the browser window (`platform::browser_window`, found via
//! `pass_agent::ipc::request_client_pid`). "Use master password instead" sends `unlock.cancel`. With
//! no dialog within 10 s the operation is cancelled and the extension asks for the password.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pass_agent::{
    Agent, AiDecision, AiRevealRequest, AiRunRequest, CardFillRequest, Consent, CrossFillRequest,
    ItemSecret, PasskeyChoice, PasskeyPick, Reason, Ui, UnlockAttempt, UnlockOptions, Verification,
};
use pass_core::PassError;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use crate::hello::focus::HelloFocus;
use crate::hello::policy::{FillGate, Gated};
use crate::i18n::tr;
use crate::settings::VaultEntry;
use crate::state::{lock, AppState, TotpPopup};
use crate::{hello, platform, popups, vaults};

pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// After "Cancel" in the Hello unlock prompt, other unlock requests queued behind it give up
/// instead of prompting again right away.
const CANCEL_SETTLE: Duration = Duration::from_secs(2);

/// How long Windows Hello's dialog may take to show over the browser window before it is cancelled.
const NO_DIALOG_TIMEOUT: Duration = Duration::from_secs(10);

enum HelloOutcome {
    Unlocked,
    Cancelled,
    /// Hello isn't ready or the user asked for the master password: use the main window.
    Password,
}

#[derive(Debug, PartialEq, Eq)]
enum PasskeyUnlock {
    Unlocked,
    Cancelled,
    /// No Hello dialog over Windows' dialog: the unlock prompt (Windows Hello over Passyble's
    /// prompt window, or the master password).
    Prompt,
    /// Hello failed or isn't ready (the sentence why, for a toast): the master password.
    Password(Option<String>),
}

pub struct AppUi {
    app: AppHandle,
    gate: Mutex<FillGate>,
    hello_flow: Mutex<()>,
    hello_cancelled: Mutex<Option<Instant>>,
    /// The user chose "Use master password instead": the main window doesn't start Hello by
    /// itself until the vault is unlocked.
    prefer_password: AtomicBool,
    browser_unlocks: AtomicUsize,
    /// The owner of the Windows Hello prompt such a request shows now (the key of
    /// `hello::focus::cancel`); `Some(None)` for a prompt without an owner.
    browser_unlock_owner: Mutex<Option<Option<isize>>>,
    /// The last `unlock.cancel`: every browser `unlock.hello` asked before it gives up.
    unlock_cancelled: Mutex<Option<Instant>>,
}

enum HelloOver<T> {
    Done(T),
    Cancelled,
    /// No Hello dialog showed up within [`NO_DIALOG_TIMEOUT`] (or the Hello thread died): cancelled.
    NoDialog,
}

struct Counted<'a>(&'a AtomicUsize);

impl<'a> Counted<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl AppUi {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            gate: Mutex::new(FillGate::default()),
            hello_flow: Mutex::new(()),
            hello_cancelled: Mutex::new(None),
            prefer_password: AtomicBool::new(false),
            browser_unlocks: AtomicUsize::new(0),
            browser_unlock_owner: Mutex::new(None),
            unlock_cancelled: Mutex::new(None),
        }
    }

    fn state(&self) -> Arc<AppState> {
        self.app.state::<Arc<AppState>>().inner().clone()
    }

    pub fn show_totp_popup_for(
        &self,
        item_id: &str,
        title: &str,
        target: Option<platform::Target>,
    ) {
        *lock(&self.state().totp_popup) = Some(TotpPopup {
            item_id: item_id.to_string(),
            title: title.to_string(),
            target,
        });
        crate::webview_memory::wake(&self.app, "totp");
        let _ = self.app.emit_to("totp", "totp-popup", ());
        popups::show_totp_popup(&self.app);
    }

    pub fn prefer_password(&self) -> bool {
        self.prefer_password.load(Ordering::Relaxed)
    }

    /// A new request the user started in Windows' passkey dialog: an earlier Cancel in the unlock
    /// prompt doesn't make it give up ([`CANCEL_SETTLE`]).
    pub fn forget_hello_cancel(&self) {
        *lock(&self.hello_cancelled) = None;
    }

    /// The vault was unlocked moments ago for the request now being served: that unlock counts as its
    /// user verification (so the Windows passkey provider doesn't show Hello twice). One-shot.
    pub fn take_unlock_credit(&self) -> bool {
        lock(&self.gate).take_unlock_credit(Instant::now())
    }

    /// After a Hello unlock of list entry `vault`: its "last opened" time and `note` (a toast), on a
    /// thread of their own so the request that asked for the unlock isn't held up by the disk.
    fn after_hello_unlock(&self, vault: &str, note: Option<String>) {
        let app = self.app.clone();
        let vault = vault.to_string();
        in_background(move || {
            let state = app.state::<Arc<AppState>>().inner().clone();
            vaults::mark_opened(&state, &vault);
            if let Some(note) = note {
                let _ = app.emit("toast", note);
            }
        });
    }

    fn hello_vault(&self, state: &AppState) -> Option<VaultEntry> {
        let entry = state.settings().active().cloned()?;
        (entry.windows_hello && state.hello_available.load(Ordering::Relaxed)).then_some(entry)
    }

    pub fn main_owner(&self) -> Option<isize> {
        self.app
            .get_webview_window("main")
            .and_then(|w| platform::window_handle(&w))
    }

    /// Held while a Windows Hello prompt is up, so the main window and the browser never show two at once.
    pub fn hello_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        lock(&self.hello_flow)
    }

    fn prompt_owner(&self) -> Option<isize> {
        self.app
            .get_webview_window("prompt")
            .and_then(|w| platform::window_handle(&w))
    }

    /// Runs `run` (showing Hello in front of the prompt window) on its own thread, following the prompt
    /// window: a choice there or closing it cancels Hello, and `update` hears when Hello stalls (no
    /// dialog, or not in front after 2 s) or recovers.
    fn attend<T: Send + 'static>(
        &self,
        answers: &mpsc::Receiver<Value>,
        update: &dyn Fn(HelloFocus),
        run: impl FnOnce() -> T + Send + 'static,
    ) -> Attended<T> {
        let owner = self.prompt_owner();
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("pass-hello".into())
            .spawn(move || {
                let _ = tx.send(run());
            });
        if spawned.is_err() {
            return Attended::Closed;
        }
        let mut shown = HelloFocus::Starting;
        let interrupted = loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => return Attended::Done(result),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Attended::Closed,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            match answers.try_recv() {
                Ok(answer) => break Attended::Answer(answer),
                Err(mpsc::TryRecvError::Disconnected) => break Attended::Closed,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            let focus = hello::focus::status(owner).unwrap_or(HelloFocus::Starting);
            if prompt_state(focus) != prompt_state(shown) {
                update(focus);
                if focus == HelloFocus::NotShown {
                    // No Hello dialog to cover it: the prompt's own choices come to the front.
                    popups::show_prompt(&self.app);
                }
            }
            shown = focus;
        };
        // Cancel the pending Hello operation (again, in case it only starts now) and wait briefly
        // for the thread to notice.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            hello::focus::cancel(owner);
            if rx.recv_timeout(Duration::from_millis(50)).is_ok() {
                break;
            }
        }
        interrupted
    }

    fn hello_unlock(&self, state: &AppState, agent: &Arc<Agent>) -> HelloOutcome {
        let _flow = lock(&self.hello_flow);
        if !agent.is_locked() {
            return HelloOutcome::Unlocked;
        }
        if lock(&self.hello_cancelled).is_some_and(|t| t.elapsed() < CANCEL_SETTLE) {
            return HelloOutcome::Cancelled;
        }
        if self.prefer_password() {
            return HelloOutcome::Password;
        }
        let Some(entry) = self.hello_vault(state) else {
            return HelloOutcome::Password;
        };
        if !hello::readiness(&entry.id, &entry.hello_policy).ready {
            return HelloOutcome::Password;
        }
        let data = |prompt_state: &str, error: Option<&str>| {
            json!({
                "vault_name": entry.name,
                "state": prompt_state,
                "error": error,
            })
        };
        let (id, answers) = state
            .prompts
            .open(&self.app, "unlock", data("waiting", None));
        let close = |outcome: HelloOutcome| {
            state.prompts.close(&self.app, id);
            match outcome {
                HelloOutcome::Password => self.prefer_password.store(true, Ordering::Relaxed),
                HelloOutcome::Cancelled => *lock(&self.hello_cancelled) = Some(Instant::now()),
                HelloOutcome::Unlocked => {}
            }
            outcome
        };
        let unlocked = |result: &Result<Option<String>, String>| {
            self.after_hello_unlock(&entry.id, result.as_ref().ok().cloned().flatten());
        };
        let update = |focus: HelloFocus| {
            state
                .prompts
                .update(&self.app, id, data(prompt_state(focus), None));
        };
        loop {
            let run = {
                let agent = agent.clone();
                let vault = entry.id.clone();
                let policy = entry.hello_policy;
                let owner = self.prompt_owner();
                move || hello::unlock(&agent, &vault, owner, &policy)
            };
            let result = match self.attend(&answers, &update, run) {
                Attended::Done(result) => result,
                // A choice made while Windows Hello was up (or the prompt closed with Esc).
                interrupted => {
                    if !agent.is_locked() {
                        unlocked(&Ok(None));
                        return close(HelloOutcome::Unlocked);
                    }
                    match interrupted {
                        Attended::Answer(answer) if is_retry(&answer) => {
                            state.prompts.update(&self.app, id, data("waiting", None));
                            popups::show_prompt(&self.app);
                            continue;
                        }
                        Attended::Answer(answer) => return close(answer_outcome(&answer)),
                        _ => return close(HelloOutcome::Cancelled),
                    }
                }
            };
            if !agent.is_locked() {
                unlocked(&result);
                return close(HelloOutcome::Unlocked);
            }
            let error = match result {
                Ok(_) => tr!("errors.still_locked"),
                Err(e) => e,
            };
            // The blob was discarded or the master password is due: no point in retrying.
            if !hello::readiness(&entry.id, &entry.hello_policy).ready {
                let _ = self.app.emit("toast", &error);
                return close(HelloOutcome::Password);
            }
            state
                .prompts
                .update(&self.app, id, data("failed", Some(&error)));
            match answers.recv_timeout(PROMPT_TIMEOUT) {
                Ok(answer) if is_retry(&answer) => {
                    state.prompts.update(&self.app, id, data("waiting", None));
                    popups::show_prompt(&self.app);
                }
                Ok(answer) => return close(answer_outcome(&answer)),
                Err(_) => return close(HelloOutcome::Cancelled),
            }
        }
    }

    /// The "verify" prompt window plus Windows Hello over it. Call with `hello_flow` held. `true` (and the
    /// fill gate's grace period restarted) when verified. If Hello doesn't confirm or the user picks "Use
    /// master password instead", the prompt asks for the password ([`Self::verify_with_password`]).
    fn hello_prompt(&self, state: &AppState, vault_name: &str, reason: &str) -> bool {
        let data = |prompt_state: &str, error: Option<&str>| json!({ "vault_name": vault_name, "reason": reason, "state": prompt_state, "error": error });
        let (id, answers) = state
            .prompts
            .open(&self.app, "verify", data("waiting", None));
        let update = |focus: HelloFocus| {
            state
                .prompts
                .update(&self.app, id, data(prompt_state(focus), None));
        };
        let mut wrong = 0;
        let verified = loop {
            let run = {
                let owner = self.prompt_owner();
                let reason = reason.to_string();
                move || platform::hello_verify(owner, &reason).unwrap_or(false)
            };
            let error = match self.attend(&answers, &update, run) {
                Attended::Done(true) => break true,
                // Not confirmed in Windows Hello: the master password is the other way.
                Attended::Done(false) => Some(tr!("prompt.verify_hello_failed")),
                Attended::Answer(answer) if is_retry(&answer) => {
                    state.prompts.update(&self.app, id, data("waiting", None));
                    popups::show_prompt(&self.app);
                    continue;
                }
                Attended::Answer(answer) if answer_action(&answer) == Some("password") => None,
                _ => break false,
            };
            state
                .prompts
                .update(&self.app, id, data("password", error.as_deref()));
            popups::show_prompt(&self.app);
            match self.verify_with_password(state, &answers, &mut wrong, &|error| {
                state
                    .prompts
                    .update(&self.app, id, data("password", Some(error)));
            }) {
                PasswordVerify::Verified => break true,
                PasswordVerify::Hello => {
                    state.prompts.update(&self.app, id, data("waiting", None));
                    popups::show_prompt(&self.app);
                }
                PasswordVerify::Refused => break false,
            }
        };
        state.prompts.close(&self.app, id);
        if verified {
            lock(&self.gate).verified(Instant::now());
        }
        verified
    }

    /// The verify prompt asks for the master password in Passyble's own window and checks it against the
    /// open vault. Answers: `{ action: "verify_password", password }`, `retry` (Hello again), else give up;
    /// so does the [`MAX_WRONG_PASSWORDS`]th wrong one (`wrong` counts them). `show_error` puts a sentence
    /// on the prompt.
    fn verify_with_password(
        &self,
        state: &AppState,
        answers: &mpsc::Receiver<Value>,
        wrong: &mut u32,
        show_error: &dyn Fn(&str),
    ) -> PasswordVerify {
        loop {
            let Ok(answer) = answers.recv_timeout(PROMPT_TIMEOUT) else {
                return PasswordVerify::Refused;
            };
            if is_retry(&answer) {
                return PasswordVerify::Hello;
            }
            if answer_action(&answer) != Some("verify_password") {
                return PasswordVerify::Refused;
            }
            let password = Zeroizing::new(
                answer
                    .get("password")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            drop(answer);
            if password.is_empty() || password.len() > 1024 {
                show_error(&tr!("unlock.enter_password"));
                continue;
            }
            // Not activity: the fill it stands in front of counts once it went through.
            let checked = state.quiet_vault().and_then(|vault| {
                vault
                    .check_password(password.to_string())
                    .map_err(crate::errors::friendly)
            });
            match checked {
                Ok(true) => return PasswordVerify::Verified,
                Ok(false) => {
                    *wrong += 1;
                    if *wrong >= MAX_WRONG_PASSWORDS {
                        return PasswordVerify::Refused;
                    }
                    show_error(&tr!("errors.wrong_master_password"));
                }
                Err(e) => show_error(&e),
            }
        }
    }

    /// Runs `run` (a Hello prompt, given its owner) on its own thread, owned by `owner` (the browser
    /// window, or Windows' passkey dialog), with no Passyble window; blocks until it ends. Gives up
    /// (cancelling Hello) when `cancelled` says so or no dialog shows within [`NO_DIALOG_TIMEOUT`].
    /// `unlock`: an `unlock.hello`, which `unlock.cancel` may cancel. Call with `hello_flow` held.
    fn over_window<T: Send + 'static>(
        &self,
        owner: Option<isize>,
        unlock: bool,
        cancelled: &dyn Fn() -> bool,
        run: impl FnOnce(Option<isize>) -> T + Send + 'static,
    ) -> HelloOver<T> {
        let (tx, rx) = mpsc::channel();
        let trace = pass_agent::timing::current();
        let spawned = std::thread::Builder::new()
            .name("pass-hello-browser".into())
            .spawn(move || {
                let _entered = pass_agent::timing::enter(trace);
                let _ = tx.send(run(owner));
            });
        if spawned.is_err() {
            return HelloOver::NoDialog;
        }
        if unlock {
            *lock(&self.browser_unlock_owner) = Some(owner);
        }
        let started = Instant::now();
        let mut shown = false;
        let end = loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => break HelloOver::Done(result),
                Err(mpsc::RecvTimeoutError::Disconnected) => break HelloOver::NoDialog,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            shown |= matches!(
                hello::focus::status(owner),
                Some(HelloFocus::Shown | HelloFocus::Focused | HelloFocus::Unfocused)
            );
            let interrupted = if cancelled() {
                HelloOver::Cancelled
            } else if !shown && started.elapsed() >= NO_DIALOG_TIMEOUT {
                crate::applog::plog!("Windows Hello: no dialog over the other app after 10 s");
                HelloOver::NoDialog
            } else {
                continue;
            };
            // Cancel the pending Hello operation (again, in case it only starts now) and wait
            // briefly for the thread to notice. A result arriving now is dropped: the caller
            // looks at the vault itself.
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                hello::focus::cancel(owner);
                if rx.recv_timeout(Duration::from_millis(50)).is_ok() {
                    break;
                }
            }
            break interrupted;
        };
        if unlock {
            *lock(&self.browser_unlock_owner) = None;
        }
        end
    }

    /// `unlock.hello` from the browser: Hello over the browser window that asked, no Passyble window.
    /// Blocking. `entry` passed the readiness checks.
    fn browser_hello_unlock(
        &self,
        agent: &Arc<Agent>,
        entry: &VaultEntry,
        client_pid: u32,
    ) -> UnlockAttempt {
        let asked = Instant::now();
        let _counted = Counted::new(&self.browser_unlocks);
        let _flow = lock(&self.hello_flow);
        pass_agent::timing::mark("hello: prompt slot taken");
        let cancelled = || lock(&self.unlock_cancelled).is_some_and(|t| t >= asked);
        if cancelled() {
            return UnlockAttempt::Cancelled;
        }
        if !agent.is_locked() {
            // Unlocked by another request while this one waited: the extension retries what the
            // user was doing. That unlock was the other request's check: with a grace period it
            // covers this one too, with "Every time" this fill asks.
            return UnlockAttempt::Unlocked;
        }
        let ready = || hello::readiness(&entry.id, &entry.hello_policy);
        let readiness = ready();
        if !readiness.ready {
            return UnlockAttempt::Unavailable(
                readiness
                    .note
                    .unwrap_or_else(|| tr!("errors.use_password_this_time")),
            );
        }
        let run = {
            let agent = agent.clone();
            let vault = entry.id.clone();
            let policy = entry.hello_policy;
            move |owner| hello::unlock_attempt(&agent, &vault, owner, &policy)
        };
        let owner = platform::browser_window(client_pid);
        pass_agent::timing::mark("hello: owner window found");
        let end = self.over_window(owner, true, &cancelled, run);
        if !agent.is_locked() {
            // The unlock already counts as the verification of the fill the extension sends now
            // (`notify_lock_state`); the rest doesn't hold up the answer.
            let note = match &end {
                HelloOver::Done(Ok(note)) => note.clone(),
                _ => None,
            };
            self.after_hello_unlock(&entry.id, note);
            return UnlockAttempt::Unlocked;
        }
        match end {
            HelloOver::Cancelled => UnlockAttempt::Cancelled,
            HelloOver::NoDialog => UnlockAttempt::Unavailable(tr!("errors.hello_no_dialog")),
            HelloOver::Done(Ok(_)) => UnlockAttempt::Failed(tr!("errors.still_locked")),
            HelloOver::Done(Err(failure)) if failure.cancelled => UnlockAttempt::Cancelled,
            // The blob was discarded or the master password is due: the extension asks for it.
            HelloOver::Done(Err(failure)) if !ready().ready => {
                UnlockAttempt::Unavailable(failure.message)
            }
            HelloOver::Done(Err(failure)) => UnlockAttempt::Failed(failure.message),
        }
    }

    /// Windows Hello for a user verification: over the browser window when the request came from the
    /// browser (not verified if no dialog shows within [`NO_DIALOG_TIMEOUT`]), else the "verify" prompt
    /// window ([`Self::hello_prompt`]). Call with `hello_flow` held. `true` when the user was verified.
    fn verify_now(&self, state: &AppState, vault_name: &str, reason: &str) -> bool {
        let Some(client_pid) = pass_agent::ipc::request_client_pid() else {
            return self.hello_prompt(state, vault_name, reason);
        };
        let run = {
            let reason = reason.to_string();
            move |owner| platform::hello_verify(owner, &reason).unwrap_or(false)
        };
        let owner = platform::browser_window(client_pid);
        pass_agent::timing::mark("hello: owner window found");
        let verified = matches!(
            self.over_window(owner, false, &|| false, run),
            HelloOver::Done(true)
        );
        if verified {
            lock(&self.gate).verified(Instant::now());
        }
        verified
    }

    /// The main window's unlock form, until unlocked or given up. `on_top`: kept above other
    /// windows meanwhile (Windows' passkey dialog, which waits for this unlock).
    fn password_unlock(&self, state: &AppState, agent: &Arc<Agent>, on_top: bool) -> bool {
        let (tx, rx) = mpsc::channel();
        lock(&state.unlock_waiters).push(tx);
        let _ = self.app.emit("unlock-requested", ());
        popups::show_main(&self.app);
        let main = on_top
            .then(|| self.app.get_webview_window("main"))
            .flatten();
        if let Some(window) = &main {
            let _ = window.set_always_on_top(true);
        }
        let unlocked = rx.recv_timeout(PROMPT_TIMEOUT).unwrap_or(false);
        if let Some(window) = &main {
            let _ = window.set_always_on_top(false);
        }
        // "Use master password instead" was for this request only.
        self.prefer_password.store(false, Ordering::Relaxed);
        unlocked && !agent.is_locked()
    }

    /// Unlock for a Windows passkey request, which Windows may cancel. Hello over Windows' passkey dialog
    /// first (one prompt that unlocks and counts as the user verification); when Hello can't show there,
    /// the unlock prompt as for other requests, or the master password in the main window, kept on top.
    fn passkey_unlock(&self, state: &AppState, agent: &Arc<Agent>, window: Option<isize>) -> bool {
        let started = Instant::now();
        let cancelled = crate::passkey_provider::request_cancelled;
        self.refresh_hello_available(state);
        let mut route = PasskeyUnlock::Prompt;
        if let Some(entry) = self.hello_vault(state) {
            let readiness = hello::readiness(&entry.id, &entry.hello_policy);
            route = if readiness.ready {
                self.passkey_hello_unlock(agent, &entry, window)
            } else {
                PasskeyUnlock::Password(readiness.note)
            };
        }
        let how = match route {
            PasskeyUnlock::Unlocked => "Windows Hello over Windows' dialog",
            PasskeyUnlock::Cancelled => "cancelled in Windows Hello or by Windows",
            PasskeyUnlock::Prompt if cancelled() => "cancelled by Windows",
            PasskeyUnlock::Prompt => match self.hello_unlock(state, agent) {
                HelloOutcome::Unlocked => "the unlock prompt",
                HelloOutcome::Cancelled => "cancelled in the unlock prompt",
                HelloOutcome::Password => self.passkey_password_unlock(state, agent),
            },
            PasskeyUnlock::Password(note) => {
                if let Some(note) = note {
                    let _ = self.app.emit("toast", note);
                }
                self.passkey_password_unlock(state, agent)
            }
        };
        let unlocked = !agent.is_locked();
        crate::applog::plog!(
            "passkey provider: unlock for the request {}: {how}, after {:.1} s",
            if unlocked { "done" } else { "not done" },
            started.elapsed().as_secs_f64()
        );
        unlocked
    }

    fn passkey_password_unlock(&self, state: &AppState, agent: &Arc<Agent>) -> &'static str {
        if crate::passkey_provider::request_cancelled() {
            return "cancelled by Windows";
        }
        if self.password_unlock(state, agent, true) {
            "the master password"
        } else {
            "no master password (closed, timed out or cancelled by Windows)"
        }
    }

    fn passkey_hello_unlock(
        &self,
        agent: &Arc<Agent>,
        entry: &VaultEntry,
        window: Option<isize>,
    ) -> PasskeyUnlock {
        let _flow = lock(&self.hello_flow);
        if !agent.is_locked() {
            return PasskeyUnlock::Unlocked;
        }
        let run = {
            let agent = agent.clone();
            let vault = entry.id.clone();
            let policy = entry.hello_policy;
            move |owner| hello::unlock_attempt(&agent, &vault, owner, &policy)
        };
        let end = self.over_window(
            window,
            false,
            &crate::passkey_provider::request_cancelled,
            run,
        );
        if !agent.is_locked() {
            let note = match &end {
                HelloOver::Done(Ok(note)) => note.clone(),
                _ => None,
            };
            self.after_hello_unlock(&entry.id, note);
            return PasskeyUnlock::Unlocked;
        }
        still_locked_after(end)
    }

    /// `hello_available` is checked on a thread at start-up (main.rs); a request that arrives before
    /// that checks now, for a vault with Windows Hello turned on.
    fn refresh_hello_available(&self, state: &AppState) {
        if state.hello_available.load(Ordering::Relaxed)
            || !state.settings().active().is_some_and(|e| e.windows_hello)
        {
            return;
        }
        if platform::hello_available() {
            state.hello_available.store(true, Ordering::Relaxed);
            let _ = self.app.emit("hello-available", ());
        }
    }

    /// [`Ui::verify_user`] with the prompt's line as text (`reason`); also for the app's own fills.
    pub fn verify(&self, reason: &str) -> Verification {
        self.verify_gated(reason, Gated::Other)
    }

    /// [`AppUi::verify`] for `what` ([`FillGate::without_prompt_for`]: with "Every time" an unlock
    /// counts only for the login it was asked for, and a confirmed login's 2FA codes follow).
    fn verify_gated(&self, reason: &str, what: Gated<'_>) -> Verification {
        let state = self.state();
        // An unlock (Windows Hello or master password) that this very request asked for is a
        // real verification: it counts as one even without the per-fill policy (WebAuthn UV).
        let policy = self
            .hello_vault(&state)
            .filter(|e| e.hello_policy.verify_each_fill);
        let Some(entry) = policy else {
            pass_agent::timing::mark("verify: no per-fill policy");
            return if lock(&self.gate).take_unlock_credit(Instant::now()) {
                Verification::Verified
            } else {
                Verification::Allowed
            };
        };
        let grace = entry.hello_policy.grace();
        // Within the grace period nothing is verified now: allowed, but no UV flag.
        let skip = |gate: &mut FillGate| {
            gate.without_prompt_for(Instant::now(), grace, what)
                .map(|verified| {
                    if verified {
                        Verification::Verified
                    } else {
                        Verification::Allowed
                    }
                })
        };
        if let Some(outcome) = skip(&mut lock(&self.gate)) {
            pass_agent::timing::mark("verify: no Windows Hello needed (grace period or unlock)");
            return outcome;
        }
        pass_agent::timing::mark("verify: hello needed");
        let _flow = lock(&self.hello_flow);
        // The unlock this request waited for (it holds the prompt slot until it is done), or,
        // within the grace period, another request's verification, may have come meanwhile.
        if let Some(outcome) = skip(&mut lock(&self.gate)) {
            return outcome;
        }
        let verified = self.verify_now(&state, &entry.name, reason);
        pass_agent::timing::mark("verify: done");
        if !verified {
            return Verification::Refused;
        }
        if let Gated::Password(item) = what {
            lock(&self.gate).filled(Instant::now(), item);
        }
        Verification::Verified
    }

    /// [`Ui::require_verification`] with the prompt's line as text. A site demands user verification:
    /// only Windows Hello (or the unlock this request just triggered) counts, whatever the per-fill
    /// policy says, and the grace period doesn't apply. `Refused` when Hello isn't set up or the user
    /// declines; the agent then answers `not_supported` and the extension falls back to the browser.
    fn require_verified(&self, reason: &str) -> Verification {
        let state = self.state();
        if lock(&self.gate).take_unlock_credit(Instant::now()) {
            pass_agent::timing::mark("verify: required, the unlock counts");
            return Verification::Verified;
        }
        if !state.hello_available.load(Ordering::Relaxed) {
            pass_agent::timing::mark("verify: required, no Windows Hello");
            return Verification::Refused;
        }
        pass_agent::timing::mark("verify: required, hello needed");
        let _flow = lock(&self.hello_flow);
        if lock(&self.gate).take_unlock_credit(Instant::now()) {
            return Verification::Verified;
        }
        let vault_name = state
            .settings()
            .active()
            .map(|e| e.name.clone())
            .unwrap_or_default();
        let verified = self.verify_now(&state, &vault_name, reason);
        pass_agent::timing::mark("verify: done");
        if verified {
            Verification::Verified
        } else {
            Verification::Refused
        }
    }
}

impl AppUi {
    /// Confirms the user after a yes to an AI tool's request (Settings → AI tools) in the prompt window:
    /// Windows Hello (master password as the other way) where available, else the master password. `true`
    /// when confirmed. Not shown over the browser: these requests come from the connector.
    fn verify_for_ai(&self, reason: &str) -> bool {
        let state = self.state();
        let _flow = lock(&self.hello_flow);
        let vault_name = state
            .settings()
            .active()
            .map(|e| e.name.clone())
            .unwrap_or_default();
        if state.hello_available.load(Ordering::Relaxed) {
            return self.hello_prompt(&state, &vault_name, reason);
        }
        let data = |error: Option<&str>| json!({ "vault_name": vault_name, "reason": reason, "state": "password", "error": error });
        let (id, answers) = state.prompts.open(&self.app, "verify", data(None));
        let mut wrong = 0;
        let verified = loop {
            match self.verify_with_password(&state, &answers, &mut wrong, &|error| {
                state.prompts.update(&self.app, id, data(Some(error)));
            }) {
                PasswordVerify::Verified => break true,
                PasswordVerify::Hello => continue,
                PasswordVerify::Refused => break false,
            }
        };
        state.prompts.close(&self.app, id);
        verified
    }

    /// The "Sign in with a passkey" prompt window. `elsewhere`: it also offers "Use another
    /// device" (a request from the browser, which can take over).
    fn ask_passkey(&self, rp_id: &str, options: &[PasskeyChoice], elsewhere: bool) -> PasskeyPick {
        let list: Vec<Value> = options
            .iter()
            .map(|o| json!({ "item_id": o.item_id, "title": o.title, "user_name": o.user_name }))
            .collect();
        let answer = self.state().prompts.ask(
            &self.app,
            "passkey-choose",
            json!({
                "rp_id": rp_id, "options": list, "site": crate::site_icons::host_site(rp_id),
                "elsewhere": elsewhere,
            }),
            PROMPT_TIMEOUT,
        );
        passkey_pick(answer.as_ref(), options.len(), elsewhere)
    }
}

/// The prompt window's answer to "passkey-choose": `{ index }`, `{ elsewhere: true }` (only when
/// offered), anything else (closed, timed out) is Cancelled.
fn passkey_pick(answer: Option<&Value>, options: usize, elsewhere: bool) -> PasskeyPick {
    let Some(answer) = answer else {
        return PasskeyPick::Cancelled;
    };
    if elsewhere && answer.get("elsewhere").and_then(Value::as_bool) == Some(true) {
        return PasskeyPick::Elsewhere;
    }
    match answer.get("index").and_then(Value::as_u64) {
        Some(index) if (index as usize) < options => PasskeyPick::Chosen(index as usize),
        _ => PasskeyPick::Cancelled,
    }
}

fn still_locked_after(
    end: HelloOver<Result<Option<String>, hello::UnlockFailure>>,
) -> PasskeyUnlock {
    match end {
        HelloOver::Cancelled => PasskeyUnlock::Cancelled,
        HelloOver::Done(Err(failure)) if failure.cancelled => PasskeyUnlock::Cancelled,
        HelloOver::NoDialog => PasskeyUnlock::Prompt,
        HelloOver::Done(Err(failure)) => PasskeyUnlock::Password(Some(failure.message)),
        HelloOver::Done(Ok(_)) => PasskeyUnlock::Password(Some(tr!("errors.still_locked"))),
    }
}

fn in_background(work: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new()
        .name("pass-after-unlock".into())
        .spawn(work)
    {
        crate::applog::plog!("after unlock: no thread: {e}");
    }
}

fn reason_text(reason: &Reason) -> String {
    match reason {
        Reason::FillLogin { title } => tr!("reason.fill_login", title = title),
        Reason::FillLoginInto { title, host } => {
            tr!("reason.fill_login_into", title = title, host = host)
        }
        Reason::UseCode { title } => tr!("reason.use_code", title = title),
        Reason::CopyPassword { title } => tr!("reason.copy_password", title = title),
        Reason::CopyCode { title } => tr!("reason.copy_code", title = title),
        Reason::EditLogin { title } => tr!("reason.edit_login", title = title),
        Reason::SaveChanges { title } => tr!("reason.save_changes", title = title),
        Reason::AddLogin { site } => tr!("reason.add_login", site = site),
        Reason::DeleteLogin { title } => tr!("reason.delete_login", title = title),
        Reason::ChangeCode { title } => tr!("reason.change_code", title = title),
        Reason::FillCard { title, host } => tr!("reason.fill_card", title = title, host = host),
        Reason::CopyCard { title } => tr!("reason.copy_card", title = title),
        Reason::ShowNote { title } => tr!("reason.show_note", title = title),
        Reason::CopyNote { title } => tr!("reason.copy_note", title = title),
        Reason::SavePasskey { site } => tr!("reason.save_passkey", site = site),
        Reason::PasskeySignIn { site } => tr!("reason.passkey_sign_in", site = site),
    }
}

enum PasswordVerify {
    Verified,
    Hello,
    Refused,
}

/// Wrong master passwords one verify prompt takes before it gives up (the vault is open, so this
/// only slows down guessing by someone at the unlocked PC; each try costs a full key derivation).
const MAX_WRONG_PASSWORDS: u32 = 5;

enum Attended<T> {
    Done(T),
    Answer(Value),
    Closed,
}

/// The `lock-state` event (windows) and `lock_state` notification (browser extension):
/// `{ locked, soft }`, `soft` meaning locked with the list of items kept (never while unlocked).
pub(crate) fn lock_state_payload(locked: bool, soft: bool) -> Value {
    json!({ "locked": locked, "soft": locked && soft })
}

fn prompt_state(focus: HelloFocus) -> &'static str {
    match focus {
        HelloFocus::NotShown => "stalled",
        HelloFocus::Unfocused => "unfocused",
        HelloFocus::Starting | HelloFocus::Shown | HelloFocus::Focused => "waiting",
    }
}

fn answer_action(answer: &Value) -> Option<&str> {
    answer.get("action").and_then(Value::as_str)
}

fn is_retry(answer: &Value) -> bool {
    answer_action(answer) == Some("retry")
}

fn answer_outcome(answer: &Value) -> HelloOutcome {
    match answer.get("action").and_then(Value::as_str) {
        Some("password") => HelloOutcome::Password,
        _ => HelloOutcome::Cancelled,
    }
}

impl Ui for AppUi {
    fn request_unlock(&self) -> bool {
        let state = self.state();
        let Some(agent) = state.agent() else {
            popups::show_main(&self.app);
            return false;
        };
        if !agent.is_locked() {
            return true;
        }
        // An unlock here counts as the verification of the request being served: the fill gate
        // got it as the vault opened (`notify_lock_state`), before anyone could fill.
        if let Some(request) = crate::passkey_provider::current_request() {
            return self.passkey_unlock(&state, &agent, request.window);
        }
        match self.hello_unlock(&state, &agent) {
            HelloOutcome::Unlocked => true,
            HelloOutcome::Cancelled => false,
            HelloOutcome::Password => self.password_unlock(&state, &agent, false),
        }
    }

    fn unlock_options(&self) -> UnlockOptions {
        let state = self.state();
        let hello = self
            .hello_vault(&state)
            .is_some_and(|e| hello::readiness(&e.id, &e.hello_policy).ready);
        UnlockOptions { hello }
    }

    fn unlock_with_password(&self, password: &str) -> Option<UnlockAttempt> {
        let state = self.state();
        let (Some(agent), Ok(id)) = (state.agent(), vaults::active_id(&state)) else {
            return Some(UnlockAttempt::Failed(tr!("errors.set_up_vault_first")));
        };
        if !agent.is_locked() {
            return Some(UnlockAttempt::Unlocked);
        }
        match agent.unlock(password) {
            Ok(()) => {}
            // A Passyble Server vault whose password was changed on another device.
            Err(PassError::InvalidPassword)
                if crate::signin::refresh_from_server(&self.app, &agent, &id, password) => {}
            Err(PassError::InvalidPassword) => return Some(UnlockAttempt::WrongPassword),
            Err(e) => return Some(UnlockAttempt::Failed(crate::errors::friendly(e))),
        }
        // The extension fills right after this answer, and the unlock already counts as that fill's
        // verification (`notify_lock_state`). Bookkeeping (the Hello file, which may set Hello up with its own
        // prompt; "last opened"; Password health's master password tip, a zeroized copy) doesn't hold it up.
        let app = self.app.clone();
        let typed = zeroize::Zeroizing::new(password.to_string());
        in_background(move || {
            let state = app.state::<Arc<AppState>>().inner().clone();
            crate::health::note_master_password_unlock(&state, &id, &typed);
            drop(typed);
            let result = crate::commands::after_password_unlock(&state, &agent, &id);
            if let Some(warning) = result["warning"].as_str() {
                let _ = app.emit("toast", warning);
            }
        });
        Some(UnlockAttempt::Unlocked)
    }

    /// "Use Windows Hello" in the extension's unlock form (or a login picked while locked): Hello over the
    /// browser window that asked, no Passyble window. Outside an IPC request it uses the prompt window.
    fn unlock_with_hello(&self) -> UnlockAttempt {
        pass_agent::timing::mark("hello: request received");
        let state = self.state();
        let Some(agent) = state.agent() else {
            return UnlockAttempt::Failed(tr!("errors.set_up_vault_first"));
        };
        if !agent.is_locked() {
            return UnlockAttempt::Unlocked;
        }
        let Some(entry) = self.hello_vault(&state) else {
            return UnlockAttempt::Unavailable(tr!("errors.hello_off_use_password"));
        };
        let readiness = hello::readiness(&entry.id, &entry.hello_policy);
        pass_agent::timing::mark("hello: availability checked");
        if !readiness.ready {
            return UnlockAttempt::Unavailable(
                readiness
                    .note
                    .unwrap_or_else(|| tr!("errors.use_password_this_time")),
            );
        }
        // The user asked for Windows Hello just now: an earlier "Use master password instead" or
        // Cancel doesn't stand in the way.
        self.prefer_password.store(false, Ordering::Relaxed);
        *lock(&self.hello_cancelled) = None;
        if let Some(client_pid) = pass_agent::ipc::request_client_pid() {
            return self.browser_hello_unlock(&agent, &entry, client_pid);
        }
        match self.hello_unlock(&state, &agent) {
            HelloOutcome::Unlocked => UnlockAttempt::Unlocked,
            HelloOutcome::Cancelled => UnlockAttempt::Cancelled,
            HelloOutcome::Password => {
                // "Use master password instead": the extension's form has the field.
                self.prefer_password.store(false, Ordering::Relaxed);
                UnlockAttempt::Unavailable(tr!("errors.use_password"))
            }
        }
    }

    /// "Use master password instead" in the browser while `unlock.hello` is pending: cancels its Hello
    /// prompt and any `unlock.hello` waiting for its turn; they answer `cancelled`.
    fn cancel_unlock(&self) -> bool {
        if self.browser_unlocks.load(Ordering::SeqCst) == 0 {
            return false;
        }
        *lock(&self.unlock_cancelled) = Some(Instant::now());
        if let Some(owner) = *lock(&self.browser_unlock_owner) {
            hello::focus::cancel(owner);
        }
        true
    }

    fn hello_in_browser(&self) -> bool {
        cfg!(windows)
    }

    /// The extension asked for logins: a Google Drive vault checks for other devices' changes if
    /// the last check is over 20 s old (background.rs). Doesn't wait.
    fn logins_requested(&self) {
        crate::background::logins_requested(&self.app);
    }

    /// `support.link`: `passyble://support` opens Help and support here (the extension uses it while connected).
    fn host_features(&self) -> &'static [&'static str] {
        &["support.link"]
    }

    fn verify_user(&self, reason: &Reason) -> Verification {
        self.verify(&reason_text(reason))
    }

    fn verify_item(&self, reason: &Reason, item_id: &str, secret: ItemSecret) -> Verification {
        let state = self.state();
        let every_time = self
            .hello_vault(&state)
            .is_some_and(|e| e.hello_policy.verify_each_fill && e.hello_policy.grace().is_zero());
        let what = match secret {
            ItemSecret::Password => Gated::Password(item_id),
            // The code the next page asks for, of the login just filled on this site: it goes
            // through without asking, except with "Every time", where the gate decides
            // (`OTP_AFTER_FILL`).
            ItemSecret::Code { follows_fill: true } if !every_time => return Verification::Allowed,
            ItemSecret::Code { .. } => Gated::Code(item_id),
            ItemSecret::Passkey => Gated::Passkey(item_id),
        };
        self.verify_gated(&reason_text(reason), what)
    }

    fn require_verification(&self, reason: &Reason) -> Verification {
        self.require_verified(&reason_text(reason))
    }

    fn confirm_passkey_create(&self, rp_id: &str, user_name: &str) -> Consent {
        let candidates: Vec<Value> = self
            .state()
            .agent()
            .and_then(|a| a.peek_vault())
            .map(|v| v.find_for_url(format!("https://{rp_id}")))
            .unwrap_or_default()
            .into_iter()
            .map(|i| json!({ "id": i.id, "title": i.title, "username": i.username }))
            .collect();
        let candidate_ids: Vec<String> = candidates
            .iter()
            .filter_map(|c| c["id"].as_str().map(str::to_string))
            .collect();
        let answer = self.state().prompts.ask(
            &self.app,
            "passkey-create",
            json!({ "rp_id": rp_id, "user_name": user_name, "candidates": candidates }),
            PROMPT_TIMEOUT,
        );
        match answer {
            Some(a) if a.get("approve").and_then(Value::as_bool) == Some(true) => {
                let item_id = a
                    .get("item_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                // The window may only attach the passkey to one of the logins it was offered
                // (or to a new one), never to an unrelated item.
                if item_id
                    .as_ref()
                    .is_some_and(|id| !candidate_ids.contains(id))
                {
                    return Consent::Deny;
                }
                Consent::Approve { item_id }
            }
            _ => Consent::Deny,
        }
    }

    fn choose_passkey(&self, rp_id: &str, options: &[PasskeyChoice]) -> Option<usize> {
        match self.ask_passkey(rp_id, options, false) {
            PasskeyPick::Chosen(index) => Some(index),
            PasskeyPick::Elsewhere | PasskeyPick::Cancelled => None,
        }
    }

    fn choose_passkey_for_browser(&self, rp_id: &str, options: &[PasskeyChoice]) -> PasskeyPick {
        // A page's own request in the browser: "Use another device" hands it to the browser's
        // own WebAuthn (a phone, a security key, the browser's passkeys).
        self.ask_passkey(rp_id, options, true)
    }

    fn show_totp_popup(&self, item_id: &str, title: &str) {
        // Called for the browser: the browser window has focus, so "Type it" types there.
        self.show_totp_popup_for(item_id, title, platform::foreground_window());
    }

    fn show_server_pairing(&self, link: &str) -> bool {
        // The main window takes the link with `server_pair_take` and shows the "Connect to Pass
        // Server" dialog; nothing is stored until the user confirms there.
        *lock(&self.state().server_pair) = Some(link.to_string());
        let _ = self.app.emit_to("main", "server-pair-requested", ());
        popups::show_main(&self.app);
        true
    }

    fn vault_changed(&self) {
        // A login or passkey changed from the browser: Windows' list of Passyble passkeys is updated too.
        let _ = self.app.emit("vault-changed", ());
        crate::passkey_provider::kick_sync();
    }

    fn vault_name(&self) -> Option<String> {
        let settings = self.state().settings();
        if settings.vaults.len() < 2 {
            return None;
        }
        settings.active().map(|e| e.name.clone())
    }

    fn credential_used(&self) {
        // "Require Windows Hello before each fill": a use within the grace period starts it again
        // (sliding, capped at the chosen minutes); once it has run out, the next fill asks.
        let state = self.state();
        let Some(entry) = self
            .hello_vault(&state)
            .filter(|e| e.hello_policy.verify_each_fill)
        else {
            return;
        };
        lock(&self.gate).used(Instant::now(), entry.hello_policy.grace());
    }

    fn show_item(&self, item_id: &str) -> bool {
        // "Open in Passyble" from the extension popup: the main window opens that item when it
        // handles `show-item` (payload `{ id }`); it is brought up either way.
        let _ = self
            .app
            .emit_to("main", "show-item", json!({ "id": item_id }));
        popups::open_main(&self.app);
        true
    }

    fn own_vaults(&self) -> Option<Vec<pass_agent::OwnVault>> {
        let settings = self.state().settings();
        Some(
            settings
                .vaults
                .iter()
                .map(|v| pass_agent::OwnVault {
                    id: v.id.clone(),
                    vault_id: v.vault_id.clone(),
                    name: v.name.clone(),
                    location: v.location(),
                    active: settings.active_vault.as_deref() == Some(v.id.as_str()),
                })
                .collect(),
        )
    }

    fn switch_vault(&self, id: &str) -> Option<bool> {
        let state = self.state();
        if state.settings().vault(id).is_none() {
            return Some(false);
        }
        let unlocked = state.agent().is_some_and(|a| !a.is_locked());
        let app = self.app.clone();
        let id = id.to_string();
        // Off the agent's request thread: switching a locked vault reconfigures the agent.
        std::thread::spawn(move || {
            if unlocked {
                // The vault view's own "Switch vault": the other vault's unlock over this one,
                // which stays open until then (vault.js `switchTo`).
                let _ = app.emit_to("main", "switch-vault", json!({ "id": id }));
                popups::show_main(&app);
            } else if vaults::activate(&app, &id).is_ok() {
                let _ = app.emit_to("main", "switch-vault", json!({ "id": id }));
                popups::open_main(&app);
            }
        });
        Some(true)
    }

    fn teams_summary(&self) -> Option<pass_agent::TeamsSummary> {
        crate::teams::summary(&self.app)
    }

    fn password_policy(&self) -> Option<pass_agent::PasswordPolicy> {
        crate::password_mode::rule(&self.app).agent_policy()
    }

    fn show_teams(&self, section: &str) -> bool {
        crate::tray::show_teams(&self.app, section);
        true
    }

    fn account_summary(&self) -> Option<pass_agent::AccountSummary> {
        // `settings.json` only (no token, no credential store): answers locked and offline too.
        let account = crate::account::signed_in(&self.app);
        Some(pass_agent::AccountSummary {
            signed_in: account.is_some(),
            email: account.map(|a| a.email),
        })
    }

    fn show_account(&self, sign_in: bool) -> bool {
        crate::account::show_from_extension(&self.app, sign_in);
        true
    }

    // The same-computer sign-in handoff with the browser extension in browser mode (account.rs):
    // locked or not, no prompt; the outcomes are toasts.

    fn account_peer(&self) -> Option<pass_agent::AccountPeer> {
        Some(crate::account::peer_for_extension(&self.app))
    }

    fn handoff_to_extension(
        &self,
        code_challenge: &str,
        device_name: &str,
    ) -> Result<pass_agent::HandoffCode, pass_agent::AccountError> {
        crate::account::hand_to_extension(&self.app, code_challenge, device_name)
    }

    fn handoff_begin(&self) -> Result<pass_agent::HandoffRequest, pass_agent::AccountError> {
        crate::account::begin_from_extension(&self.app)
    }

    fn handoff_finish(&self, code: &str) -> Result<String, pass_agent::AccountError> {
        crate::account::finish_from_extension(&self.app, code)
    }

    fn sign_out_from_extension(&self) -> Result<(), pass_agent::AccountError> {
        crate::account::sign_out_from_extension(&self.app)
    }

    fn peer_signed_out(&self) -> Result<(), pass_agent::AccountError> {
        crate::account::extension_signed_out(&self.app)
    }

    fn sync_now(&self) -> Option<pass_agent::SyncReport> {
        Some(crate::background::sync_all(&self.app).0)
    }

    fn copy_to_clipboard(&self, text: &str) -> bool {
        // `logins.copy` from the extension popup's vault search, `generate.copy`: copied as a
        // secret (cleared after 45 s, kept out of clipboard history and the cloud clipboard).
        crate::clipboard::copy_secret(text).is_ok()
    }

    fn confirm_cross_fill(&self, request: &CrossFillRequest) -> Option<bool> {
        // `logins.fill_cross`: "Fill a login from another site?" in the prompt window; closing it or the timeout is "no".
        let answer = self.state().prompts.ask(
            &self.app,
            "fill-cross",
            json!({
                "title": request.title,
                "username": request.username,
                "item_domain": request.item_domain,
                "page_host": request.page_host,
                "site": crate::site_icons::host_site(&request.item_domain),
                // The page looks like the login's site without being it: a stronger warning, and
                // Cancel stays the default.
                "lookalike": request.lookalike.as_ref().map(|l| json!({
                    "domain": l.domain, "host": l.host, "reason": l.reason.as_str(),
                })),
            }),
            PROMPT_TIMEOUT,
        );
        Some(answer.and_then(|a| a.get("approve").and_then(Value::as_bool)) == Some(true))
    }

    fn confirm_card_fill(&self, request: &CardFillRequest) -> Option<bool> {
        // Payment card fill or copy: "Fill <card> on <host>?" in the prompt window, Cancel the default; closing it or the timeout is "no".
        let answer = self.state().prompts.ask(
            &self.app,
            "fill-card",
            json!({
                "title": request.title,
                "brand": request.brand,
                "brand_name": pass_core::card_brand_name(request.brand.clone()),
                "last4": request.last4,
                "page_host": request.page_host,
                "top_host": request.top_host,
                "copy": request.copy,
            }),
            PROMPT_TIMEOUT,
        );
        Some(answer.and_then(|a| a.get("approve").and_then(Value::as_bool)) == Some(true))
    }

    fn confirm_ai_run(&self, request: &AiRunRequest) -> Option<AiDecision> {
        // An AI tool wants to run a command with secrets in its environment: Deny (the default), Allow once
        // or Allow until the vault locks. Closing it or the 2-minute timeout counts as Deny.
        let state = self.state();
        let answer = state.prompts.ask(
            &self.app,
            "ai-run",
            crate::ai_tools::run_prompt_data(request),
            PROMPT_TIMEOUT,
        );
        let decision = crate::ai_tools::run_decision(answer.as_ref());
        if decision == AiDecision::Deny {
            return Some(AiDecision::Deny);
        }
        // The vault's "Require Windows Hello before each fill" covers AI tools too.
        let policy = self
            .hello_vault(&state)
            .is_some_and(|e| e.hello_policy.verify_each_fill);
        if policy && !self.verify_for_ai(&tr!("reason.ai_run", client = request.client.label())) {
            return Some(AiDecision::Deny);
        }
        Some(decision)
    }

    fn confirm_ai_reveal(&self, request: &AiRevealRequest) -> Option<bool> {
        // Every single time, with the warning that the value goes into the AI chat and to the AI
        // provider; then Windows Hello or the master password.
        let answer = self.state().prompts.ask(
            &self.app,
            "ai-reveal",
            crate::ai_tools::reveal_prompt_data(request),
            PROMPT_TIMEOUT,
        );
        if !crate::ai_tools::reveal_approved(answer.as_ref()) {
            return Some(false);
        }
        Some(self.verify_for_ai(&tr!(
            "reason.ai_reveal",
            field = request.field,
            title = request.item_title
        )))
    }

    fn ai_activity(&self) {
        let _ = self.app.emit_to("main", "ai-activity", ());
    }

    fn ai_allows_vault(&self, vault: &pass_agent::VaultRef) -> bool {
        crate::ai_tools::vault_allowed(&self.app, vault)
    }

    /// Also called for a soft lock (list kept) and soft to full (list dropped); `soft` in the payload says
    /// which. Either way every secret shown anywhere goes (TOTP popup, quick-pick, import preview, undo
    /// copies); the main window keeps the list only for a soft lock.
    fn notify_lock_state(&self, locked: bool) {
        let state = self.state();
        if !locked {
            // The shared vaults' list, keys and notifications (`teams_vaults.rs`), in the
            // background: only for a Passyble account or a Passyble Server vault.
            crate::teams_vaults::refresh_soon(&self.app);
            // The Passyble account's key: a reset another device started, a changed key, a Team that requires
            // admin recovery (account_keys/reset.rs).
            crate::account_keys::reset::watch_soon(&self.app);
            // Emergency access for the account: this vault's grants, if missing or stale.
            crate::teams_send::renew_soon(&self.app);
            // An unlock with Windows Hello or the master password counts as a user verification, recorded before
            // the windows and the extension hear of it, so the fill the extension sends at once never asks for
            // Hello again: within the per-fill grace period, and once (`hello::policy::UNLOCK_CREDIT`) with
            // "Every time" too, only for the login the unlock was asked for (`for`).
            let for_item = state.agent().and_then(|a| a.unlock_requested_for());
            lock(&self.gate).unlocked(Instant::now(), for_item);
        }
        // The agent calls this without holding its own state lock.
        let soft = locked && state.agent().is_some_and(|a| a.is_soft_locked());
        let payload = lock_state_payload(locked, soft);
        // Neither a lock (auto-lock, Win+L, sleep, a full lock) nor an unlock is the user asking
        // for Windows Hello: a window opened earlier doesn't start it on the unlock screen now.
        lock(&state.auto_hello).clear();
        let _ = self.app.emit("lock-state", payload.clone());
        // A main window hidden in the tray rests deeper once it has cleared itself.
        crate::webview_memory::set_locked(&self.app, locked);
        if let Some(server) = state.server.get() {
            server.notify("lock_state", payload);
        }
        if locked {
            // The Passyble account's key goes with the vault key (account_keys.rs).
            crate::account_keys::forget_held();
            *lock(&state.totp_popup) = None;
            *lock(&state.quickpick) = None;
            lock(&self.gate).reset();
            crate::import::clear_all();
            crate::screen_qr::clear();
            crate::undo::clear_items();
            crate::site_icons::on_lock(&state);
            // A running breach check stops ("The vault locked"); finished results go.
            crate::health::on_lock(&self.app);
            popups::hide(&self.app, "totp");
            popups::hide(&self.app, "quickpick");
            popups::hide(&self.app, "quickaccess");
            popups::hide(&self.app, "qrscan");
        } else {
            self.prefer_password.store(false, Ordering::Relaxed);
            state.resolve_unlock_waiters(true);
            state.kick_sync();
        }
        crate::tray::update(&self.app, locked, soft);
    }
}

#[cfg(test)]
mod tests {
    use super::{lock_state_payload, passkey_pick, still_locked_after, HelloOver, PasskeyUnlock};
    use pass_agent::PasskeyPick;
    use serde_json::json;

    #[test]
    fn a_passkey_unlock_left_locked_cancels_quietly_or_falls_back() {
        let failure = |cancelled| {
            HelloOver::Done(Err(crate::hello::UnlockFailure {
                message: "Windows Hello failed".into(),
                cancelled,
            }))
        };
        // Windows cancelled the request, or the user cancelled Windows Hello: no other prompt.
        assert_eq!(
            still_locked_after(HelloOver::Cancelled),
            PasskeyUnlock::Cancelled
        );
        assert_eq!(still_locked_after(failure(true)), PasskeyUnlock::Cancelled);
        assert_eq!(
            still_locked_after(HelloOver::NoDialog),
            PasskeyUnlock::Prompt
        );
        assert_eq!(
            still_locked_after(failure(false)),
            PasskeyUnlock::Password(Some("Windows Hello failed".into()))
        );
        assert!(matches!(
            still_locked_after(HelloOver::Done(Ok(None))),
            PasskeyUnlock::Password(Some(_))
        ));
    }

    #[test]
    fn the_passkey_prompt_answers() {
        let pick = |answer: serde_json::Value, elsewhere| passkey_pick(Some(&answer), 2, elsewhere);
        assert_eq!(pick(json!({ "index": 1 }), true), PasskeyPick::Chosen(1));
        assert_eq!(pick(json!({ "index": 2 }), true), PasskeyPick::Cancelled);
        assert_eq!(
            pick(json!({ "elsewhere": true }), true),
            PasskeyPick::Elsewhere
        );
        // Not offered (the Windows passkey provider): no way out to "another device".
        assert_eq!(
            pick(json!({ "elsewhere": true }), false),
            PasskeyPick::Cancelled
        );
        assert_eq!(pick(json!(null), true), PasskeyPick::Cancelled);
        assert_eq!(passkey_pick(None, 2, true), PasskeyPick::Cancelled);
    }

    #[test]
    fn lock_state_says_whether_the_list_is_kept() {
        assert_eq!(
            lock_state_payload(true, true),
            json!({ "locked": true, "soft": true })
        );
        assert_eq!(
            lock_state_payload(true, false),
            json!({ "locked": true, "soft": false })
        );
        // Never soft while unlocked.
        assert_eq!(
            lock_state_payload(false, true),
            json!({ "locked": false, "soft": false })
        );
    }
}
