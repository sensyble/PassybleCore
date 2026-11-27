# pass-native-host

The browser starts this tiny relay through Native Messaging (`com.sensyble.pass`). It forwards each
message to the desktop agent's local socket and passes back responses and events. It holds no secrets.
When the app isn't running it tries to start `Pass.exe --background` (from its own folder) once and waits
up to ~15 s for it. If that fails it answers `agent_unavailable`, but tries to connect again before each
request (without starting the app again), so it works as soon as Passyble is up.

The credentials it relays do pass through its memory, so a release build hardens itself first thing
(`pass_agent::harden`, as the app does): no crash dumps, and on Windows a process DACL that keeps the
user's other programs from reading its memory (macOS: `PT_DENY_ATTACH`). The browser ends it through the
handle it got when starting it, which the DACL doesn't affect.

The app it starts must outlive the host, which the browser ends when it closes the port (an idle MV3
service worker does after ~30 s). So it gets null stdin / stdout / stderr (the host's own are the native
messaging pipes), its own process group, and on Windows `CREATE_BREAKAWAY_FROM_JOB`, so that a browser
running in a job object (started by a launcher or a sandboxing tool) doesn't take Pass down with the host.
A job that doesn't allow breakaway refuses that flag (access denied); then Pass is started without it.

On Windows, before relaying each request, it calls `AllowSetForegroundWindow` for the agent's process
(from `GetNamedPipeServerProcessId`). The browser that started the host is the foreground app, so this
lets Pass bring its unlock or passkey window to the front instead of only flashing in the taskbar.

The agent only accepts pipe connections from this exe when it sits beside `Pass.exe`, and the host only
talks to a pipe served by that `Pass.exe` (a pipe created first by another program or user is refused
and reported as `agent_unavailable`; see `Core/agent/README.md`), so the host must stay in the
install folder.

Registration (done by the desktop app on first run, see `Core/desktop-app/README.md`): a manifest
`com.sensyble.pass.json` with `"type": "stdio"`, the path to this exe and the extension's
`allowed_origins`, referenced from `HKCU\Software\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave-Browser,Chromium,Mozilla}\NativeMessagingHosts\com.sensyble.pass`.
