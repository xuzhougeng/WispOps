# CLAUDE.md

WispOps is an AI-native server operations desktop app in Rust with GPUI, ported from the dsh-wisp-ops plugin (logic) and Wisp Paper (agent plumbing and UI idiom). UI strings are Chinese keys looked up through `i18n::t` (`locales/en.json`); dynamic text uses `tf!` with both literals. Code comments are in English.

## Commands

```sh
cargo run --features runtime_shaders          # this machine has no Metal Toolchain
cargo test --features runtime_shaders         # all five crates
cargo test -p wisp_ops_engine                 # engine only, no GPUI build
cargo clippy --features runtime_shaders --all-targets   # expected to be warning-free
```

- The toolchain is pinned in `rust-toolchain.toml` (as in Wisp Paper); do not run `cargo fmt` on the root crate, `crates/core` or `crates/net` (hand-formatted, long lines, as in Wisp Paper).
- `WISP_OPS_HOME=<dir>` holds data and settings; `WISP_OPS_VAULT_KEY=file` keeps the vault key beside the vault instead of the keychain. Use both for any manual or scripted run.
- Debug builds script the window: `WISP_OPS_DEV="page:servers,2@shot:/tmp/a.png,3@quit"` (steps in `dev_step` at the end of `src/app.rs`; `shot:` renders off-screen to a PNG). The assistant is put away at start unless it was left docked (a round button at the bottom right): `assistant` opens it, `dock:on`/`dock:off` stands it beside the pages or floats it, `history` shows the kept conversations. `close` presses the window's close button through the system and `hidden` prints what became of the program (设置 › 后台运行); `keep` flips that switch.
- With the fake ssh on macOS set `ssh.loadProfile` to `false` (the profile puts the real `ps`/`du` before any fakes), and note that the security script's `/home/*` glob hangs on the automount.
- An end-to-end run without servers: point `config.json`'s `ssh.binary` at `crates/engine/tests/fixtures/fake-ssh.sh`, which runs the "remote" script locally.
- In a `#[cfg(test)]` module of a file with `use gpui::*`, do not `use super::*` (it brings in gpui's `test` attribute).

## CI and releases

- `.github/workflows/ci.yml`: clippy `-D warnings` and the tests on Windows, macOS and Linux for every push to main and every pull request (no `runtime_shaders`: the runners have the Metal Toolchain).
- `.github/workflows/release.yml`: a pushed tag `v<version>` matching `Cargo.toml` builds the DMGs (`scripts/package-macos.sh`), the Windows zip and the Linux tar.gz and publishes a release with `.github/release-notes/<tag>.md`. Signed when all ten signing secrets are set, unsigned when none are, stopped when only some are. A pull request touching `scripts/` or the workflow rehearses the packaging unsigned.

## Architecture

- `crates/engine` (no GUI, no LLM, synchronous): `config`, `inventory` (+ selectors), `managed` (revision-checked `managed.json`), `risk` (command classifier, verified against 8k golden cases from the TS), `policy` (grants, `gate`), `ssh` (system `ssh`, askpass over a FIFO, sudo password on stdin, `AuthGuard`; ControlMaster sockets in `<data>/cm`, or under `/tmp/wispops-<uid>` when that path is too long for a socket), `vault`, `store` (audit, histories), `change`, `schedule`.
- `crates/collect`: pure script/parse/render triples (`inspect`, `disk`, `files`, `security`, `probe`, `space`), thresholds and findings. Shell text is byte-identical to the plugin's. `longrun` (user tasks older than a threshold) and `attacks` (failed logins by source, account and hour; a tail appended to the security script) are this app's own.
- `crates/core` / `crates/net`: request bodies and stream parsing for Anthropic Messages, chat completions and Responses; providers; settings; skills.
- Root crate: `Workspace` in `src/app.rs` holds all state; every click is a `Cmd` handled in `Workspace::run` (page-specific arms in `servers.rs`, `vault.rs`, `tasks.rs`, `settings.rs`). `src/ops.rs` is `Fleet`: engine + collectors, shared as `Arc<Fleet>` with background work; `Fleet::view()` builds what the pages draw (`View`), re-read by `Workspace::reload`. Never read disk or SSH from render.
- `src/scans.rs` (`impl Fleet`) is what the 磁盘, 长时任务 and 安全 pages (`disk.rs`, `longrun.rs`, `security.rs`) run: the first disk scan (home, or every local filesystem as root via `Fleet::root_way`) with its plan in `disk-scans.json` and the timed follow-up scans, the long-task check, the attack triage. Their results live in the store (`space`, `longrun`, `security`); the disk page loads its scans in `load_disk`, not in `view()`.
- `src/tools.rs`: the `ops_*` catalog, `gate` (plan → `policy::gate` → `Gate::{Run, Ask, Refuse}`) and `run`. Keep it fail-closed: a call that touches hosts needs the `Ticket`'s voucher and the voucher must name the hosts the selector resolves to. Deny rules are never asked about. Vault and inventory editing are window-only and must never become model tools.
- `src/chat.rs`: `ask` → `chat_step` → `run_tools` → (consent card) → `execute_tools` → `chat_step`. Background results check `chat.generation`.
- `src/background.rs`: 设置 › 后台运行 (`keep_running`). The timers belong to the window's `Workspace`, so with it on the window is never closed: the program is hidden on macOS (Dock icon back, ⌘Q from the one menu, App Nap held off), the window minimised elsewhere, where GPUI has no tray icon.
- `src/assistant.rs`: `Page::Assistant`, the conversation as a page; its header leads to the kept conversations (`chat.history`, a view of the same page and the only place they are listed; `chat.conversations` is read on entering and by `Workspace::relist` after a save, open or delete). Beside the other pages the assistant floats over the bottom right corner or, docked (`settings.chat_docked`), stands as a column at the right; put away it is the round button there (`render_chat_button` in `app.rs`). The conversation is drawn by `render_conversation` once a frame, so on the assistant's page neither is drawn.
- `src/findings.rs`: how a finding reads in the window. The collectors word findings in English (history, audit and the model keep that); `findings::words` gives the Chinese window Chinese and folds long lists. A new finding code wants a rule there.
- Routine tasks: schedules are daily, an interval or five-field cron (`crates/engine/src/cron.rs`, evaluated in the task's zone). A task can run an accepted check script (`crates/engine/src/check_scripts.rs`, `src/scripts.rs`) or start from a template (`crates/engine/src/templates.rs`, `src/templates.rs`). `ops_script_draft` and `ops_template_draft` only queue drafts: a person accepts them in the window, and that must stay so.
- Outgoing network besides the model: webhooks (`crates/engine/src/notify.rs`, `src/notify.rs`, `src/webhooks.rs`), WebDAV device sync (`crates/engine/src/{sync,sync_crypto,webdav}.rs`, `src/sync.rs`; snapshots are encrypted before they leave, in the plugin's format) and the update check (`src/updates.rs`, `src/updates_view.rs`; it downloads and verifies a package, never installs or runs it). All go through the proxy setting except requests to this computer. Their tests use a listener on 127.0.0.1, never a real service.
- Never log or return credentials. Passwords leave the vault only inside `Fleet::execute`.
- Colours only from `theme.rs`; design principles as in Wisp Paper (安静的版面).
