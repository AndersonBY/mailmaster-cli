# Changelog

## Unreleased

### Agent skill & CLI UX

- Added a ready-to-install Agent Skill at `skill/SKILL.md` (and bundled copy at
  `src/mailmaster/skill/SKILL.md` packaged inside the wheel), programmatic
  helpers in `mailmaster.skill` (`load_skill_markdown`, `get_skill_source_path`,
  `install_skill`, `SUPPORTED_SKILL_TARGETS`), and the `mailmaster activate-skill`
  command (`--install project|claude|codex|gemini|cursor`, `--dest`, `--path`,
  and JSON mode).
- Added a first-class `--json` flag and flexible placement for both `--json` and
  `--format json|text` before or after any subcommand, plus actionable
  `suggestions` on `invalid_argument` CLI errors.
- Organized `mailmaster --help` into five help panels (`Setup & Skill`,
  `Read & Search`, `Send & Drafts`, `Mailbox Actions`,
  `Protocol Diagnostics (Advanced)`), added usage examples to command help text,
  and rewrote user-facing help and error messages in plain language.
- Updated `fetch-mail` / `AccountAccess.fetch_mail_source` to auto-resolve local
  numeric `mail_id` values to their `RemoteId` via `mail.db`.
- Rewrote `README.md`, `README_EN.md`, `docs/library-api.md`,
  `docs/architecture.md`, and `docs/README.md` in plain, direct language with
  `uv tool install mailmaster` quick-install instructions and AI Agent setup.

### Architecture & modularization

- Replaced the monolithic `src/mailmaster/wmsvr.py` and `src/mailmaster/wmsvr_mail.py`
  with the modular `src/mailmaster/wmsvr/` subpackage (`tlv`, `keys`, `d1_wire`,
  `bootstrap`, `payloads`, `login`, `diagnostics`, `lz4`, `session`, `operations`),
  keeping `src/mailmaster/wmsvr_mail.py` as a public compatibility facade.
- Split `src/mailmaster/cli/commands.py` into focused modules (`errors`,
  `skill_commands`, `read_commands`, `send_commands`, `mutation_commands`,
  `wmsvr_commands`, `render`), replaced global output-format state with a
  `ContextVar`, and exported `LocalLookupError`, `WmsvrMailError`, and
  `resolve_send_transport` from `mailmaster`.
- Deduplicated `_facade.py` per-operation Wmsvr sessions via `_open_private_session`
  and centralized transport resolution in `resolve_send_transport`.

### Store, capabilities & sending

- Added cached read-only SQLite snapshot copying (`copy_sqlite_snapshot`, invalidated
  by `(st_mtime_ns, st_size)` and `-wal` sidecar changes) across `store.py`,
  `protocol_config.py`, and `wmsvr/bootstrap.py`.
- Added `AccountStore.get_contents_bulk` so `search_mail(..., include_body=True)`
  reads `content.db` in a single batch query instead of N+1 opens.
- Accepted `int | str` account identifiers on `get_account`, `open_account`, and
  `MailMaster` facade methods.
- Fixed `AccountCapabilities.matches(require_send=True)` (`capabilities --sendable`)
  to include Wmsvr private-send accounts alongside SMTP-send accounts.
- Added unified `MailMaster.send_mail` / `AccountAccess.send_mail` and Markdown/LaTeX
  options (`--markdown-body`, `--markdown-file`, `--latex-mode`) on `send-mail` and
  `save-draft`.

### CLI error contract & quality

- Normalized `--format json` / `--json` CLI parameter/usage validation failures
  into the standard JSON error envelope (`code: "invalid_argument"`, exit code
  `2`, no traceback) via `JsonAwareTyperGroup`.
- Added structured `LocalLookupError` (`account_not_found`) handling to `wmsvr-*`
  inspection commands.
- Fixed all `ty check` diagnostics across `src/`, `tests/`, and `examples/`, and
  added `python -m ty check` to GitHub Actions CI.

## 0.1.0 — 2026-11-24

Initial beta release.

### Product capabilities

- Local MailMaster data access: accounts, mailboxes, mail list, details,
  search, and raw source export.
- SMTP sending with dynamically decrypted or domain-derived profiles, including
  plain text, HTML, Markdown, inline images, attachments, and LaTeX modes.
- Direct IMAP mutations for IMAP-backed accounts: mark read/unread, move and
  delete.
- Wmsvr / 163 private-protocol support without Frida or a running MailMaster
  process:
  - login and session bootstrap from local materials;
  - mark read/unread, move and delete with in-session read-back verification;
  - send, including attachments (four-step upload) and sent-copy verification;
  - create/update drafts and send stored drafts;
  - fetch raw RFC822 source, including chunked large messages.
- Capability discovery and transport selection via `mailmaster capabilities`.
- Stable JSON envelope (`ok`, `command`, `data`/`error`) and structured errors
  for local lookups, SMTP failures, and Wmsvr protocol failures.
- Offline `wmsvr-*` inspection commands for reverse-engineering and build-drift
  checks.

### Packaging

- Hatchling build with the `mailmaster` console entry point and MIT license.
- `uv build` produces a wheel containing only product modules and an sdist that
  excludes maintainer-only notes, history, CI configuration, and archived
  reports.
- Verified by installing the wheel into a clean virtual environment: `--help`,
  `doctor`, `accounts`, JSON capabilities, the unknown-account error contract,
  and the full test suite (310 tests) all pass.

### Known limitations

- Windows only; requires an installed and previously configured MailMaster.
- Wmsvr private operations authenticate per call.
- Wmsvr delete is a server-side hard delete and is not reversible.
- Parameter-validation failures are not yet fully normalized into the JSON
  error envelope; this is planned for the next minor release.
