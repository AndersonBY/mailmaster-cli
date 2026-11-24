# Architecture

`mailmaster` is a layered Windows CLI and Python library for NetEase MailMaster. It reads MailMaster's local SQLite databases via cached read-only snapshots, decrypts stored protocol configuration in memory, and talks directly to SMTP, IMAP, or 163/Wmsvr servers—without Frida, browser DevTools, or a running MailMaster process.

## Layers

| Layer | Module | Responsibility |
| --- | --- | --- |
| Discovery | `discovery.py` | Locate the MailMaster installation, `app.db`, and per-account data roots. |
| Local store | `store.py` | Read `app.db`, per-account `mail.db`, and `content.db` through cached read-only snapshots (`copy_sqlite_snapshot`) and bulk body loading (`get_contents_bulk`); resolve accounts (`int \| str`), mailboxes, and mail IDs. Raises `LocalLookupError` with stable codes. |
| Config crypto | `protocol_config.py` | Decrypt protected account configuration blobs (SMTP/IMAP/Wmsvr) in memory using local machine material; reads `mail.db` via `copy_sqlite_snapshot`. |
| Content decoding | `codec.py` | Decode stored message bodies and convert HTML to plain text. |
| Rendering | `email_renderer.py` | Build plain-text and HTML mail from plain text, HTML, or Markdown, including inline images and LaTeX modes (`auto`, `mathml`, `image`, `raw`). |
| SMTP | `smtp.py` | Resolve an SMTP profile (stored or domain-derived) and send mail directly. |
| IMAP | `imap_ops.py` | Direct IMAP mutations (mark read/unread, move, delete) for IMAP-backed accounts. |
| Wmsvr protocol & mailbox | `wmsvr/` (`tlv`, `keys`, `d1_wire`, `bootstrap`, `payloads`, `login`, `diagnostics`, `lz4`, `session`, `operations`) + `wmsvr_mail.py` | Modular Wmsvr/d1 transport, TLV/LEB128 codec, embedded RSA key unwrapping, AES-CBC slices, `app.db` bootstrap, login handshake, pure-Python LZ4/reply decoding, `WmsvrMailSession`, and verified send/draft/attachment/mutation/raw-source operations. `wmsvr_mail.py` stays as a compatibility facade. |
| Facade | `_facade.py` | High-level `MailMaster` and `AccountAccess` APIs: `int \| str` account lookup, capability detection, centralized `resolve_send_transport`, unified `send_mail`, local-to-remote ID resolution in `fetch_mail_source`, shared `_open_private_session`, and verified workflows. |
| Agent skill | `skill/` (repo root) + `src/mailmaster/skill/` | Canonical Agent playbook (`SKILL.md`, bundled inside the wheel) plus programmatic `load_skill_markdown`, `get_skill_source_path`, and `install_skill` helpers targeting `project`, `claude`, `codex`, `gemini`, and `cursor`. |
| CLI | `cli/` (`__init__`, `errors`, `skill_commands`, `read_commands`, `send_commands`, `mutation_commands`, `wmsvr_commands`, `render`, `commands`) | Thin modular Typer CLI with `ContextVar`-scoped output format, flexible `--json` / `--format json` handling before or after subcommands, grouped help panels, structured JSON errors with actionable `suggestions`, `activate-skill`, and advanced `wmsvr-*` inspection commands. |

`models.py` holds the dataclasses shared across layers; `__init__.py` is the public library surface.

## CLI command panels

Top-level `mailmaster --help` organizes commands into five panels:

- **Setup & Skill**: `doctor`, `accounts`, `capabilities`, `activate-skill`
- **Read & Search**: `mailboxes`, `list`, `read`, `search`, `fetch-mail`
- **Send & Drafts**: `send-mail`, `save-draft`, `send-draft`, `smtp-send`
- **Mailbox Actions**: `mark-read`, `mark-unread`, `move-mail`, `delete-mail`
- **Protocol Diagnostics (Advanced)**: `wmsvr-bootstrap` and the `wmsvr-*` inspection helpers

## Transport selection

The CLI and facade pick a transport using `mailmaster capabilities`:

- **Read** — local SQLite snapshots, offline.
- **Send** — stored SMTP profile when available; otherwise the 163/Wmsvr private protocol (`mbox:compose`), including attachments and Markdown/LaTeX. When the only SMTP profile is domain-guessed and private send is available, `auto` prefers `wmsvr-private`.
- **Mutations** — direct IMAP when IMAP material exists; otherwise the Wmsvr private protocol (`mbox:updateMessageInfos`, `mbox:deleteMessages`).
- **Drafts & raw source** — Wmsvr private protocol (`save-draft`, `send-draft`, `fetch-mail`). `fetch-mail` accepts either a `RemoteId` (`<msid>:<mid>`) or a local numeric `LocalId` (automatically resolved from `mail.db`).

Scripts and AI Agents should branch on `recommended_read_method`, `recommended_send_method`, `recommended_mutation_method`, and `product_paths` in the capabilities payload rather than guessing from raw config presence.

## Verification model

Private-protocol writes are never reported as successful on server acknowledgment alone:

- Mark, move, and delete read back the remote message state in the same session.
- Send resolves the new sent copy (from `savedSent` or a Sent folder listing) and verifies its subject.
- Attachment uploads additionally verify cumulative `actualSize` on every chunk.
- Draft saves resolve the returned `draftId` in the same session.

If read-back cannot confirm the write, the call raises `wmsvr_state_change_not_verified` (or a related structured error) instead of reporting success.

## Error & JSON contract

Pass `--json` or `--format json` anywhere on the command line (before or after the subcommand) to receive a consistent JSON envelope:

```json
{"ok": true, "command": "list", "data": {}}
```

```json
{
  "ok": false,
  "command": "read",
  "error": {"code": "mail_not_found", "message": "...", "details": {}}
}
```

- Local lookup failures return `account_not_found`, `mailbox_not_found`, or `mail_not_found` (exit code `2`, no traceback).
- CLI parameter and usage validation failures return `invalid_argument` (exit code `2`, no traceback) with a `suggestions` list inside `error.details`, handled by `JsonAwareTyperGroup`.
- Transport, skill, and protocol errors return stable codes such as `invalid_skill_target`, `smtp_auth_failed`, `wmsvr_session_expired`, `wmsvr_method_rejected`, and `wmsvr_state_change_not_verified`.

## Operational boundaries

- **Read-only local access**: SQLite databases (`app.db`, `mail.db`, `content.db`) are read via cached temp snapshots (`copy_sqlite_snapshot`, invalidated on source or `-wal` `(st_mtime_ns, st_size)` changes), avoiding live database locks while keeping repeated reads fast.
- **In-memory credentials**: decrypted passwords and tokens stay in memory and are never written to disk.
- **Per-call private sessions**: each 163/Wmsvr operation authenticates for the duration of the call; no long-lived session cache is persisted.
- **Permanent delete on 163/Wmsvr**: `delete-mail` over the private protocol is a server-side hard delete (does not move to Trash).
- **Platform**: Windows only, relying on an installed MailMaster profile with local data.
- **Diagnostics stay separate**: `wmsvr-*` commands are advanced inspection tools and are not required for everyday mail workflows.
