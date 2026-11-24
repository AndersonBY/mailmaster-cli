# mailmaster Library API & CLI Reference

This guide covers the Python SDK (`MailMaster`, `AccountAccess`, `mailmaster.skill`, rendering/SMTP helpers) and the low-level `mailmaster.wmsvr` protocol surface.

## High-level facade (`MailMaster` & `AccountAccess`)

Start with `MailMaster` to discover local accounts and open an `AccountAccess` handle:

```python
from mailmaster import MailMaster

mm = MailMaster()
accounts = mm.get_accounts()

# Lookup accepts email address, account name, or numeric account.id
acc = mm.open_account(accounts[0].id)
```

You can also point `MailMaster` at a specific `app.db`:

```python
from pathlib import Path
from mailmaster import MailMaster

mm = MailMaster(app_db=Path(r"C:\path\to\app.db"))
```

### `MailMaster` methods

All `identifier` / `account` parameters accept `str | int` (numeric `account.id`, email address, or account name):

- **Accounts & capabilities**
  - `get_accounts()` — list all local accounts
  - `get_account(identifier: str | int)` — resolve one `Account`
  - `open_account(identifier: str | int)` / `account(identifier: str | int)` — return an `AccountAccess`
  - `get_capabilities(account)` — inspect read, send, draft, attachment, and mutation capabilities for one account
  - `list_capabilities(*, query=None, require_send=False, require_mutation=False, require_paths=None)` — filter accounts by capability (`require_send=True` matches both SMTP and Wmsvr private-send accounts; `require_mutation=True` matches IMAP and Wmsvr private-mutation accounts)
- **Local read & search (offline, cached SQLite snapshots)**
  - `get_mailboxes(account)`
  - `list_mail(account, *, mailbox=None, unread_only=False, limit=20)`
  - `search_mail(account, query, *, mailbox=None, include_body=False, limit=20)` — when `include_body=True`, loads candidate bodies in a single batch query via `AccountStore.get_contents_bulk`
  - `get_mail(account, mail_id)` / `get_details(account, mail_id)` — accepts `LocalId` or `RemoteId`
- **Sending, drafts, raw source & mutations**
  - `send_mail(account, ...)` — unified send over SMTP or 163/Wmsvr private protocol (`transport="auto"|"smtp"|"wmsvr-private"`), with plain text, HTML, Markdown/LaTeX, and attachment support
  - `send_mail_private(account, ...)` — explicit Wmsvr private-protocol send
  - `save_mail_draft(account, ...)` / `send_mail_draft(account, ...)` / `find_mail_draft(account, ...)` — server-side draft workflows on Wmsvr accounts
  - `fetch_mail_source(account, mail_id, *, part=None, offset=0, max_part=8)` — fetch full RFC822 message source (accepts either `LocalId` or `RemoteId`)
  - `mark_read(account, mail_id)` / `mark_read_many(account, mail_ids)`
  - `mark_unread(account, mail_id)` / `mark_unread_many(account, mail_ids)`
  - `move_mail(account, mail_id, target_mailbox=...)` / `move_mail_many(account, mail_ids, target_mailbox=...)`
  - `delete_mail(account, mail_id)` / `delete_mail_many(account, mail_ids)`
- **Wmsvr bootstrap & diagnostics**
  - `get_wmsvr_bootstrap(account=None)`
  - `get_wmsvr_login_context(account)`
  - `refresh_wmsvr_master_session(account)`
  - `probe_wmsvr_get_settings(account)` / `probe_wmsvr_runtime_public_key(account)`

### `AccountAccess` methods

`AccountAccess` binds the same operations to a single account:

```python
from mailmaster import MailMaster

mm = MailMaster()
acc = mm.open_account("sender@example.com")

# Local read
mailboxes = acc.get_mailboxes()
mails = acc.list_mail(limit=10)
details = acc.get_details("40073")

# Unified send (auto-picks SMTP or Wmsvr private protocol)
res = acc.send_mail(
    to=["colleague@example.com"],
    subject="Weekly notes",
    markdown_text="# Notes\n\nEnergy: `$E = mc^2$`",
    latex_mode="auto",
    attachments=[r"C:\path\report.pdf"],
)
print(res["transport"], res["status"])

# Batch mutations
acc.mark_read_many(["40073", "40074"])
acc.move_mail_many(["40073", "40074"], target_mailbox="Archive")
```

Full `AccountAccess` surface:

- **Local read**: `get_mailboxes()`, `list_mail(...)`, `search_mail(...)`, `get_mail(mail_id)`, `get_details(mail_id)`, `get_server_configs()`, `get_capabilities()`
- **Transport resolution & rendering**:
  - `resolve_send_transport(transport="auto", *, capability=None)` — returns `"smtp"`, `"wmsvr-private"`, or `"none"`
  - `render_markdown_email(markdown_text, latex_mode="auto")`
- **Sending**:
  - `send_mail(*, to, cc=None, bcc=None, subject="", body="", html_body="", markdown_text=None, latex_mode="auto", attachments=None, in_reply_to="", transport="auto", verify=True, html_base_dir=None)` — unified send across SMTP and Wmsvr private protocol. Returns a normalized dict containing `transport`, `status`, `content_mode`, `latex_mode`, and transport-specific verification fields.
  - `send_email(...)` / `send_markdown_email(...)` — explicit direct SMTP
  - `send_mail_private(...)` — explicit Wmsvr private-protocol send
- **Drafts (Wmsvr)**:
  - `save_mail_draft(*, to=None, cc=None, bcc=None, subject="", body="", html_body="", markdown_text=None, latex_mode="auto", attachments=None, compose_id=None, verify=True)` — create or update a server-side draft
  - `send_mail_draft(*, draft_id=None, subject=None, to=None, cc=None, bcc=None, body=None, html_body=None, verify=True)` — restore and deliver a stored draft (existing attachments carry over without re-uploading)
  - `find_mail_draft(*, subject=None)` — locate a draft in the Drafts folder by subject or newest entry
- **Raw RFC822 source (Wmsvr)**:
  - `fetch_mail_source(mail_id, *, part=None, offset=0, max_part=8)` — accepts either a local numeric `LocalId` (automatically resolved to its `RemoteId` via `mail.db`) or a raw `RemoteId` (`<msid>:<mid>`)
- **Mutations**:
  - `mark_read(mail_id)` / `mark_read_many(mail_ids)`
  - `mark_unread(mail_id)` / `mark_unread_many(mail_ids)`
  - `move_mail(mail_id, target_mailbox=...)` / `move_mail_many(mail_ids, target_mailbox=...)`
  - `delete_mail(mail_id)` / `delete_mail_many(mail_ids)`
  - Verified Wmsvr-specific forms: `mark_read_verified(mail_ids)`, `mark_unread_verified(mail_ids)`, `move_mail_verified(mail_ids, target_mailbox=...)`, `delete_mail_verified(mail_ids)`, and `list_wmsvr_folders()`

### Capability discovery

Inspect account capabilities before choosing a path in scripts or AI Agents:

```python
caps = mm.get_capabilities("sender@example.com")
print(caps.recommended_read_method)
print(caps.recommended_send_method)
print(caps.recommended_mutation_method)
print(caps.product_paths)

sendable = mm.list_capabilities(require_send=True)
mutable = mm.list_capabilities(require_mutation=True)
wmsvr_accounts = mm.list_capabilities(query="163", require_paths=["wmsvr-private-send"])
```

## Exceptions & CLI JSON contract

Top-level exports from `mailmaster`:

- `LocalLookupError` (`ValueError` subclass) — raised on missing account, mailbox, or mail ID with stable `.code` values: `account_not_found`, `mailbox_not_found`, `mail_not_found`.
- `WmsvrMailError` — raised on Wmsvr private-protocol errors with a stable `.code` (for example `wmsvr_login_credential_missing`, `wmsvr_session_expired`, `wmsvr_mail_not_found`, `wmsvr_method_rejected`, `wmsvr_upload_rejected`, `wmsvr_compose_id_unknown`, `wmsvr_state_change_not_verified`). Error details never contain passwords or tokens.
- `resolve_send_transport(capability, transport="auto")` — central transport resolver returning `"smtp"`, `"wmsvr-private"`, or `"none"`.

In the CLI, passing `--json` or `--format json` **before or after** any subcommand produces a uniform JSON envelope:

- Success: `{"ok": true, "command": "<name>", "data": {...}}` (exit code `0`)
- Error: `{"ok": false, "command": "<name>", "error": {"code": "...", "message": "...", "details": {...}}}` (exit code `2`, no Python traceback)

CLI parameter and usage validation errors emit `code: "invalid_argument"` with a `suggestions` list in `error.details`.

## Transport behavior & verified workflows

### Sending & attachments

- `send_mail(..., transport="auto")` picks SMTP when a usable stored SMTP profile exists, and prefers `wmsvr-private` when SMTP is missing or only domain-guessed (`smtp_profile_guessed`) and private send is available. Passing `transport="smtp"` still attempts SMTP directly and maps 535 authentication rejections to structured `smtp_auth_failed`.
- Markdown and LaTeX options work on both transports: on `smtp`, `latex_mode="auto"` can embed inline CID images (when `mailmaster[latex-image]` is installed); on `wmsvr-private`, `latex_mode="auto"` renders formulas as MathML.
- On `wmsvr-private`, attachments are uploaded in 64 KiB chunks (`DEFAULT_UPLOAD_CHUNK_SIZE`) with per-chunk cumulative `actualSize` verification before delivery. Delivery itself is verified by reading the saved sent copy back in the same session; if read-back cannot confirm it, `wmsvr_state_change_not_verified` is raised.

### Drafts (Wmsvr)

- `save_mail_draft` creates a server-side draft (including Markdown and attachments) and verifies its `draft_id` in the same session.
- Pass `compose_id` from an earlier save to update that draft in place (`mode="update"`). Note that a `compose_id` expires after a few hours; expired or unknown IDs raise `wmsvr_compose_id_unknown`, so mint a fresh draft (`compose_id=None`) when an old handle has expired. If the draft was deleted before updating with a still-valid `compose_id`, the server recreates it and the result sets `recreated=True`.
- `send_mail_draft` restores a stored draft by `draft_id` or matching `subject`, delivers it (carrying existing attachments without re-uploading), and verifies the sent copy in the same session.

### Mutations (IMAP & Wmsvr)

- Accounts with IMAP material use direct IMAP for `mark_read`, `mark_unread`, `move_mail`, and `delete_mail`.
- Wmsvr accounts without IMAP material run over the private protocol and read back remote state in the same session (`state_change_verified`).
- `move_mail` accepts either a folder name (resolved via `list_wmsvr_folders`) or a numeric server folder ID.
- `delete_mail` on Wmsvr performs a **server-side hard delete** (it does not move messages to Trash and cannot be undone). Deleting an ID that is already absent on the server succeeds idempotently with `already_absent: [True, ...]`.

### Raw RFC822 source (`fetch_mail_source`)

- Fetches the full RFC822 source (headers, body parts, and base64 attachments) from the Wmsvr server via `wzpm:getMessageData`.
- Accepts either a local numeric `LocalId` (automatically resolved to `RemoteId` via local `mail.db`) or a raw `RemoteId` (`<msid>:<mid>`).
- Large messages streamed in 65,536-byte frames are automatically reassembled into the complete byte payload.
- By default (`part=None`), scans slice slots `0..max_part` to locate the RFC822 source (`part_slot`, `candidates`, `misses`). Pass `part=N` to read one specific slot (and optional `offset` bytes into that slot).

## Programmatic skill helpers (`mailmaster.skill`)

`mailmaster` bundles its Agent Skill (`SKILL.md`) inside the installed package so both the CLI (`mailmaster activate-skill`) and Python callers can read or install it:

```python
from pathlib import Path
from mailmaster.skill import (
    SUPPORTED_SKILL_TARGETS,
    get_skill_source_path,
    install_skill,
    load_skill_markdown,
)

# Read the bundled SKILL.md content or locate its path
markdown = load_skill_markdown()
src_path = get_skill_source_path()

# Supported target names: ("project", "claude", "codex", "gemini", "cursor")
print(SUPPORTED_SKILL_TARGETS)

# Install SKILL.md for one or more Agent environments
written = install_skill(targets=["project", "claude"])

# Or install to a custom directory or explicit .md path
written_custom = install_skill(dest=Path(r"C:\path\to\skills"))
```

Target paths:

- `"project"` → `<cwd>/.agents/skills/mailmaster/SKILL.md`
- `"claude"` → `~/.claude/skills/mailmaster/SKILL.md`
- `"codex"` → `~/.codex/skills/mailmaster/SKILL.md`
- `"gemini"` → `~/.gemini/config/skills/mailmaster/SKILL.md`
- `"cursor"` → `<cwd>/.cursor/skills/mailmaster/SKILL.md`

## Rendering & SMTP helpers

Use the rendering layer directly when building email content:

```python
from mailmaster import render_markdown_email

rendered = render_markdown_email("# Title\n\nHello `$E = mc^2$`", latex_mode="auto")
print(rendered.plain_text)
print(rendered.html)
```

Supported `latex_mode` values: `auto`, `mathml`, `image`, `raw`.

Low-level SMTP helpers are also exported from `mailmaster`:

```python
from mailmaster import (
    ResolvedSmtpProfile,
    SmtpProfile,
    profile_from_server_config,
    resolve_smtp_profile,
    send_email,
)
```

`resolve_smtp_profile()` prefers stored `SMTPServerConfig` settings and falls back to domain-derived settings with `WmsvrServerConfig` credentials when needed. For everyday use, prefer `AccountAccess.send_mail()`.

## Low-level Wmsvr protocol API (`mailmaster.wmsvr` / `mailmaster.wmsvr_mail`)

This section is intended for protocol researchers and custom tooling. Normal callers should use `MailMaster` / `AccountAccess`.

The implementation lives in the `mailmaster.wmsvr` subpackage (`tlv`, `keys`, `d1_wire`, `bootstrap`, `payloads`, `login`, `diagnostics`, `lz4`, `session`, `operations`), with `mailmaster.wmsvr_mail` maintained as a compatibility facade.

### Authenticated session (`WmsvrMailSession`)

```python
from mailmaster import MailMaster
from mailmaster.wmsvr_mail import (
    WmsvrAttachment,
    WmsvrMailError,
    WmsvrMailSession,
    decode_lz4_block,
    decode_wmsvr_payload,
    open_wmsvr_mail_session,
    parse_business_reply,
)

mm = MailMaster()
ctx = mm.get_wmsvr_login_context("user@163.com")
refreshed = mm.refresh_wmsvr_master_session("user@163.com")

with open_wmsvr_mail_session(ctx, master_session_token=refreshed.token) as session:
    folders = session.list_folders()
    flags = session.get_message_flags(["<msid>:<mid>"])
```

Key session methods:

- `list_folders()`, `get_message_flags(ids)`, `get_message_infos(ids)`, `get_message_folders(ids)`
- `set_message_read(ids, read=...)` / `set_message_read_verified(ids, read=...)`
- `set_message_folder(ids, fid=...)` / `set_message_folder_verified(ids, fid=...)`
- `delete_messages(ids, delete_type="batch")` / `delete_messages_verified(ids, delete_type="batch")`
- `create_compose()`, `send_mail(...)` / `send_mail_verified(...)`, `send_mail_with_attachments(...)` / `send_mail_with_attachments_verified(...)`
- `save_draft(...)` / `save_draft_verified(...)`, `find_draft(...)`, `send_draft(...)` / `send_draft_verified(...)`
- `read_message_slice(mid, part=..., offset=...)` / `fetch_message_source(mid, max_part=8)`
- `decode_lz4_block()` / `decode_wmsvr_payload()` — pure-Python LZ4 reply decoding (no external `lz4` package required)

### Bootstrap, d1 framing & login builders

```python
from mailmaster import (
    LOGIN_METHOD_LOGINMAIL,
    MailMaster,
    build_get_settings_frame,
    build_loginmail_body,
    build_loginone_body,
    build_loginone_payload,
    build_masterdevice_payload,
    build_wmsvr_d1_request_context,
    build_wmsvr_login_frame,
    build_wmsvr_pre_auth_frame,
    parse_d1_frame,
)

mm = MailMaster()
bootstrap = mm.get_wmsvr_bootstrap("user@163.com")
peers = bootstrap.get_candidate_peers(account="user@163.com")

ctx = mm.get_wmsvr_login_context("user@163.com")
frame, session_key, client_id = build_wmsvr_login_frame(
    ctx,
    method=LOGIN_METHOD_LOGINMAIL,
    body=build_loginmail_body(ctx),
)
pre_auth_frame, _, wrapped_key = build_wmsvr_pre_auth_frame(
    build_wmsvr_d1_request_context(ctx),
    session_key=session_key,
)

settings_frame = build_get_settings_frame()
parsed = parse_d1_frame(settings_frame.to_bytes())
```

Additional diagnostic & key-unwrapping helpers exported from `mailmaster`:

- Key & crypto helpers: `load_wmsvr_hardcoded_public_keys`, `get_wmsvr_hardcoded_public_key`, `compute_wmsvr_public_key_digest`, `find_wmsvr_hardcoded_public_key_by_digest`, `unwrap_wmsvr_key_update_blob`, `decode_get_settings_key_update`, `generate_wmsvr_d1_session_key`, `encrypt_wmsvr_d1_slice`, `decrypt_wmsvr_d1_slice`, `pad_d1_slice` (PKCS#7 default)
- Frame & TLV helpers: `send_d1_frame`, `recv_d1_frame`, `build_wmsvr_d1_control_tlv`, `build_wmsvr_d1_encrypted_frame`, `build_wmsvr_d1_request_frame`, `WmsvrControlPayload`, `build_wmsvr_control_tlv`, `parse_wmsvr_control_tlv`, `WmsvrStartupPayload`, `build_wmsvr_startup_tlv`, `parse_wmsvr_startup_tlv`
- Login probe & response inspection: `execute_wmsvr_login_probe`, `parse_login_response`, `summarize_login_response` (redacts secrets unless `include_secrets=True`), `describe_login_response_slice`

See [`docs/reverse-engineering.md`](reverse-engineering.md) for wire-level protocol findings and build anchors.
