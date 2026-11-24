---
name: mailmaster
description: >-
  Read, search, send, draft, and manage emails on Windows through the local
  NetEase MailMaster client (supports IMAP/SMTP and 163/126/yeah.net Wmsvr
  accounts). Use when the user asks to check inbox/unread mail, search
  emails, read messages or raw RFC822 source, send plain/HTML/Markdown/LaTeX
  emails with attachments, manage drafts, or mark/move/delete emails.
---

# MailMaster CLI Agent Playbook

Use `mailmaster` on Windows to read, search, send, draft, and manage mail across accounts signed into the local NetEase MailMaster desktop client (both IMAP/SMTP accounts and 163/126/yeah.net Wmsvr accounts). The MailMaster GUI does not need to be running; local reads use temporary read-only SQLite snapshots.

## Quick Start Workflow

### 1. Always use JSON mode for reliable parsing

Pass `--json` (or `--format json`) either before or after the subcommand:

```powershell
mailmaster --json <command> ...
mailmaster <command> ... --json
```

All commands return a stable JSON envelope:

- Success (exit `0`): `{"ok": true, "command": "<name>", "data": ...}`
- Error (exit `2`): `{"ok": false, "command": "<name>", "error": {"code": "...", "message": "...", "details": ...}}`

### 2. Discover accounts and capabilities first

Never guess account IDs or supported transports. Start with `capabilities`:

```powershell
mailmaster --json capabilities
mailmaster --json capabilities --sendable
mailmaster --json capabilities --account user@163.com
```

- Pass either the numeric `id` or `email` to `--account` in later commands.
- Trust `recommended_send_method` (`smtp`, `wmsvr-private`, or `none`) and `recommended_mutation_method` (`imap`, `wmsvr-private`, or `none`).
- If MailMaster paths or databases appear missing, run `mailmaster --json doctor`.

### 3. Read and search mail locally (offline, instant)

```powershell
# List folders / mailboxes
mailmaster --json mailboxes --account user@163.com

# List recent or unread messages
mailmaster --json list --account user@163.com --mailbox 收件箱 --unread --limit 20

# Read full message details and plain text (or raw HTML with --html)
mailmaster --json read --account user@163.com --mail-id 12345
mailmaster --json read --account user@163.com --mail-id 12345 --html

# Search subject/sender/recipients (add --body to search decoded message bodies)
mailmaster --json search --account user@163.com "invoice" --body --limit 20
```

`list` and `search` return both `local_id` (numeric) and `remote_id` (e.g. `1:abc123`). Both are accepted by `read`, `fetch-mail`, and mailbox mutation commands.

### 4. Fetch raw RFC822 source from the server (163/Wmsvr)

When you need raw headers, original MIME structure, or server attachment metadata on a Wmsvr account:

```powershell
mailmaster --json fetch-mail --account user@163.com --mail-id 12345 --out message.eml
```

`--mail-id` accepts either a local numeric `local_id` (auto-resolved to its `remote_id`) or a direct `remote_id` (`<fid>:<mid>`).

### 5. Send email (plain text, HTML, Markdown/LaTeX, attachments)

`send-mail` automatically chooses the account's best send transport (stored SMTP profile or 163 Wmsvr private protocol):

```powershell
# Plain text
mailmaster --json send-mail --account sender@example.com --to recipient@example.com --subject "Weekly update" --body "Hello from MailMaster CLI."

# Markdown with math formulas and attachments
mailmaster --json send-mail --account user@163.com --to recipient@example.com --cc alice@example.com --subject "Report" --markdown-file report.md --latex-mode auto --attach report.pdf
```

- Body options: `--body`, `--html-body` (wins over `--body`), `--markdown-body`, or `--markdown-file` (pass `-` to read Markdown from stdin).
- `--latex-mode`: `auto` (default), `mathml`, `image`, or `raw`.
- `--to`, `--cc`, `--bcc`, and `--attach` are repeatable.
- `--transport`: `auto` (default), `smtp`, or `wmsvr-private`.
- **Confirmation rule**: Before sending to external recipients, confirm recipients, subject, attachments, and body with the user unless the user explicitly instructed immediate sending.

### 6. Create, update, and send server drafts (163/Wmsvr)

```powershell
# Create a new server draft (returns compose_id and draft_id)
mailmaster --json save-draft --account user@163.com --to recipient@example.com --subject "Q3 Proposal" --markdown-body "## Summary\nDraft text." --attach deck.pdf

# Update that draft before sending (pass the returned compose_id)
mailmaster --json save-draft --account user@163.com --compose-id <compose_id> --to recipient@example.com --subject "Q3 Proposal (v2)" --body "Updated text."

# Send a stored draft (existing draft attachments are sent without re-uploading)
mailmaster --json send-draft --account user@163.com --draft-id <draft_id>
mailmaster --json send-draft --account user@163.com --subject "Q3 Proposal (v2)"
```

`send-draft` also accepts optional `--to`, `--body`, and `--html-body` overrides.

### 7. Mutate mailbox state (read/unread, move, delete)

All mutation commands accept repeatable `--mail-id` values and automatically route through IMAP or the 163 Wmsvr private protocol:

```powershell
mailmaster --json mark-read --account user@163.com --mail-id 12345 --mail-id 12346
mailmaster --json mark-unread --account user@163.com --mail-id 12345
mailmaster --json move-mail --account user@163.com --mail-id 12345 --target-mailbox 已删除
mailmaster --json delete-mail --account user@163.com --mail-id 12345
```

> **Destructive-action warning**: On 163/Wmsvr accounts, `delete-mail` performs a **permanent server hard-delete** — it does **not** move the message to Trash and cannot be undone. Always confirm with the user before calling `delete-mail`, or use `move-mail --target-mailbox <trash-folder>` when reversible removal is preferred.

## Command Reference

| Command | Purpose | Key Options | Notes |
| --- | --- | --- | --- |
| `activate-skill` | Print or install this `SKILL.md` | `--install <target>`, `--dest <path>`, `--path` | Targets: `project`, `claude`, `codex`, `gemini`, `cursor` |
| `doctor` | Inspect local MailMaster install and DB paths | *(none)* | Offline local check |
| `accounts` | List configured local accounts | *(none)* | Offline local read |
| `capabilities` | Inspect per-account transports and features | `--account`, `--query`, `--readable`, `--sendable`, `--mutable`, `--bootstrap`, `--path` | Always run first |
| `mailboxes` | List folders for an account | `--account` | Returns folder names and IDs |
| `list` | List messages | `--account`, `--mailbox`, `--unread`, `--limit` (`1..200`) | Offline local read |
| `read` | Read full message body and headers | `--account`, `--mail-id`, `--html` | Accepts `local_id` or `remote_id` |
| `search` | Search local messages | `--account`, `<query>`, `--mailbox`, `--body`, `--limit` (`1..100`) | Add `--body` for body text search |
| `fetch-mail` | Download raw RFC822 source from server | `--account`, `--mail-id`, `--out`, `--part`, `--offset`, `--max-part` | Wmsvr accounts; accepts `local_id` or `remote_id` |
| `send-mail` | Send an email | `--account`, `--to`, `--cc`, `--bcc`, `--subject`, `--body`, `--html-body`, `--markdown-body`, `--markdown-file`, `--latex-mode`, `--attach`, `--transport` | Auto-selects SMTP or Wmsvr |
| `smtp-send` | Send directly via SMTP | `--from`, `--to`, `--cc`, `--bcc`, `--subject`, `--body`, `--html-body`, `--markdown-body`, `--markdown-file`, `--latex-mode`, `--attach`, `--in-reply-to` | Supports `--in-reply-to` threading |
| `save-draft` | Create or update a server draft | `--account`, `--to`, `--cc`, `--bcc`, `--subject`, `--body`, `--html-body`, `--markdown-body`, `--markdown-file`, `--latex-mode`, `--compose-id`, `--attach` | Wmsvr accounts |
| `send-draft` | Send a stored server draft | `--account`, `--draft-id`, `--subject`, `--to`, `--body`, `--html-body` | Wmsvr accounts; keeps stored attachments |
| `mark-read` | Mark message(s) as read | `--account`, `--mail-id` (repeatable) | IMAP or Wmsvr |
| `mark-unread` | Mark message(s) as unread | `--account`, `--mail-id` (repeatable) | IMAP or Wmsvr |
| `move-mail` | Move message(s) to another folder | `--account`, `--mail-id` (repeatable), `--target-mailbox` | IMAP or Wmsvr |
| `delete-mail` | Delete message(s) | `--account`, `--mail-id` (repeatable) | **Permanent hard-delete on Wmsvr** |

## Common Error Codes & Recovery

| `error.code` | Meaning | Recovery Action |
| --- | --- | --- |
| `invalid_argument` | Bad CLI option or missing required argument | Check `error.details` or run `mailmaster <cmd> --help` |
| `account_not_found` | `--account` did not match any local account | Run `mailmaster --json accounts` and pick a valid `id` or `email` |
| `mailbox_not_found` | `--mailbox` or `--target-mailbox` not found | Run `mailmaster --json mailboxes --account <acct>` |
| `mail_not_found` | `--mail-id` not found in local store | Run `mailmaster --json list --account <acct>` to refresh IDs |
| `send_unsupported` / `smtp_send_unsupported` | Selected transport unavailable for account | Run `mailmaster --json capabilities --account <acct>` and use `recommended_send_method` |
| `smtp_auth_failed` / `smtp_connection_failed` / `smtp_send_failed` | SMTP server rejected auth or delivery | Check `capabilities`; try `--transport wmsvr-private` if supported |
| `imap_mutation_unsupported` / `wmsvr_session_required` | Account lacks credentials/material for mutations | Inspect `capabilities --account <acct>`; confirm the account is signed into MailMaster |
| `wmsvr_attachments_unsupported` | Private attachment upload unavailable for account | Drop `--attach` or use `--transport smtp` if SMTP is available |
| `wmsvr_compose_id_unknown` | Draft `compose_id` expired or unrecognized | Omit `--compose-id` to create a fresh draft |
| `wmsvr_draft_not_found` | No draft matched `--subject` | Save a draft first or pass `--draft-id` explicitly |
| `draft_unsupported` / `draft_send_unsupported` / `mail_read_unsupported` | Wmsvr-only feature called on non-Wmsvr account | Use local `read` or `send-mail` for non-Wmsvr accounts |
| `invalid_skill_target` | Unknown `--install` target in `activate-skill` | Use one of `project`, `claude`, `codex`, `gemini`, `cursor` |

## Installing This Skill

```powershell
# Install into the current repository (.agents/skills/mailmaster/SKILL.md)
mailmaster activate-skill --install project

# Install for Claude Code, Codex, Gemini, or Cursor
mailmaster activate-skill --install claude --install codex --install gemini --install cursor

# Install to a custom path
mailmaster activate-skill --dest C:\path\to\skills

# Or install directly from GitHub via skills CLI
npx skills add AndersonBY/mailmaster-cli
```
