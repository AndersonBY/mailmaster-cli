# mailmaster

[中文](README.md)

Read, search, send, draft, and manage **NetEase MailMaster** emails directly from the Windows CLI or Python. Supports both standard IMAP/SMTP accounts and 163/126/yeah.net (Wmsvr) accounts, with Markdown/LaTeX rendering, attachments, drafts, and structured JSON output—no running MailMaster desktop app required.

## Installation

Install globally as a CLI tool with [`uv`](https://docs.astral.sh/uv/):

```powershell
# Recommended: install the global CLI
uv tool install mailmaster

# Optional: render LaTeX math formulas as inline images
uv tool install "mailmaster[latex-image]"
```

Install as a Python library in a project:

```powershell
uv add mailmaster
# or
pip install mailmaster
```

Install from a local checkout or set up a dev environment:

```powershell
git clone https://github.com/AndersonBY/mailmaster-cli.git
cd mailmaster-cli

# Install your local checkout as a global CLI
uv tool install .

# Or create a local dev environment
uv sync
```

## For AI Agents

`mailmaster` ships a ready-to-use Agent Skill and consistent JSON output on every command, so AI Agents (Claude Code, Codex, Gemini, Cursor, etc.) can work with email immediately.

### Option 1: Load or install the Skill from the CLI

```powershell
# Print the full Skill playbook directly (for on-the-fly context loading)
mailmaster activate-skill

# Install SKILL.md into the current project or your Agent's global skills folder
mailmaster activate-skill --install project   # .agents/skills/mailmaster/SKILL.md
mailmaster activate-skill --install claude    # ~/.claude/skills/mailmaster/SKILL.md
mailmaster activate-skill --install codex     # ~/.codex/skills/mailmaster/SKILL.md
mailmaster activate-skill --install gemini    # ~/.gemini/config/skills/mailmaster/SKILL.md
mailmaster activate-skill --install cursor    # .cursor/skills/mailmaster/SKILL.md

# Or install to a custom directory / print the bundled SKILL.md path
mailmaster activate-skill --dest C:\path\to\skills
mailmaster activate-skill --path
```

### Option 2: Install from the repository `skill/` directory

The repository root contains [`skill/SKILL.md`](skill/SKILL.md). Copy `skill/` directly into your Agent's skills directory, or install it with a skill manager:

```powershell
npx skills add AndersonBY/mailmaster-cli
```

### Structured JSON output

Pass `--json` (or `--format json`) **before or after** any subcommand for deterministic JSON output:

```powershell
mailmaster accounts --json
mailmaster list --account sender@example.com --unread --limit 10 --json
```

Success envelope:

```json
{"ok": true, "command": "list", "data": {}}
```

Errors (missing local items, invalid arguments, or server rejections) exit with code `2`, print no Python traceback, and include a stable error code and actionable suggestions:

```json
{
  "ok": false,
  "command": "read",
  "error": {"code": "mail_not_found", "message": "...", "details": {}}
}
```

## Common commands

### Check status & accounts

```powershell
# Inspect discovered MailMaster paths and local account count
mailmaster doctor

# List configured accounts (commands accept email, account name, or numeric ID)
mailmaster accounts

# Inspect per-account capabilities and recommended transports
mailmaster capabilities --json
mailmaster capabilities --sendable --mutable --json
mailmaster capabilities --query 163 --json
```

### Read & search locally

Local reads run offline against read-only SQLite snapshots:

```powershell
# List mailboxes
mailmaster mailboxes --account sender@example.com

# List messages (filter by mailbox, unread status, and limit)
mailmaster list --account sender@example.com --mailbox 收件箱 --limit 10
mailmaster list --account sender@example.com --unread --limit 20

# Read a message (accepts LocalId or RemoteId; pass --html for raw HTML)
mailmaster read --account sender@example.com --mail-id 40073

# Search headers, or add --body to search message bodies as well
mailmaster search --account sender@example.com github --body --limit 5
```

### Send mail (text, HTML, Markdown/LaTeX & attachments)

`send-mail` automatically selects SMTP or the 163/Wmsvr private transport based on account capabilities (override with `--transport smtp|wmsvr-private`):

```powershell
# Plain text
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "Weekly update" --body "Progress summary..."

# HTML
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "Notice" --html-body "<p>Hello</p>"

# Markdown + LaTeX (supports --markdown-body or --markdown-file)
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "Notes" `
  --markdown-body "# Summary`n`nValue: `$E = mc^2$`" --latex-mode auto

# Attachments (supported on both SMTP and 163/Wmsvr)
mailmaster send-mail --account sender@example.com `
  --to user@example.com --subject "Report" --body "See attached." `
  --attach C:\path\report.pdf --attach C:\path\data.xlsx
```

Use `mailmaster smtp-send` when you explicitly want SMTP with a custom `--from` address.

### Drafts

Create, update, and send server-side drafts on 163/Wmsvr accounts (with Markdown and attachment support):

```powershell
# Create a draft (returns draft_id and compose_id)
mailmaster save-draft --account user@163.com `
  --to colleague@example.com --subject "Proposal" `
  --body "First draft" --attach C:\path\spec.pdf

# Update that draft using the returned compose_id
mailmaster save-draft --account user@163.com `
  --subject "Proposal v2" --body "Added section 2" --compose-id <compose_id>

# Send a stored draft by ID or newest matching subject (existing attachments carry over automatically)
mailmaster send-draft --account user@163.com --draft-id <draft_id>
mailmaster send-draft --account user@163.com --subject "Proposal v2"
```

### Mark, move, delete & fetch raw source

Mutations support repeating `--mail-id` for batch operations. IMAP accounts run over direct IMAP; 163/Wmsvr accounts use the private protocol and verify remote state in the same session:

```powershell
# Mark read / unread
mailmaster mark-read --account sender@example.com --mail-id 40073
mailmaster mark-unread --account sender@example.com --mail-id 40073 --mail-id 40074

# Move to another mailbox (by folder name or folder ID)
mailmaster move-mail --account sender@example.com --mail-id 40073 --target-mailbox Archive

# Delete messages
mailmaster delete-mail --account sender@example.com --mail-id 40073

# Fetch full RFC822 source to a .eml file (accepts either local numeric ID or RemoteId)
mailmaster fetch-mail --account user@163.com --mail-id 40073 --out message.eml
```

## Python library

```python
from mailmaster import MailMaster

mm = MailMaster()

# List accounts; open by email, account name, or numeric account.id
for account in mm.get_accounts():
    print(account.id, account.email)

acc = mm.open_account("sender@example.com")

# Local reads
for mail in acc.list_mail(limit=5):
    print(mail.local_id, mail.subject)

details = acc.get_details("40073")
print(details.content.text_body)

# Unified send (auto-selects SMTP or 163/Wmsvr; supports Markdown, LaTeX, and attachments)
result = acc.send_mail(
    to=["colleague@example.com"],
    subject="Hello",
    markdown_text="# Hello\n\nSent with `mailmaster`.",
    attachments=[r"C:\path\report.pdf"],
)
print(result["transport"], result["status"])

# Mark read and move
acc.mark_read("40073")
acc.move_mail("40073", target_mailbox="Archive")
```

See [`docs/library-api.md`](docs/library-api.md) for the complete SDK reference (drafts, batch mutations, raw source fetching, errors, skill helpers, and low-level protocol sessions).

## Notes

- Requires Windows with NetEase MailMaster installed and signed in to at least one account (the tool reads its local databases and stored account configs directly—MailMaster does not need to be running).
- Stored credentials are decrypted in memory at runtime only and are never written back to disk.
- On 163/Wmsvr accounts, `delete-mail` performs a permanent server-side delete (it does not move messages to Trash); double-check target IDs before deleting.

## Documentation

- [Agent Skill playbook](skill/SKILL.md)
- [Python SDK & CLI reference](docs/library-api.md)
- [Architecture](docs/architecture.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Reverse-engineering notes](docs/reverse-engineering.md)

## Development

```powershell
python -m pytest -q
python -m ruff check .
python -m ty check
```

## License

MIT. See [`LICENSE`](LICENSE).
