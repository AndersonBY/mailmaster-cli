# mailmaster

`mailmaster` is a Windows command-line tool for reading local NetEase MailMaster data and sending email via dynamically decrypted SMTP credentials.

It is designed to work well both for humans and for automation / AI agents.

## Install

### With `uv tool install`

```powershell
uv tool install mailmaster
```

After installation, use:

```powershell
mailmaster doctor
```

### Without installation via `uvx`

```powershell
uvx mailmaster doctor
```

If you want optional LaTeX image rendering support:

```powershell
uv tool install "mailmaster[latex-image]"

# or one-off
uvx --with "mailmaster[latex-image]" mailmaster doctor
```

## Core features

- Read account list, mailboxes, mail list, and mail details from local MailMaster databases
- Search local mail data
- Send mail through dynamically decrypted SMTP configuration
- Support plain text, HTML, Markdown, local inline images, file attachments, and LaTeX rendering modes
- Support structured JSON output for agents and scripts

## Output formats

All commands support a global `--format` option:

```powershell
# Human-friendly output
mailmaster accounts

# Structured JSON output
mailmaster --format json accounts
mailmaster --format json smtp-send --from sender@example.com --to user@example.com --subject "Test" --body "Hello"
```

JSON output uses a stable wrapper like:

```json
{
  "ok": true,
  "command": "accounts",
  "data": {}
}
```

## Quick start

### Use as a Python library

```python
from mailmaster import MailMaster

mm = MailMaster()

for account in mm.get_accounts():
    print(account.email)

acc = mm.open_account("sender@example.com")

for mail in acc.list_mail(limit=5):
    print(mail.subject)

details = acc.get_details("40073")
print(details.content.text_body)

acc.send_markdown_email(
    to=["user@example.com"],
    subject="Hello",
    markdown_text="# Title\n\nHello from the library API.",
)
```

### Inspect local mail data

```powershell
mailmaster doctor
mailmaster accounts
mailmaster mailboxes --account sender@example.com
mailmaster list --account sender@example.com --mailbox 收件箱 --limit 10
mailmaster read --account sender@example.com --mail-id 40073
mailmaster search --account sender@example.com github --body --limit 5
```

### Mutate mail state via IMAP

```powershell
# Mark as read
mailmaster mark-read --account sender@example.com --mail-id 40073

# Mark as unread
mailmaster mark-unread --account sender@example.com --mail-id 40073

# Move to another mailbox
mailmaster move-mail --account sender@example.com --mail-id 40073 --target-mailbox Archive

# Delete mail
mailmaster delete-mail --account sender@example.com --mail-id 40073
```

### Send email

`smtp-send` dynamically resolves and decrypts the current account's SMTP settings at send time. Decrypted credentials are not stored in an extra local config file.

#### Plain text

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Test" \
    --body "Hello from mailmaster"
```

#### HTML

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "HTML email" \
    --html-body "<h1>Hello</h1><p>This is an HTML email.</p>"
```

#### Markdown

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Markdown email" \
    --markdown-body "# Title\n\n- item 1\n- item 2\n\n**bold**"
```

#### Markdown from file

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Markdown file" \
    --markdown-file .\mail.md
```

#### Markdown from stdin

```powershell
Get-Content .\mail.md | mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "Markdown stdin" \
    --markdown-file -
```

#### Inline local images in Markdown

If a Markdown file contains a local image, it will be embedded inline in the email body.

Example Markdown:

```markdown
![Screenshot](C:/path/to/image.png)
```

#### File attachments

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "With attachment" \
    --body "See attachment." \
    --attach C:\path\to\attachment.png
```

Repeat `--attach` to add multiple attachments.

### LaTeX rendering modes

LaTeX is supported in Markdown bodies through three modes:

- `auto` (default): use image rendering if optional image support is installed, otherwise fall back to `raw`
- `mathml`: lightweight dependency path, but client rendering quality may vary
- `image`: best visual result, requires `mailmaster[latex-image]`
- `raw`: render formulas as raw code-like text

#### Default auto mode

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "LaTeX auto" \
    --markdown-body "Inline formula $E=mc^2$"
```

#### Force MathML mode

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "LaTeX MathML" \
    --markdown-body "Formula $E=mc^2$" \
    --latex-mode mathml
```

#### Force image mode

```powershell
mailmaster smtp-send \
    --from sender@example.com \
    --to user@example.com \
    --subject "LaTeX image" \
    --markdown-body "Formula $\\alpha + \\beta$" \
    --latex-mode image
```

## Publishing intent

This project is configured so it can be published to PyPI and used via:

- `uv tool install mailmaster`
- `uvx mailmaster ...`

The package exposes both console entry points:

- `mailmaster`
- `mailmaster`

## Reverse engineering notes

Current reverse-engineering notes are maintained in:

- `docs/reverse-engineering.md`

Library-oriented usage notes are maintained in:

- `docs/library-api.md`
