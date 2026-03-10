# mailmaster Library API

This document describes the recommended Python-library usage of `mailmaster`.

## High-level facade

The preferred entry point is `MailMaster`:

```python
from mailmaster import MailMaster

mm = MailMaster()
accounts = mm.get_accounts()
acc = mm.open_account(accounts[0].email)
```

### `MailMaster`

Common methods:

- `get_accounts()` → list accounts
- `get_account(identifier)` → resolve one account model
- `open_account(identifier)` / `account(identifier)` → get an `AccountAccess`
- `get_mailboxes(account)`
- `list_mail(account, ...)`
- `search_mail(account, query, ...)`
- `get_mail(account, mail_id)`
- `get_details(account, mail_id)`

You may also construct it with explicit paths:

```python
from pathlib import Path
from mailmaster import MailMaster

mm = MailMaster(app_db=Path(r"C:\path\to\app.db"))
```

## Account-level access

`AccountAccess` wraps a single MailMaster account.

```python
acc = mm.open_account("sender@example.com")
mailboxes = acc.get_mailboxes()
mails = acc.list_mail(limit=10)
details = acc.get_details("40073")
```

Common methods:

- `get_mailboxes()`
- `list_mail(...)`
- `search_mail(...)`
- `get_mail(mail_id)`
- `get_details(mail_id)`
- `get_server_configs()`
- `render_markdown_email(markdown_text, latex_mode="auto")`
- `send_email(...)`
- `send_markdown_email(...)`

## Rendering helpers

You can also use the rendering layer directly:

```python
from mailmaster import render_markdown_email

rendered = render_markdown_email("# Title\n\nHello")
print(rendered.plain_text)
print(rendered.html)
```

LaTeX modes:

- `auto`
- `mathml`
- `image`
- `raw`

## SMTP layer

Low-level SMTP helpers are also exported:

```python
from mailmaster import SmtpProfile, send_email, profile_from_server_config
```

For most users, prefer `AccountAccess.send_email()` or `AccountAccess.send_markdown_email()`.
