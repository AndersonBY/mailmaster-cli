# Repository Instructions

Before making changes in this repository, read the relevant documentation:

- `README.md` / `README_EN.md` — overview, installation, and CLI examples
- `docs/architecture.md` — layered module architecture, transport selection, and error/JSON contracts
- `docs/library-api.md` — Python SDK (`MailMaster`, `AccountAccess`, `mailmaster.skill`) and CLI reference
- `skill/SKILL.md` — canonical AI Agent skill playbook
- `docs/reverse-engineering.md` — durable Wmsvr / 163 protocol findings and build anchors

## Working rules

- Extend the layered architecture instead of adding business logic into the CLI layer:
  - Core modules: `src/mailmaster/store.py`, `src/mailmaster/email_renderer.py`, `src/mailmaster/smtp.py`, `src/mailmaster/imap_ops.py`, `src/mailmaster/protocol_config.py`, `src/mailmaster/wmsvr/` (and `src/mailmaster/wmsvr_mail.py`), `src/mailmaster/skill/`, and `src/mailmaster/_facade.py`
  - Thin modular CLI package: `src/mailmaster/cli/`
- Keep `skill/SKILL.md` and `src/mailmaster/skill/SKILL.md` byte-for-byte identical whenever updating the Agent Skill playbook (verified by `tests/test_skill.py`).
- Never introduce Frida, browser DevTools, or a running-MailMaster dependency into the user-facing product path.
- Preserve read-back verification for Wmsvr private-protocol writes and structured JSON error envelopes (`ok`, `command`, `error`, exit code `2`) for CLI failures.
- Keep all docs, tests, and examples free of real credentials, tokens, cookies, or personal email data.

## Product path

The supported product path works offline for reads and directly over network protocols for writes, with no Frida, browser DevTools, or running MailMaster process required:

- local SQLite read via cached read-only snapshots
- in-memory dynamic protocol-config decryption
- direct SMTP send (plain text, HTML, Markdown/LaTeX, attachments)
- direct IMAP mutations for IMAP accounts
- Wmsvr / 163 private-protocol read (with local-to-remote ID auto-resolution), send, draft, attachment, and mutation workflows with in-session read-back verification
- Agent-first CLI ergonomics: bundled `skill/SKILL.md` + `mailmaster activate-skill`, flexible `--json` / `--format json` placement, grouped help panels, and structured JSON errors with actionable suggestions

## Reverse-engineering hygiene

- Prefer offline static analysis over live probing for Wmsvr / 163 work.
- Keep raw probe logs and scripts under `reverse-engineering/artifacts/` (git-ignored) and record only durable conclusions in `docs/reverse-engineering.md`.

## Verification

Run before committing or opening a pull request:

```powershell
python -m pytest -q
python -m ruff check .
python -m ty check
```
