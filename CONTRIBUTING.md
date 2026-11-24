# Contributing

Thanks for improving `mailmaster`.

## Development setup

Requirements: Windows 10/11, Python 3.11+, and a MailMaster installation with
at least one configured account for manual/live checks.

```powershell
# with uv (recommended)
uv sync

# or with a plain virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m pip install pytest ruff
```

Run the CLI from the checkout:

```powershell
python -m mailmaster doctor
python -m mailmaster --format json capabilities
```

## Checks

```powershell
python -m pytest -q
python -m ruff check .
python -m ty check
```

The test suite is offline and uses temporary/fake data. If `dnspython` is
missing from the environment, one SMTP MX-fallback test fails for
environmental reasons; install the project dependencies before treating it as a
regression.

## Code layout

- Keep the CLI layer thin (`src/mailmaster/cli/`); put behavior in `_facade.py`,
  `store.py`, `email_renderer.py`, `smtp.py`, `imap_ops.py`,
  `protocol_config.py`, `wmsvr/`, `wmsvr_mail.py`, or `skill/`.
- Keep `skill/SKILL.md` and `src/mailmaster/skill/SKILL.md` byte-for-byte
  identical when updating the Agent Skill playbook.
- Do not add Frida, browser DevTools, or a running-MailMaster dependency to the
  product path. They may only be used for reverse-engineering evidence.
- Local lookup failures must raise `LocalLookupError` with a stable code and be
  rendered by the CLI as structured JSON, never as a traceback.
- Private writes must keep the read-back verification model: an acknowledged
  request is not success unless the remote state is confirmed.

## Reverse-engineering work

Raw probes, logs, snapshots and one-off scripts belong under
`reverse-engineering/artifacts/` (git-ignored). Keep them sanitized:

- no passwords, tokens, cookies or full account identifiers;
- no real subjects or message bodies;
- prefer sizes, hashes, codes and booleans.

After meaningful protocol findings, record durable conclusions only in
`docs/reverse-engineering.md` rather than pasting chronological experiment logs.

## Pull requests

- Keep changes focused and include tests for behavior changes.
- Run `pytest`, `ruff`, and `ty` before opening a PR.
- Describe the user-visible effect and any platform/account assumptions.
- Never include real credentials or personal mail data in commits, logs or PR
  descriptions.

## License

By contributing, you agree that your contributions are licensed under the MIT
License (see `LICENSE`).
