# Security policy

## Supported versions

`0.1.x` is the current beta line. Security fixes are applied to the latest
release.

## Reporting a vulnerability

Please do not open a public issue containing credentials, tokens, cookies,
mail contents, or a real `app.db`.

If the repository is hosted on GitHub, use a private security advisory. If that
is not available, contact the maintainer through the repository's private
contact channel and include only:

- the affected command/version;
- a minimal reproduction with redacted account and message data;
- the observed impact.

## Sensitive local data

`mailmaster` reads MailMaster's local databases and decrypts protocol
configuration in memory. Treat the following as secrets:

- account passwords and SMTP/IMAP credentials;
- Wmsvr tokens, cookies and device material;
- `app.db`, `mail.db`, `content.db` and exported raw message sources;
- message bodies, subjects, addresses and attachment contents.

The CLI redacts secret fields by default. The `wmsvr-login-context
--show-secrets` switch is intentionally explicit; do not use it when pasting
output into an issue.

## Operational safety

- `delete-mail` on the Wmsvr private path is a server-side **hard delete**. It
  does not move the message to Trash and cannot be undone by the tool.
- Private-protocol operations log in for each call; there is no long-lived
  session cache.
- The tool is Windows-only and depends on a previously configured MailMaster
  installation.
- Frida, browser DevTools and a running MailMaster process are not part of the
  supported product path.
