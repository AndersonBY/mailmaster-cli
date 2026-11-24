"""Local read, account inspection, and remote source fetch CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from ..store import LocalLookupError
from . import _emit, _emit_error, app
from .errors import _emit_fetch_unsupported, _emit_local_lookup_error, _render_failure
from .render import (
    console,
    print_accounts,
    print_capabilities,
    print_mail_details,
    print_mail_list,
    print_mailboxes,
)


@app.command(rich_help_panel="Setup & Skill")
def doctor() -> None:
    """Check MailMaster installation paths, local database, and discovered accounts."""
    from . import commands as _commands

    paths, store = _commands._paths_and_store()
    accounts_list = store.get_accounts()
    def _render() -> None:
        console.print(f"install_root: {paths.install_root}")
        console.print(f"launcher_exe: {paths.launcher_exe}")
        console.print(f"local_root: {paths.local_root}")
        console.print(f"app_db: {paths.app_db}")
        console.print(f"accounts_root: {paths.accounts_root}")
        console.print()
        print_accounts(accounts_list)

    _emit(
        "doctor",
        {"paths": paths, "accounts": accounts_list, "account_count": len(accounts_list)},
        _render,
    )


@app.command(rich_help_panel="Setup & Skill")
def accounts() -> None:
    """List local MailMaster accounts with their numeric IDs and emails."""
    from . import commands as _commands

    _, store = _commands._paths_and_store()
    accounts_list = store.get_accounts()
    _emit("accounts", accounts_list, lambda: print_accounts(accounts_list))


@app.command(rich_help_panel="Setup & Skill")
def capabilities(
    account: str | None = typer.Option(
        None, "--account", help="Account email or numeric ID from 'mailmaster accounts'."
    ),
    query: str = typer.Option("", "--query", help="Case-insensitive filter against account email or name."),
    readable: bool = typer.Option(False, "--readable", help="Only include accounts that support local read."),
    sendable: bool = typer.Option(
        False,
        "--sendable",
        help="Only include accounts that support sending (SMTP or Wmsvr private protocol).",
    ),
    mutable: bool = typer.Option(
        False,
        "--mutable",
        help="Only include accounts that support mailbox actions (IMAP or Wmsvr private protocol).",
    ),
    bootstrap: bool = typer.Option(
        False, "--bootstrap", help="Only include accounts with Wmsvr bootstrap configuration."
    ),
    path: list[str] = typer.Option(
        [], "--path", help="Require capability path(s). Repeatable (e.g. smtp-send, wmsvr-private-send)."
    ),
) -> None:
    """Inspect supported read, send, draft, and mailbox-action capabilities per account.

    Examples:
      mailmaster capabilities --json
      mailmaster capabilities --account 1 --json
    """
    from .._facade import MailMaster

    mm = MailMaster()
    filters = {
        "account": account,
        "query": query or None,
        "require_local_read": readable,
        "require_send": sendable,
        "require_mutation": mutable,
        "require_wmsvr_bootstrap": bootstrap,
        "require_paths": path or None,
    }

    if account is None:
        items = mm.list_capabilities(
            query=query or None,
            require_local_read=readable,
            require_send=sendable,
            require_mutation=mutable,
            require_wmsvr_bootstrap=bootstrap,
            require_paths=path or None,
        )
    else:
        try:
            item = mm.get_capabilities(account)
        except LocalLookupError as exc:
            _emit_local_lookup_error("capabilities", exc, account=account)
        items = [
            item
            for item in [item]
            if item.matches(
                query=query or None,
                require_local_read=readable,
                require_send=sendable,
                require_mutation=mutable,
                require_wmsvr_bootstrap=bootstrap,
                require_paths=path or None,
            )
        ]

    _emit(
        "capabilities",
        {"accounts": items, "count": len(items), "filters": filters},
        lambda: print_capabilities(items),
    )


@app.command(name="wmsvr-bootstrap", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_bootstrap(
    account: str | None = typer.Option(
        None, "--account", help="Optional account email or numeric ID from 'mailmaster accounts'."
    ),
    service_type: list[int] = typer.Option(
        [], "--service-type", help="Filter server locate entries by service type. Repeatable."
    ),
) -> None:
    """Inspect persisted Wmsvr device metadata and candidate server peers from app.db."""
    from .._facade import MailMaster

    mm = MailMaster()
    try:
        bootstrap = mm.get_wmsvr_bootstrap(account)
        account_email = mm.get_account(account).email if account is not None else None
    except LocalLookupError as exc:
        _emit_local_lookup_error("wmsvr-bootstrap", exc, account=account or "")
    locate_entries = bootstrap.get_locate_entries(
        account=account_email,
        service_types=service_type or None,
    )
    candidate_peers = bootstrap.get_candidate_peers(
        account=account_email,
        service_types=service_type or None,
    )

    def _render() -> None:
        console.print(f"account: {account_email or '(all)'}")
        console.print(f"app_db: {bootstrap.app_db_path}")
        console.print(f"app_version: {bootstrap.master_device_info.app_version}")
        console.print(f"device_id: {bootstrap.master_device_info.device_id or bootstrap.fake_device_id}")
        console.print(f"master_sdid: {bootstrap.master_sdid}")
        console.print(f"master_fp: {bootstrap.master_fp}")
        console.print(f"webui_pub_key: {'present' if bootstrap.webui_pub_key else 'missing'}")
        console.print(f"locate_entries: {len(locate_entries)}")
        console.print(f"candidate_peers: {len(candidate_peers)}")
        for entry in locate_entries:
            candidates = ", ".join(f"{item.host}:{item.port}" for item in entry.candidates[:6])
            console.print(
                f"- service={entry.service_type} scope={entry.locate_id.user or 'global'} "
                f"prefer_ipv6={entry.prefer_ipv6} candidates={candidates}"
            )

    _emit(
        "wmsvr-bootstrap",
        {
            "account": account_email,
            "service_types": service_type or None,
            "bootstrap": bootstrap,
            "locate_entries": locate_entries,
            "candidate_peers": candidate_peers,
        },
        _render,
    )


@app.command(rich_help_panel="Read & Search")
def mailboxes(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
) -> None:
    """List local mailboxes (folders) and message counts for an account."""
    from . import commands as _commands

    paths, store = _commands._paths_and_store()
    try:
        account_obj = store.get_account(account)
        mailboxes_list = _commands.AccountStore(account_obj, install_root=paths.install_root).get_mailboxes()
    except LocalLookupError as exc:
        _emit_local_lookup_error("mailboxes", exc, account=account)
    _emit("mailboxes", {"account": account_obj, "mailboxes": mailboxes_list}, lambda: print_mailboxes(mailboxes_list))


@app.command(name="list", rich_help_panel="Read & Search")
def list_mails(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mailbox: str | None = typer.Option(
        None, "--mailbox", help="Mailbox display name or ID from 'mailmaster mailboxes'."
    ),
    unread: bool = typer.Option(False, "--unread", help="Only show unread messages."),
    limit: int = typer.Option(20, "--limit", min=1, max=200, help="Maximum number of messages to return (1-200)."),
) -> None:
    """List messages from the local MailMaster database (fast, offline).

    Examples:
      mailmaster list --account 1 --unread --limit 10 --json
      mailmaster list --account user@163.com --mailbox INBOX --json
    """
    from . import commands as _commands

    paths, store = _commands._paths_and_store()
    try:
        records = _commands.AccountStore(store.get_account(account), install_root=paths.install_root).list_mail(
            mailbox=mailbox,
            unread_only=unread,
            limit=limit,
        )
    except LocalLookupError as exc:
        _emit_local_lookup_error("list", exc, account=account, mailbox=mailbox)
    _emit(
        "list",
        {"account": account, "mailbox": mailbox, "unread": unread, "limit": limit, "records": records},
        lambda: print_mail_list(records),
    )


@app.command(rich_help_panel="Read & Search")
def read(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mail_id: str = typer.Option(..., "--mail-id", help="LocalId or RemoteId from 'mailmaster list'."),
    html: bool = typer.Option(False, "--html", help="Return raw HTML body instead of extracted plain text."),
) -> None:
    """Read one message's headers, metadata, and decoded body from the local store.

    Examples:
      mailmaster read --account 1 --mail-id 12345 --json
      mailmaster read --account user@163.com --mail-id 12345 --html
    """
    from . import commands as _commands

    paths, store = _commands._paths_and_store()
    try:
        details = _commands.AccountStore(store.get_account(account), install_root=paths.install_root).get_details(mail_id)
    except LocalLookupError as exc:
        _emit_local_lookup_error("read", exc, account=account, mail_ids=[mail_id])
    _emit(
        "read",
        {
            "account": account,
            "mail_id": mail_id,
            "show_html": html,
            "details": details,
            "rendered_body": details.content.html_body if html else details.content.text_body,
        },
        lambda: print_mail_details(details, show_html=html),
    )


@app.command(rich_help_panel="Read & Search")
def search(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    query: str = typer.Argument(..., help="Case-insensitive search keyword."),
    mailbox: str | None = typer.Option(
        None, "--mailbox", help="Mailbox display name or ID from 'mailmaster mailboxes'."
    ),
    body: bool = typer.Option(False, "--body", help="Also search decoded message body text."),
    limit: int = typer.Option(20, "--limit", min=1, max=100, help="Maximum number of matches to return (1-100)."),
) -> None:
    """Search local messages by subject, sender, summary, and optionally body text.

    Examples:
      mailmaster search --account 1 invoice --json
      mailmaster search --account user@163.com "quarterly report" --body --limit 10 --json
    """
    from . import commands as _commands

    paths, store = _commands._paths_and_store()
    try:
        records = _commands.AccountStore(store.get_account(account), install_root=paths.install_root).search_mail(
            query,
            mailbox=mailbox,
            limit=limit,
            include_body=body,
        )
    except LocalLookupError as exc:
        _emit_local_lookup_error("search", exc, account=account, mailbox=mailbox)
    _emit(
        "search",
        {"account": account, "query": query, "mailbox": mailbox, "body": body, "limit": limit, "records": records},
        lambda: print_mail_list(records),
    )


@app.command(name="fetch-mail", rich_help_panel="Read & Search")
def fetch_mail(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mail_id: str = typer.Option(
        ...,
        "--mail-id",
        help="Message LocalId or RemoteId (<fid>:<mid>) from 'mailmaster list'; local numeric IDs auto-resolve.",
    ),
    part: int = typer.Option(
        -1, "--part", help="Fetch a specific server part slot instead of auto-scanning (-1: auto-scan)."
    ),
    offset: int = typer.Option(0, "--offset", help="Byte offset within the requested part (requires --part)."),
    max_part: int = typer.Option(8, "--max-part", help="Maximum part slot index to scan when --part is omitted."),
    out: Path | None = typer.Option(None, "--out", help="Write the raw RFC822 message bytes to this file path."),
) -> None:
    """Fetch a message's raw RFC822 source (headers, body, and attachments) from a 163/Wmsvr server.

    Examples:
      mailmaster fetch-mail --account user@163.com --mail-id 12345 --out message.eml --json
      mailmaster fetch-mail --account 7 --mail-id "755:<mid>" --json
    """
    from .._facade import MailMaster

    mm = MailMaster()
    try:
        capability = mm.get_capabilities(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error("fetch-mail", exc, account=account)
    if not capability.supports_wmsvr_private_read:
        _emit_fetch_unsupported(capability)
    _run_wmsvr_fetch_mail(
        mm,
        account,
        mail_id,
        part=None if part < 0 else part,
        offset=offset,
        max_part=max_part,
        out=out,
    )


def _run_wmsvr_fetch_mail(
    mm: Any,
    account: str,
    mail_id: str,
    *,
    part: int | None,
    offset: int,
    max_part: int,
    out: Path | None,
) -> None:
    """Fetch raw RFC822 message source over the Wmsvr private protocol."""
    from ..wmsvr_mail import WmsvrMailError

    try:
        result = mm.fetch_mail_source(account, mail_id, part=part, offset=offset, max_part=max_part)
    except ValueError as exc:
        message = str(exc)
        _emit_error(
            command="fetch-mail",
            code="fetch_invalid",
            message=message,
            details={"account": account, "mail_id": mail_id, "part": part, "offset": offset},
            text_renderer=lambda: _render_failure(message, []),
        )
    except WmsvrMailError as exc:
        message = exc.message
        _emit_error(
            command="fetch-mail",
            code=exc.code,
            message=message,
            details={
                "account": account,
                "mail_id": mail_id,
                "part": part,
                "offset": offset,
                "max_part": max_part,
                **exc.details,
            },
            text_renderer=lambda: _render_failure(
                message,
                [
                    "Omit --part to auto-scan for the RFC822 source slot, or increase --max-part.",
                    f"Verify the message ID with: mailmaster --json list --account {account}",
                ],
            ),
        )
    source = result.get("source") or b""
    written = None
    if out is not None:
        out.write_bytes(source)
        written = len(source)
    _emit(
        "fetch-mail",
        {
            "account": account,
            "mail_id": result.get("mid"),
            "status": "fetched",
            "transport": "wmsvr-private",
            "method": result.get("method"),
            "mode": result.get("mode"),
            "part_slot": result.get("part_slot"),
            "offset": result.get("offset"),
            "length": result.get("length"),
            "sha256": result.get("sha256"),
            "source_slots": result.get("source_slots"),
            "candidates": result.get("candidates"),
            "misses": result.get("misses"),
            "out": str(out) if out is not None else None,
            "bytes_written": written,
        },
        lambda: console.print(
            f"[green]Fetched {result.get('length')} bytes from slot {result.get('part_slot')} "
            f"over the Wmsvr private protocol (sha256 {str(result.get('sha256'))[:12]})"
            + (f", written to {out}.[/green]" if out is not None else ".[/green]")
        ),
    )
