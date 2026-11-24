"""Mailbox mutation CLI commands (mark-read, mark-unread, move-mail, delete-mail)."""

from __future__ import annotations

from typing import Any

import typer

from . import _emit, _emit_error, app
from .errors import _emit_mail_not_found, _ensure_mutation_capability, _render_failure
from .render import console


def _run_wmsvr_delete_mutation(mm: Any, account: str, mail_ids: list[str]) -> None:
    """Delete mail over the private protocol and report the verified removal."""
    from ..wmsvr_mail import WmsvrMailError

    try:
        outcome = mm.delete_mail_verified(account, mail_ids)
    except WmsvrMailError as exc:
        details = {"account": account, "mail_ids": mail_ids, **exc.details}
        message = exc.message
        _emit_error(
            command="delete-mail",
            code=exc.code,
            message=message,
            details=details,
            text_renderer=lambda: _render_failure(
                message,
                [
                    f"List current local messages: mailmaster --json list --account {account}",
                    f"Inspect account capabilities: mailmaster --json capabilities --account {account}",
                ],
            ),
        )
    except ValueError as exc:
        _emit_mail_not_found("delete-mail", account, mail_ids, exc)
    result = outcome["result"]
    records = outcome["records"]
    _emit(
        "delete-mail",
        {
            "account": account,
            "mail_ids": mail_ids,
            "records": records,
            "count": len(records),
            "status": "deleted",
            "transport": "wmsvr-private",
            "server_code": result.get("code"),
            "delete_type": result.get("delete_type"),
            "remote_folders_before": result.get("remote_folders_before"),
            "remote_folders_after": result.get("remote_folders_after"),
            "gone": result.get("gone"),
            "state_change_verified": result.get("state_change_verified"),
        },
        lambda: console.print(
            f"[green]Deleted {len(records)} mail(s) over the Wmsvr private protocol "
            f"(server {result.get('code')}, removal verified).[/green]"
        ),
    )


def _run_wmsvr_flag_mutation(
    mm: Any,
    account: str,
    mail_ids: list[str],
    *,
    read: bool,
    command: str,
    status: str,
) -> None:
    """Mark read/unread over the private protocol and report the verified change."""
    from ..wmsvr_mail import WmsvrMailError

    try:
        outcome = mm.mark_read_verified(account, mail_ids) if read else mm.mark_unread_verified(account, mail_ids)
    except WmsvrMailError as exc:
        details = {"account": account, "mail_ids": mail_ids, **exc.details}
        message = exc.message
        _emit_error(
            command,
            code=exc.code,
            message=message,
            details=details,
            text_renderer=lambda: _render_failure(
                message,
                [
                    f"Inspect account capabilities: mailmaster --json capabilities --account {account}",
                    f"Verify the message ID with: mailmaster --json list --account {account}",
                ],
            ),
        )
    except ValueError as exc:
        _emit_mail_not_found(command, account, mail_ids, exc)
    result = outcome["result"]
    records = outcome["records"]
    _emit(
        command,
        {
            "account": account,
            "mail_ids": mail_ids,
            "records": records,
            "count": len(records),
            "status": status,
            "transport": "wmsvr-private",
            "server_code": result.get("code"),
            "remote_flags_before": result.get("remote_flags_before"),
            "remote_flags_after": result.get("remote_flags_after"),
            "state_change_verified": result.get("state_change_verified"),
        },
        lambda: console.print(
            f"[green]Marked {len(records)} mail(s) as {status} over the Wmsvr private protocol "
            f"(server {result.get('code')}, remote state change verified).[/green]"
        ),
    )


@app.command(name="mark-read", rich_help_panel="Mailbox Actions")
def mark_read(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mail_id: list[str] = typer.Option(
        ..., "--mail-id", help="LocalId or RemoteId from 'mailmaster list'. Repeatable."
    ),
) -> None:
    """Mark one or more messages as read on the mail server (IMAP or 163/Wmsvr)."""
    from .._facade import MailMaster

    mm = MailMaster()
    capability = _ensure_mutation_capability(mm, account, command="mark-read", mail_ids=mail_id)
    if not capability.supports_imap_mutations and capability.supports_wmsvr_private_mutations:
        _run_wmsvr_flag_mutation(mm, account, mail_id, read=True, command="mark-read", status="read")
        return
    try:
        records = mm.mark_read_many(account, mail_id)
    except ValueError as exc:
        _emit_mail_not_found("mark-read", account, mail_id, exc)
    _emit(
        "mark-read",
        {
            "account": account,
            "mail_ids": mail_id,
            "records": records,
            "count": len(records),
            "status": "read",
            "transport": "imap",
        },
        lambda: console.print(f"Marked {len(records)} mail(s) as read."),
    )


@app.command(name="mark-unread", rich_help_panel="Mailbox Actions")
def mark_unread(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mail_id: list[str] = typer.Option(
        ..., "--mail-id", help="LocalId or RemoteId from 'mailmaster list'. Repeatable."
    ),
) -> None:
    """Mark one or more messages as unread on the mail server (IMAP or 163/Wmsvr)."""
    from .._facade import MailMaster

    mm = MailMaster()
    capability = _ensure_mutation_capability(mm, account, command="mark-unread", mail_ids=mail_id)
    if not capability.supports_imap_mutations and capability.supports_wmsvr_private_mutations:
        _run_wmsvr_flag_mutation(mm, account, mail_id, read=False, command="mark-unread", status="unread")
        return
    try:
        records = mm.mark_unread_many(account, mail_id)
    except ValueError as exc:
        _emit_mail_not_found("mark-unread", account, mail_id, exc)
    _emit(
        "mark-unread",
        {
            "account": account,
            "mail_ids": mail_id,
            "records": records,
            "count": len(records),
            "status": "unread",
            "transport": "imap",
        },
        lambda: console.print(f"Marked {len(records)} mail(s) as unread."),
    )


def _run_wmsvr_folder_mutation(
    mm: Any,
    account: str,
    mail_ids: list[str],
    *,
    target_mailbox: str,
) -> None:
    """Move mail over the private protocol and report the verified folder change."""
    from ..wmsvr_mail import WmsvrMailError

    try:
        outcome = mm.move_mail_verified(account, mail_ids, target_mailbox=target_mailbox)
    except WmsvrMailError as exc:
        details = {"account": account, "mail_ids": mail_ids, **exc.details}
        message = exc.message
        _emit_error(
            command="move-mail",
            code=exc.code,
            message=message,
            details=details,
            text_renderer=lambda: _render_failure(
                message,
                [
                    f"List available mailbox names and numeric IDs: mailmaster --json mailboxes --account {account}",
                ],
            ),
        )
    except ValueError as exc:
        _emit_mail_not_found("move-mail", account, mail_ids, exc)
    result = outcome["result"]
    records = outcome["records"]
    _emit(
        "move-mail",
        {
            "account": account,
            "mail_ids": mail_ids,
            "records": records,
            "count": len(records),
            "target_mailbox": target_mailbox,
            "transport": "wmsvr-private",
            "server_code": result.get("code"),
            "target_fid": result.get("target_fid"),
            "remote_folders_before": result.get("remote_folders_before"),
            "remote_folders_after": result.get("remote_folders_after"),
            "state_change_verified": result.get("state_change_verified"),
        },
        lambda: console.print(
            f"[green]Moved {len(records)} mail(s) to {target_mailbox} over the Wmsvr private protocol "
            f"(fid {result.get('target_fid')}, remote folder change verified).[/green]"
        ),
    )


@app.command(name="move-mail", rich_help_panel="Mailbox Actions")
def move_mail(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mail_id: list[str] = typer.Option(
        ..., "--mail-id", help="LocalId or RemoteId from 'mailmaster list'. Repeatable."
    ),
    target_mailbox: str = typer.Option(
        ..., "--target-mailbox", help="Destination mailbox display name or numeric ID from 'mailmaster mailboxes'."
    ),
) -> None:
    """Move one or more messages to another mailbox on the server (IMAP or 163/Wmsvr).

    Examples:
      mailmaster move-mail --account 1 --mail-id 12345 --target-mailbox Archive --json
      mailmaster move-mail --account user@163.com --mail-id 12345 --target-mailbox 7 --json
    """
    from .._facade import MailMaster

    mm = MailMaster()
    capability = _ensure_mutation_capability(mm, account, command="move-mail", mail_ids=mail_id)
    if not capability.supports_imap_mutations and capability.supports_wmsvr_private_mutations:
        _run_wmsvr_folder_mutation(mm, account, mail_id, target_mailbox=target_mailbox)
        return
    try:
        records = mm.move_mail_many(account, mail_id, target_mailbox=target_mailbox)
    except ValueError as exc:
        _emit_mail_not_found("move-mail", account, mail_id, exc)
    _emit(
        "move-mail",
        {
            "account": account,
            "mail_ids": mail_id,
            "records": records,
            "count": len(records),
            "target_mailbox": target_mailbox,
            "transport": "imap",
        },
        lambda: console.print(f"Moved {len(records)} mail(s) to {target_mailbox}."),
    )


@app.command(name="delete-mail", rich_help_panel="Mailbox Actions")
def delete_mail(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    mail_id: list[str] = typer.Option(
        ..., "--mail-id", help="LocalId or RemoteId from 'mailmaster list'. Repeatable."
    ),
) -> None:
    """Delete one or more messages from the mail server (IMAP or 163/Wmsvr).

    Note: on 163/Wmsvr accounts this permanently deletes the message on the server rather than moving it to Trash.

    Examples:
      mailmaster delete-mail --account 1 --mail-id 12345 --json
      mailmaster delete-mail --account user@163.com --mail-id 12345 --mail-id 12346 --json
    """
    from .._facade import MailMaster

    mm = MailMaster()
    capability = _ensure_mutation_capability(mm, account, command="delete-mail", mail_ids=mail_id)
    if not capability.supports_imap_mutations and capability.supports_wmsvr_private_mutations:
        _run_wmsvr_delete_mutation(mm, account, mail_id)
        return
    try:
        records = mm.delete_mail_many(account, mail_id)
    except ValueError as exc:
        _emit_mail_not_found("delete-mail", account, mail_id, exc)
    _emit(
        "delete-mail",
        {
            "account": account,
            "mail_ids": mail_id,
            "records": records,
            "count": len(records),
            "status": "deleted",
        },
        lambda: console.print(f"Deleted {len(records)} mail(s)."),
    )
