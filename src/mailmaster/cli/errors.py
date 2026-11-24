"""Structured CLI error rendering and capability guard helpers."""

from __future__ import annotations

import json
import smtplib
from typing import Any, NoReturn

from ..models import AccountCapabilities
from ..store import LocalLookupError
from ..wmsvr import (
    WMSVR_METHOD_DELETE_MESSAGES,
    WMSVR_METHOD_UPDATE_MESSAGE_INFOS,
    build_update_message_infos_body,
)
from . import _emit_error
from .render import console


def _render_failure(message: str, suggestions: list[str]) -> None:
    console.print(f"[red]{message}[/red]")
    if suggestions:
        console.print("[bold]Next steps:[/bold]")
        for item in suggestions:
            console.print(f"- {item}")


def _ensure_send_capability(mm: Any, account: str, *, command: str) -> None:
    try:
        capability = mm.get_capabilities(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error(command, exc, account=account)
    if capability.supports_smtp_send:
        return
    message = f"Account {capability.email} does not have a usable SMTP configuration."
    suggestions = [
        f"Inspect account capabilities: mailmaster --json capabilities --account {capability.email}",
        "Choose an account with recommended_send_method = smtp.",
    ]
    if capability.supports_local_read:
        suggestions.append("Local read commands remain available: list, read, search.")
    if capability.supports_wmsvr_private_send:
        suggestions.append(
            f"Send via the Wmsvr private protocol instead: mailmaster --json send-mail --account {capability.email} --transport wmsvr-private --to <recipient> --subject <subject> --body <body>"
        )
    elif capability.supports_wmsvr_bootstrap:
        suggestions.append(
            "Wmsvr bootstrap data is present; once credentials and device metadata are complete, use 'mailmaster send-mail --transport wmsvr-private'."
        )
    _emit_error(
        command,
        code="smtp_send_unsupported",
        message=message,
        details={
            "account": capability.email,
            "required_capability": "supports_smtp_send",
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _ensure_mutation_capability(
    mm: Any,
    account: str,
    *,
    command: str,
    mail_ids: list[str] | None = None,
) -> AccountCapabilities:
    """Return capabilities once a mutation transport (IMAP or Wmsvr) is available."""
    try:
        capability = mm.get_capabilities(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error(command, exc, account=account)
    if capability.supports_imap_mutations or capability.supports_wmsvr_private_mutations:
        return capability
    if capability.has_wmsvr_config:
        _raise_wmsvr_session_gap(mm, account, capability, command=command, mail_ids=mail_ids)
    message = f"Account {capability.email} does not support mailbox actions (no IMAP or Wmsvr write transport configured)."
    suggestions = [
        f"Inspect account capabilities: mailmaster --json capabilities --account {capability.email}",
        "Choose an account with recommended_mutation_method = imap or wmsvr-private.",
    ]
    if capability.supports_local_read:
        suggestions.append("Local read commands remain available: list, read, search.")
    if capability.supports_smtp_send:
        suggestions.append("Sending over SMTP remains available.")
    if capability.supports_wmsvr_bootstrap:
        suggestions.append(
            "Wmsvr mailbox actions require a stored password and local device metadata (MasterFP/MasterSdid)."
        )
    _emit_error(
        command,
        code="imap_mutation_unsupported",
        message=message,
        details={
            "account": capability.email,
            "required_capability": "supports_imap_mutations",
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _raise_wmsvr_session_gap(
    mm: Any,
    account: str,
    capability: AccountCapabilities,
    *,
    command: str,
    mail_ids: list[str] | None = None,
) -> NoReturn:
    """Report the missing prerequisite preventing a Wmsvr private-protocol action."""
    ready: dict[str, object] = {
        "method": WMSVR_METHOD_UPDATE_MESSAGE_INFOS,
        "move_body": '{"attrs":{"fid":<targetFid>},"ids":[...]}',
        "delete_method": WMSVR_METHOD_DELETE_MESSAGES,
        "delete_body": '{"deleteType":"batch","ids":[...]}',
        "captured_len0": 624,
        "body_matches_capture": True,
    }
    read: bool | None = None
    if command == "mark-read":
        read = True
    elif command == "mark-unread":
        read = False
    if read is not None and mail_ids:
        remote_ids: list[str] = []
        for mail_id in mail_ids:
            try:
                remote_ids.append(mm.get_mail(account, mail_id).remote_id)
            except Exception:
                remote_ids = []
                break
        if remote_ids and all(remote_ids):
            body = build_update_message_infos_body(remote_ids, read=read)
            ready["ids"] = remote_ids
            ready["body_json"] = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        else:
            ready["ids_note"] = (
                "Pass --mail-id values from 'mailmaster list': each message's RemoteId uses <fid>:<mid> format."
            )
    elif command == "delete-mail":
        ready["note"] = (
            "Private delete permanently removes messages on the server using batch delete."
        )
    reason = capability.wmsvr_private_mutation_reason or "unknown"
    message = (
        f"Account {capability.email} cannot open a Wmsvr session for '{command}': {reason}."
    )
    suggestions = [
        f"Inspect missing prerequisites: mailmaster --json capabilities --account {capability.email}",
        f"Check local Wmsvr login inputs (passwords redacted): mailmaster --json wmsvr-login-context --account {capability.email}",
        "Local read commands (list, read, search) remain available.",
    ]
    _emit_error(
        command,
        code="wmsvr_session_required",
        message=message,
        details={
            "account": capability.email,
            "required_capability": "supports_wmsvr_private_mutations",
            "unavailable_reason": reason,
            "missing_envelope_records": ["0x0101 token", "0x0102 route"],
            "ready_request": ready,
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _emit_send_unsupported(
    capability: AccountCapabilities,
    *,
    command: str,
    requested: str,
    transport: str,
) -> NoReturn:
    """Report that no usable send transport is available for this account."""
    if requested == "auto":
        message = (
            f"Account {capability.email} has no available send transport "
            "(neither SMTP nor Wmsvr private send is configured)."
        )
    else:
        message = (
            f"Account {capability.email} does not support the '{transport}' send transport."
        )
    suggestions = [
        f"Inspect available transports: mailmaster --json capabilities --account {capability.email}",
        "Find sendable accounts: mailmaster --json capabilities --sendable",
    ]
    if capability.supports_wmsvr_bootstrap:
        suggestions.append(
            "Wmsvr private send requires a stored password, candidate d1 peers, and local device metadata."
        )
    _emit_error(
        command,
        code="send_unsupported",
        message=message,
        details={
            "account": capability.email,
            "requested_transport": requested,
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _emit_draft_send_unsupported(capability: AccountCapabilities) -> NoReturn:
    """Report that sending stored server drafts is unavailable for this account."""
    reason = capability.wmsvr_private_draft_send_reason or "unknown"
    message = f"Account {capability.email} cannot send server drafts ({reason})."
    suggestions = [
        f"Inspect account capabilities: mailmaster --json capabilities --account {capability.email}",
        "Server drafts are supported only on 163/Wmsvr accounts with complete login credentials.",
        f"Send a new message directly instead: mailmaster --json send-mail --account {capability.email} --to <recipient> --subject <subject> --body <body>",
    ]
    _emit_error(
        "send-draft",
        code="draft_send_unsupported",
        message=message,
        details={
            "account": capability.email,
            "required_capability": "supports_wmsvr_private_draft_send",
            "unavailable_reason": reason,
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _emit_fetch_unsupported(capability: AccountCapabilities) -> NoReturn:
    """Report that fetching raw server RFC822 source is unavailable for this account."""
    reason = capability.wmsvr_private_read_reason or "unknown"
    message = f"Account {capability.email} cannot fetch raw RFC822 source from the server ({reason})."
    suggestions = [
        f"Inspect account capabilities: mailmaster --json capabilities --account {capability.email}",
        f"Read cached messages offline instead: mailmaster --json read --account {capability.email} --mail-id <id>",
    ]
    _emit_error(
        "fetch-mail",
        code="mail_read_unsupported",
        message=message,
        details={
            "account": capability.email,
            "required_capability": "supports_wmsvr_private_read",
            "unavailable_reason": reason,
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _emit_draft_unsupported(capability: AccountCapabilities) -> NoReturn:
    """Report that saving server drafts is unavailable for this account."""
    reason = capability.wmsvr_private_draft_reason or "unknown"
    message = f"Account {capability.email} cannot save server drafts ({reason})."
    suggestions = [
        f"Inspect account capabilities: mailmaster --json capabilities --account {capability.email}",
        "Server drafts require a 163/Wmsvr account with stored password and local device metadata.",
        f"Send directly without saving a draft: mailmaster --json send-mail --account {capability.email} --to <recipient> --subject <subject> --body <body>",
    ]
    _emit_error(
        "save-draft",
        code="draft_unsupported",
        message=message,
        details={
            "account": capability.email,
            "required_capability": "supports_wmsvr_private_drafts",
            "unavailable_reason": reason,
            "capabilities": capability,
            "suggestions": suggestions,
        },
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _smtp_error_text(value: object) -> str | None:
    """Render an SMTP server response without assuming text or leaking anything else."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _emit_smtp_failure(command: str, account: str, exc: Exception) -> NoReturn:
    """Report an SMTP transport failure as structured output."""
    suggestions = [
        f"Inspect account capabilities: mailmaster --json capabilities --account {account}",
        f"If this is a 163/Wmsvr account, send via the private protocol instead: mailmaster --json send-mail --account {account} --transport wmsvr-private --to <recipient> --subject <subject> --body <body>",
    ]
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        code = "smtp_auth_failed"
        message = f"SMTP authentication failed for {account}: the server rejected the stored credentials."
        details: dict[str, Any] = {
            "account": account,
            "smtp_code": exc.smtp_code,
            "smtp_error": _smtp_error_text(exc.smtp_error),
            "suggestions": suggestions,
        }
    elif isinstance(exc, smtplib.SMTPException):
        code = "smtp_send_failed"
        message = f"SMTP send failed for {account} ({type(exc).__name__})."
        details = {
            "account": account,
            "exception": type(exc).__name__,
            "smtp_code": getattr(exc, "smtp_code", None),
            "smtp_error": _smtp_error_text(getattr(exc, "smtp_error", None)),
            "suggestions": suggestions,
        }
    else:
        code = "smtp_connection_failed"
        message = f"Could not connect to the SMTP server for {account}: {exc}"
        details = {
            "account": account,
            "exception": type(exc).__name__,
            "suggestions": suggestions,
        }
    _emit_error(
        command,
        code=code,
        message=message,
        details=details,
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _emit_local_lookup_error(
    command: str,
    exc: LocalLookupError,
    *,
    account: str,
    **details: object,
) -> NoReturn:
    """Turn a failed local lookup into the stable structured error contract."""
    message = str(exc)
    if exc.code == "mail_not_found":
        suggestions = [f"List local messages first: mailmaster --json list --account {account}"]
    elif exc.code == "mailbox_not_found":
        suggestions = [f"List available mailboxes first: mailmaster --json mailboxes --account {account}"]
    elif exc.code == "account_not_found":
        suggestions = ["List available accounts first: mailmaster --json accounts"]
    else:
        suggestions = []
    payload: dict[str, object] = {"account": account, **details}
    if suggestions:
        payload["suggestions"] = suggestions
    _emit_error(
        command,
        code=exc.code,
        message=message,
        details=payload,
        text_renderer=lambda: _render_failure(message, suggestions),
    )


def _emit_mail_not_found(
    command: str,
    account: str,
    mail_ids: list[str],
    exc: Exception,
) -> NoReturn:
    """Report a missing local mail ID as a structured user error."""
    if isinstance(exc, LocalLookupError) and exc.code != "mail_not_found":
        _emit_local_lookup_error(command, exc, account=account, mail_ids=mail_ids)
    message = str(exc) or "Mail ID not found in the local store."
    suggestions = [f"List local messages first: mailmaster --json list --account {account}"]
    _emit_error(
        command,
        code="mail_not_found",
        message=message,
        details={"account": account, "mail_ids": mail_ids, "suggestions": suggestions},
        text_renderer=lambda: _render_failure(message, suggestions),
    )
