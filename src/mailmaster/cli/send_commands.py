"""Mail sending and draft CLI commands (SMTP and Wmsvr private protocol)."""

from __future__ import annotations

from pathlib import Path
import smtplib
import sys
from typing import Any, cast

import typer

from ..email_renderer import InlineImage, LatexMode, render_markdown_email
from ..store import LocalLookupError
from . import _emit, _emit_error, app
from .errors import (
    _emit_draft_send_unsupported,
    _emit_draft_unsupported,
    _emit_local_lookup_error,
    _emit_send_unsupported,
    _emit_smtp_failure,
    _ensure_send_capability,
    _render_failure,
)
from .render import console

_VALID_LATEX_MODES = frozenset({"auto", "mathml", "image", "raw"})


def _validate_markdown_options(
    *,
    markdown_body: str,
    markdown_file: Path | None,
    latex_mode: str,
) -> LatexMode:
    normalized = latex_mode.lower().strip()
    if normalized not in _VALID_LATEX_MODES:
        raise typer.BadParameter("--latex-mode must be one of: auto, mathml, image, raw")
    if markdown_body and markdown_file is not None:
        raise typer.BadParameter("Use either --markdown-body or --markdown-file, not both.")
    return cast(LatexMode, normalized)


def _resolve_body_content(
    *,
    body: str,
    html_body: str,
    markdown_body: str,
    markdown_file: Path | None,
    latex_mode: LatexMode,
    transport: str,
) -> tuple[str, str, list[InlineImage], Path | None, str, LatexMode | None]:
    markdown_source: str | None = None
    if markdown_file is not None:
        if str(markdown_file) == "-":
            markdown_source = sys.stdin.read()
        else:
            if not markdown_file.exists():
                raise typer.BadParameter(f"Markdown file not found: {markdown_file}")
            markdown_source = markdown_file.read_text("utf-8")
    elif markdown_body:
        markdown_source = markdown_body

    html_base_dir: Path | None = None
    if markdown_file is not None and str(markdown_file) != "-":
        html_base_dir = markdown_file.parent.resolve()

    if markdown_source is not None:
        effective_latex_mode: LatexMode = (
            "mathml" if (transport == "wmsvr-private" and latex_mode == "auto") else latex_mode
        )
        rendered = render_markdown_email(markdown_source, latex_mode=effective_latex_mode)
        inline_images = rendered.inline_images if transport == "smtp" else []
        return (
            rendered.plain_text,
            rendered.html,
            inline_images,
            html_base_dir,
            "markdown",
            effective_latex_mode,
        )

    return (
        body,
        html_body,
        [],
        html_base_dir,
        "html" if html_body else "plain",
        None,
    )


@app.command(name="smtp-send", rich_help_panel="Send & Drafts")
def smtp_send(
    email: str = typer.Option(
        ..., "--from", help="Sender account email or numeric ID from 'mailmaster accounts'."
    ),
    to: list[str] = typer.Option(..., "--to", help="Recipient email address. Repeatable."),
    cc: list[str] = typer.Option([], "--cc", help="Cc email address. Repeatable."),
    bcc: list[str] = typer.Option([], "--bcc", help="Bcc email address. Repeatable."),
    attach: list[Path] = typer.Option([], "--attach", help="Attach local file(s). Repeatable."),
    subject: str = typer.Option("", "--subject", help="Email subject line."),
    body: str = typer.Option("", "--body", help="Plain-text body."),
    html_body: str = typer.Option("", "--html-body", help="HTML body (overrides --body)."),
    markdown_body: str = typer.Option("", "--markdown-body", help="Markdown body (auto-converted to HTML email)."),
    markdown_file: Path | None = typer.Option(
        None, "--markdown-file", help="Read Markdown body from a file (or '-' for stdin) and convert to HTML."
    ),
    latex_mode: str = typer.Option(
        "auto", "--latex-mode", help="LaTeX math mode for Markdown: auto, mathml, image, or raw."
    ),
    in_reply_to: str = typer.Option("", "--in-reply-to", help="Message-ID header for reply threading."),
) -> None:
    """Send an email directly over SMTP (for accounts with stored SMTP settings; prefer 'send-mail' for auto-routing)."""
    from .._facade import MailMaster
    from ..smtp import resolve_smtp_profile, send_email
    from . import commands as _commands

    validated_latex_mode = _validate_markdown_options(
        markdown_body=markdown_body,
        markdown_file=markdown_file,
        latex_mode=latex_mode,
    )
    (
        effective_body,
        effective_html_body,
        markdown_inline_images,
        html_base_dir,
        content_mode,
        effective_latex_mode,
    ) = _resolve_body_content(
        body=body,
        html_body=html_body,
        markdown_body=markdown_body,
        markdown_file=markdown_file,
        latex_mode=validated_latex_mode,
        transport="smtp",
    )

    paths, store = _commands._paths_and_store()
    mm = MailMaster(paths=paths)
    _ensure_send_capability(mm, email, command="smtp-send")
    try:
        account_obj = store.get_account(email)
    except LocalLookupError as exc:
        _emit_local_lookup_error("smtp-send", exc, account=email)
    configs = _commands.AccountStore(account_obj, install_root=paths.install_root).get_server_configs()
    profile_info = resolve_smtp_profile(account_obj.email, configs)
    profile = profile_info.profile
    try:
        send_email(
            profile,
            to=to,
            cc=cc or None,
            bcc=bcc or None,
            subject=subject,
            body=effective_body,
            html_body=effective_html_body,
            html_base_dir=html_base_dir,
            attachments=attach,
            inline_images=markdown_inline_images,
            in_reply_to=in_reply_to,
        )
    except (smtplib.SMTPException, OSError) as exc:
        _emit_smtp_failure("smtp-send", account_obj.email, exc)
    _emit(
        "smtp-send",
        {
            "sent": True,
            "from": account_obj.email,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "attachments": [str(path) for path in attach],
            "subject": subject,
            "content_mode": content_mode,
            "latex_mode": effective_latex_mode,
            "smtp": {
                "host": profile.smtp_host,
                "port": profile.smtp_port,
                "username": profile.effective_username,
                "use_ssl": profile.use_ssl,
                "use_starttls": profile.use_starttls,
                "config_source": profile_info.config_source,
                "settings_source": profile_info.settings_source,
                "credential_source": profile_info.credential_source,
            },
        },
        lambda: console.print(
            f"[green]Email sent from {email} to {', '.join(to)} via {profile.smtp_host}:{profile.smtp_port}.[/green]"
        ),
    )


@app.command(name="send-mail", rich_help_panel="Send & Drafts")
def send_mail(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    to: list[str] = typer.Option(..., "--to", help="Recipient email address. Repeatable."),
    cc: list[str] = typer.Option([], "--cc", help="Cc email address. Repeatable."),
    bcc: list[str] = typer.Option([], "--bcc", help="Bcc email address. Repeatable."),
    subject: str = typer.Option("", "--subject", help="Email subject line."),
    body: str = typer.Option("", "--body", help="Plain-text body."),
    html_body: str = typer.Option("", "--html-body", help="HTML body (overrides --body)."),
    markdown_body: str = typer.Option("", "--markdown-body", help="Markdown body (auto-converted to HTML email)."),
    markdown_file: Path | None = typer.Option(
        None, "--markdown-file", help="Read Markdown body from a file (or '-' for stdin) and convert to HTML."
    ),
    latex_mode: str = typer.Option(
        "auto", "--latex-mode", help="LaTeX math mode for Markdown: auto, mathml, image, or raw."
    ),
    attach: list[Path] = typer.Option([], "--attach", help="Attach local file(s). Repeatable."),
    transport: str = typer.Option(
        "auto", "--transport", help="Send transport: auto (recommended), smtp, or wmsvr-private."
    ),
) -> None:
    """Send an email using the account's best available transport (SMTP or 163/Wmsvr).

    Supports plain text, HTML, Markdown (with LaTeX math), and file attachments.

    Examples:
      mailmaster send-mail --account 1 --to alice@example.com --subject "Hello" --body "Hi!" --json
      mailmaster send-mail --account user@163.com --to alice@example.com --subject "Report" --markdown-file report.md --attach data.csv --json
    """
    from .._facade import MailMaster, resolve_send_transport

    requested = transport.strip().lower()
    if requested not in {"auto", "smtp", "wmsvr-private"}:
        raise typer.BadParameter("--transport must be one of: auto, smtp, wmsvr-private")
    validated_latex_mode = _validate_markdown_options(
        markdown_body=markdown_body,
        markdown_file=markdown_file,
        latex_mode=latex_mode,
    )

    mm = MailMaster()
    try:
        capability = mm.get_capabilities(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error("send-mail", exc, account=account)

    chosen = resolve_send_transport(capability, requested)

    if (
        attach
        and chosen == "wmsvr-private"
        and not capability.supports_wmsvr_private_attachments
    ):
        _emit_error(
            command="send-mail",
            code="wmsvr_attachments_unsupported",
            message=(
                f"Account {capability.email} cannot carry attachments over the Wmsvr private "
                "protocol right now."
            ),
            details={
                "account": capability.email,
                "reason": capability.wmsvr_private_attachment_reason,
                "attachments": [str(path) for path in attach],
            },
            text_renderer=lambda: _render_failure(
                "The private-protocol attachment upload is unavailable for this account.",
                ["Drop --attach, or send over SMTP (it carries attachments as MIME parts)."],
            ),
        )

    if chosen == "none":
        _emit_send_unsupported(capability, command="send-mail", requested=requested, transport=requested)

    (
        effective_body,
        effective_html_body,
        inline_images,
        html_base_dir,
        content_mode,
        effective_latex_mode,
    ) = _resolve_body_content(
        body=body,
        html_body=html_body,
        markdown_body=markdown_body,
        markdown_file=markdown_file,
        latex_mode=validated_latex_mode,
        transport=chosen,
    )

    if chosen == "wmsvr-private":
        _run_wmsvr_send(
            mm,
            account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=effective_body,
            html_body=effective_html_body,
            attach=attach,
            content_mode=content_mode,
            latex_mode=effective_latex_mode,
        )
        return

    smtp_kwargs: dict[str, Any] = {
        "to": to,
        "cc": cc or None,
        "bcc": bcc or None,
        "subject": subject,
        "body": effective_body,
        "html_body": effective_html_body,
    }
    if html_base_dir is not None:
        smtp_kwargs["html_base_dir"] = html_base_dir
    if attach:
        smtp_kwargs["attachments"] = attach
    if inline_images:
        smtp_kwargs["inline_images"] = inline_images
    try:
        mm.open_account(account).send_email(**smtp_kwargs)
    except (smtplib.SMTPException, OSError) as exc:
        _emit_smtp_failure("send-mail", capability.email, exc)
    _emit(
        "send-mail",
        {
            "account": account,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "attachments": [str(path) for path in attach],
            "content_mode": content_mode,
            "latex_mode": effective_latex_mode,
            "status": "sent",
            "transport": "smtp",
        },
        lambda: console.print(f"[green]Email sent to {', '.join(to)} over SMTP.[/green]"),
    )


def _run_wmsvr_send(
    mm: Any,
    account: str,
    *,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body: str,
    html_body: str,
    attach: list[Path] | None = None,
    content_mode: str = "plain",
    latex_mode: LatexMode | None = None,
) -> None:
    """Send over the private protocol and report the verified sent copy."""
    from ..wmsvr_mail import WmsvrMailError

    attachments = list(attach or [])
    try:
        private_kwargs: dict[str, Any] = {
            "account": account,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "body": body,
            "html_body": html_body,
        }
        if attachments:
            private_kwargs["attachments"] = attachments
        result = mm.send_mail_private(**private_kwargs)
    except WmsvrMailError as exc:
        details = {"account": account, "to": to, **exc.details}
        message = exc.message
        _emit_error(
            command="send-mail",
            code=exc.code,
            message=message,
            details=details,
            text_renderer=lambda: _render_failure(
                message,
                [
                    f"Inspect account capabilities: mailmaster --json capabilities --account {account}",
                    "Check the returned error code and details before retrying.",
                ],
            ),
        )
    except (ValueError, OSError) as exc:
        message = str(exc)
        _emit_error(
            command="send-mail",
            code="send_invalid",
            message=message,
            details={"account": account, "to": to},
            text_renderer=lambda: _render_failure(message, []),
        )
    _emit(
        "send-mail",
        {
            "account": account,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "content_mode": content_mode,
            "latex_mode": latex_mode,
            "attachments": [
                {
                    "path": str(path),
                    "file_name": item.get("file_name"),
                    "size": item.get("size"),
                    "attachment_id": item.get("attachment_id"),
                    "actual_size": item.get("actual_size"),
                    "packets": item.get("packets"),
                    "sent": item.get("sent"),
                    "completed": item.get("completed"),
                }
                for path, item in zip(attachments, result.get("attachments") or [])
            ]
            if attachments
            else [],
            "status": "sent",
            "transport": "wmsvr-private",
            "method": result.get("method"),
            "compose_id": result.get("compose_id"),
            "server_code": result.get("code"),
            "sent_id": result.get("sent_id"),
            "sent_folder_fid": result.get("sent_folder_fid"),
            "sent_subject": result.get("sent_subject"),
            "read_back_code": result.get("read_back_code"),
            "readback_fallback": result.get("readback_fallback"),
            "state_change_verified": result.get("state_change_verified"),
        },
        lambda: console.print(
            f"[green]Email sent to {', '.join(to)} over the Wmsvr private protocol "
            + (f"with {len(attachments)} attachment(s) " if attachments else "")
            + f"(sent copy verified: {result.get('state_change_verified')}).[/green]"
        ),
    )


@app.command(name="send-draft", rich_help_panel="Send & Drafts")
def send_draft(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    draft_id: str = typer.Option(
        "", "--draft-id", help="Draft ID (<fid>:<mid>) returned by 'mailmaster save-draft'."
    ),
    subject: str = typer.Option(
        "", "--subject", help="Find and send the newest server draft matching this subject."
    ),
    to: list[str] = typer.Option([], "--to", help="Override the draft's recipients. Repeatable."),
    body: str = typer.Option("", "--body", help="Override the draft's plain-text body."),
    html_body: str = typer.Option("", "--html-body", help="Override the draft's HTML body."),
) -> None:
    """Send an existing server-side draft on a 163/Wmsvr account (preserves draft attachments).

    Examples:
      mailmaster send-draft --account user@163.com --draft-id "755:<mid>" --json
      mailmaster send-draft --account 7 --subject "Weekly update" --to alice@example.com --json
    """
    from .._facade import MailMaster

    if not draft_id and not subject:
        raise typer.BadParameter("Provide --draft-id or --subject to name the draft to send.")

    mm = MailMaster()
    try:
        capability = mm.get_capabilities(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error("send-draft", exc, account=account)
    if not capability.supports_wmsvr_private_draft_send:
        _emit_draft_send_unsupported(capability)
    _run_wmsvr_send_draft(
        mm,
        account,
        draft_id=draft_id,
        subject=subject,
        to=to,
        body=body,
        html_body=html_body,
    )


def _run_wmsvr_send_draft(
    mm: Any,
    account: str,
    *,
    draft_id: str = "",
    subject: str = "",
    to: list[str] | None = None,
    body: str = "",
    html_body: str = "",
) -> None:
    """Send a stored draft over the private protocol and report the verified sent copy."""
    from ..wmsvr_mail import WmsvrMailError

    try:
        resolved_draft_id = draft_id
        if not resolved_draft_id:
            found = mm.find_mail_draft(account, subject=subject)
            resolved_draft_id = str(found.get("draft_id") or "")
            if not resolved_draft_id:
                raise WmsvrMailError(
                    "wmsvr_draft_not_found",
                    "no draft in the drafts folder carries that subject",
                    details={"subject": subject},
                )
        send_kwargs: dict[str, Any] = {"draft_id": resolved_draft_id}
        if to:
            send_kwargs["to"] = to
        if body:
            send_kwargs["body"] = body
        if html_body:
            send_kwargs["html_body"] = html_body
        result = mm.send_mail_draft(account, **send_kwargs)
    except WmsvrMailError as exc:
        details = {"account": account, "draft_id": draft_id, "subject": subject, **exc.details}
        message = exc.message
        _emit_error(
            command="send-draft",
            code=exc.code,
            message=message,
            details=details,
            text_renderer=lambda: _render_failure(
                message,
                [
                    f"Verify the draft ID or subject, or inspect account status: mailmaster --json capabilities --account {account}",
                ],
            ),
        )
    except (ValueError, OSError) as exc:
        message = str(exc)
        _emit_error(
            command="send-draft",
            code="draft_send_invalid",
            message=message,
            details={"account": account, "draft_id": draft_id},
            text_renderer=lambda: _render_failure(message, []),
        )
    _emit(
        "send-draft",
        {
            "account": account,
            "to": result.get("to"),
            "cc": result.get("cc"),
            "bcc": result.get("bcc"),
            "subject": result.get("subject"),
            "status": "sent",
            "transport": "wmsvr-private",
            "method": result.get("method"),
            "from_draft": True,
            "draft_id": result.get("draft_id"),
            "compose_id": result.get("compose_id"),
            "server_code": result.get("code"),
            "sent_id": result.get("sent_id"),
            "sent_folder_fid": result.get("sent_folder_fid"),
            "sent_subject": result.get("sent_subject"),
            "sent_size": result.get("sent_size"),
            "read_back_code": result.get("read_back_code"),
            "readback_fallback": result.get("readback_fallback"),
            "state_change_verified": result.get("state_change_verified"),
            "attachments": [
                {
                    "attachment_id": item.get("attachment_id"),
                    "file_name": item.get("file_name"),
                    "content_type": item.get("content_type"),
                    "size": item.get("size"),
                    "uploaded_again": False,
                }
                for item in result.get("attachments") or []
            ],
        },
        lambda: console.print(
            f"[green]Draft {result.get('draft_id')} sent over the Wmsvr private protocol"
            + (
                f" with {len(result.get('attachments') or [])} stored attachment(s)"
                if result.get("attachments")
                else ""
            )
            + f" (sent copy verified: {result.get('state_change_verified')}).[/green]"
        ),
    )


@app.command(name="save-draft", rich_help_panel="Send & Drafts")
def save_draft(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    to: list[str] = typer.Option([], "--to", help="Recipient email address. Repeatable."),
    cc: list[str] = typer.Option([], "--cc", help="Cc email address. Repeatable."),
    bcc: list[str] = typer.Option([], "--bcc", help="Bcc email address. Repeatable."),
    subject: str = typer.Option("", "--subject", help="Draft subject line."),
    body: str = typer.Option("", "--body", help="Plain-text body."),
    html_body: str = typer.Option("", "--html-body", help="HTML body (overrides --body)."),
    markdown_body: str = typer.Option("", "--markdown-body", help="Markdown body (auto-converted to HTML draft)."),
    markdown_file: Path | None = typer.Option(
        None, "--markdown-file", help="Read Markdown body from a file (or '-' for stdin) and convert to HTML."
    ),
    latex_mode: str = typer.Option(
        "auto", "--latex-mode", help="LaTeX math mode for Markdown: auto, mathml, image, or raw."
    ),
    compose_id: str = typer.Option(
        "",
        "--compose-id",
        help="Update an existing draft using the compose_id returned by a previous 'save-draft'.",
    ),
    attach: list[Path] = typer.Option([], "--attach", help="Attach local file(s) to the draft. Repeatable."),
) -> None:
    """Create or update a server-side draft on a 163/Wmsvr account.

    Returns draft_id and compose_id so you can later update or send the draft.

    Examples:
      mailmaster save-draft --account user@163.com --to alice@example.com --subject "Draft" --body "WIP" --json
      mailmaster save-draft --account user@163.com --compose-id "<compose_id>" --subject "Draft v2" --markdown-file notes.md --json
    """
    from .._facade import MailMaster

    validated_latex_mode = _validate_markdown_options(
        markdown_body=markdown_body,
        markdown_file=markdown_file,
        latex_mode=latex_mode,
    )

    mm = MailMaster()
    try:
        capability = mm.get_capabilities(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error("save-draft", exc, account=account)
    if not capability.supports_wmsvr_private_drafts:
        _emit_draft_unsupported(capability)
    if attach and not capability.supports_wmsvr_private_attachments:
        _emit_error(
            "save-draft",
            code="wmsvr_attachments_unsupported",
            message=(
                f"Account {capability.email} cannot attach files to a draft: the private upload "
                f"path is unavailable "
                f"({capability.wmsvr_private_attachment_reason or 'unknown'})."
            ),
            details={
                "account": account,
                "required_capability": "supports_wmsvr_private_attachments",
                "capabilities": capability,
            },
            text_renderer=lambda: _render_failure(
                f"Account {capability.email} cannot attach files to a draft.", []
            ),
        )

    (
        effective_body,
        effective_html_body,
        _,
        _,
        content_mode,
        effective_latex_mode,
    ) = _resolve_body_content(
        body=body,
        html_body=html_body,
        markdown_body=markdown_body,
        markdown_file=markdown_file,
        latex_mode=validated_latex_mode,
        transport="wmsvr-private",
    )

    _run_wmsvr_save_draft(
        mm,
        account,
        to=to,
        cc=cc,
        bcc=bcc,
        subject=subject,
        body=effective_body,
        html_body=effective_html_body,
        compose_id=compose_id,
        attach=attach,
        content_mode=content_mode,
        latex_mode=effective_latex_mode,
    )


def _run_wmsvr_save_draft(
    mm: Any,
    account: str,
    *,
    to: list[str],
    cc: list[str],
    bcc: list[str],
    subject: str,
    body: str,
    html_body: str,
    compose_id: str = "",
    attach: list[Path] | None = None,
    content_mode: str = "plain",
    latex_mode: LatexMode | None = None,
) -> None:
    """Save a draft over the private protocol and report the verified draft id."""
    from ..wmsvr_mail import WmsvrMailError

    attachments = list(attach or [])
    save_kwargs: dict[str, Any] = {
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject,
        "body": body,
        "html_body": html_body,
        "compose_id": compose_id or None,
    }
    if attachments:
        save_kwargs["attachments"] = attachments
    try:
        result = mm.save_mail_draft(account, **save_kwargs)
    except WmsvrMailError as exc:
        details = {"account": account, "to": to, **exc.details}
        message = exc.message
        _emit_error(
            command="save-draft",
            code=exc.code,
            message=message,
            details=details,
            text_renderer=lambda: _render_failure(
                message,
                [
                    f"Inspect account capabilities: mailmaster --json capabilities --account {account}",
                    "If updating with --compose-id failed because the ID expired, omit --compose-id to create a new draft.",
                ],
            ),
        )
    except ValueError as exc:
        message = str(exc)
        _emit_error(
            command="save-draft",
            code="draft_invalid",
            message=message,
            details={"account": account, "to": to},
            text_renderer=lambda: _render_failure(message, []),
        )
    _emit(
        "save-draft",
        {
            "account": account,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "content_mode": content_mode,
            "latex_mode": latex_mode,
            "status": "saved",
            "transport": "wmsvr-private",
            "mode": result.get("mode"),
            "recreated": result.get("recreated"),
            "method": result.get("method"),
            "compose_id": result.get("compose_id"),
            "server_code": result.get("code"),
            "draft_id": result.get("draft_id"),
            "draft_folder_fid": result.get("draft_folder_fid"),
            "draft_subject": result.get("draft_subject"),
            "draft_size": result.get("draft_size"),
            "read_back_code": result.get("read_back_code"),
            "readback_fallback": result.get("readback_fallback"),
            "state_change_verified": result.get("state_change_verified"),
            "attachments": [
                {
                    "path": str(path),
                    "file_name": item.get("file_name"),
                    "size": item.get("size"),
                    "attachment_id": item.get("attachment_id"),
                    "actual_size": item.get("actual_size"),
                    "packets": item.get("packets"),
                    "sent": item.get("sent"),
                    "completed": item.get("completed"),
                }
                for path, item in zip(attachments, result.get("attachments") or [])
            ]
            if attachments
            else [],
        },
        lambda: console.print(
            "[green]Draft saved over the Wmsvr private protocol "
            + (f"with {len(attachments)} attachment(s) " if attachments else "")
            + f"(draft verified: {result.get('state_change_verified')}).[/green]"
        ),
    )
