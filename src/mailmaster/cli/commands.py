from __future__ import annotations

from pathlib import Path
import sys
from typing import TYPE_CHECKING, cast

import typer

from ..discovery import discover_paths
from ..email_renderer import LatexMode
from ..store import AccountStore, MailMasterStore
from . import _emit, app
from .render import console, print_accounts, print_mail_details, print_mail_list, print_mailboxes

if TYPE_CHECKING:
    from ..models import MailMasterPaths


def _paths_and_store() -> tuple[MailMasterPaths, MailMasterStore]:
    paths = discover_paths()
    if not paths.app_db.exists():
        raise typer.BadParameter(f"MailMaster app db not found: {paths.app_db}")
    return paths, MailMasterStore(paths.app_db)


@app.command()
def doctor() -> None:
    paths, store = _paths_and_store()
    accounts = store.get_accounts()
    _emit(
        "doctor",
        {"paths": paths, "accounts": accounts, "account_count": len(accounts)},
        lambda: (
            console.print(f"install_root: {paths.install_root}"),
            console.print(f"launcher_exe: {paths.launcher_exe}"),
            console.print(f"local_root: {paths.local_root}"),
            console.print(f"app_db: {paths.app_db}"),
            console.print(f"accounts_root: {paths.accounts_root}"),
            console.print(),
            print_accounts(accounts),
        ),
    )


@app.command()
def accounts() -> None:
    _, store = _paths_and_store()
    accounts_list = store.get_accounts()
    _emit("accounts", accounts_list, lambda: print_accounts(accounts_list))


@app.command()
def mailboxes(account: str = typer.Option(..., "--account", help="Account email or numeric ID.")) -> None:
    paths, store = _paths_and_store()
    account_obj = store.get_account(account)
    mailboxes_list = AccountStore(account_obj, install_root=paths.install_root).get_mailboxes()
    _emit("mailboxes", {"account": account_obj, "mailboxes": mailboxes_list}, lambda: print_mailboxes(mailboxes_list))


@app.command(name="list")
def list_mails(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    mailbox: str | None = typer.Option(None, "--mailbox", help="Mailbox display name or ID."),
    unread: bool = typer.Option(False, "--unread", help="Only show unread mails."),
    limit: int = typer.Option(20, "--limit", min=1, max=200),
) -> None:
    paths, store = _paths_and_store()
    records = AccountStore(store.get_account(account), install_root=paths.install_root).list_mail(mailbox=mailbox, unread_only=unread, limit=limit)
    _emit("list", {"account": account, "mailbox": mailbox, "unread": unread, "limit": limit, "records": records}, lambda: print_mail_list(records))


@app.command()
def read(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    mail_id: str = typer.Option(..., "--mail-id", help="LocalId or RemoteId from MailMeta."),
    html: bool = typer.Option(False, "--html", help="Show HTML instead of extracted plain text."),
) -> None:
    paths, store = _paths_and_store()
    details = AccountStore(store.get_account(account), install_root=paths.install_root).get_details(mail_id)
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


@app.command()
def search(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    query: str = typer.Argument(..., help="Search keyword."),
    mailbox: str | None = typer.Option(None, "--mailbox", help="Mailbox display name or ID."),
    body: bool = typer.Option(False, "--body", help="Also search decoded body content."),
    limit: int = typer.Option(20, "--limit", min=1, max=100),
) -> None:
    paths, store = _paths_and_store()
    records = AccountStore(store.get_account(account), install_root=paths.install_root).search_mail(query, mailbox=mailbox, limit=limit, include_body=body)
    _emit("search", {"account": account, "query": query, "mailbox": mailbox, "body": body, "limit": limit, "records": records}, lambda: print_mail_list(records))


@app.command(name="smtp-send")
def smtp_send(
    email: str = typer.Option(..., "--from", help="Sender email (resolved dynamically from MailMaster local data)."),
    to: list[str] = typer.Option(..., "--to", help="Recipient email. Repeatable."),
    cc: list[str] = typer.Option([], "--cc", help="Cc email. Repeatable."),
    bcc: list[str] = typer.Option([], "--bcc", help="Bcc email. Repeatable."),
    attach: list[Path] = typer.Option([], "--attach", help="Attach local file(s). Repeatable."),
    subject: str = typer.Option("", "--subject"),
    body: str = typer.Option("", "--body"),
    html_body: str = typer.Option("", "--html-body", help="HTML body (overrides --body)."),
    markdown_body: str = typer.Option("", "--markdown-body", help="Markdown body; auto-converted to HTML email."),
    markdown_file: Path | None = typer.Option(None, "--markdown-file", help="Read Markdown body from a file and auto-convert to HTML email."),
    latex_mode: str = typer.Option("auto", "--latex-mode", help="LaTeX rendering mode for Markdown: auto, mathml, image, or raw."),
    in_reply_to: str = typer.Option("", "--in-reply-to", help="Message-ID for threading."),
) -> None:
    from ..email_renderer import render_markdown_email
    from ..smtp import profile_from_server_config, send_email

    latex_mode = latex_mode.lower().strip()
    if latex_mode not in {"auto", "mathml", "image", "raw"}:
        raise typer.BadParameter("--latex-mode must be one of: auto, mathml, image, raw")
    validated_latex_mode = cast(LatexMode, latex_mode)

    if markdown_body and markdown_file is not None:
        raise typer.BadParameter("Use either --markdown-body or --markdown-file, not both.")

    effective_body = body
    effective_html_body = html_body
    markdown_inline_images = []
    markdown_source: str | None = None
    if markdown_file is not None:
        markdown_source = sys.stdin.read() if str(markdown_file) == "-" else markdown_file.read_text("utf-8")
    elif markdown_body:
        markdown_source = markdown_body

    if markdown_source is not None:
        rendered = render_markdown_email(markdown_source, latex_mode=validated_latex_mode)
        effective_body = rendered.plain_text
        effective_html_body = rendered.html
        markdown_inline_images = rendered.inline_images

    html_base_dir: Path | None = None
    if markdown_file is not None and str(markdown_file) != "-":
        html_base_dir = markdown_file.parent.resolve()

    paths, store = _paths_and_store()
    account_obj = store.get_account(email)
    configs = AccountStore(account_obj, install_root=paths.install_root).get_server_configs()
    smtp_cfg = configs.get("SMTPServerConfig")
    if not smtp_cfg:
        raise typer.BadParameter(f"No SMTPServerConfig found for {account_obj.email}.")

    profile = profile_from_server_config(account_obj.email, smtp_cfg)
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
            "content_mode": "markdown" if markdown_source is not None else ("html" if html_body else "plain"),
            "latex_mode": validated_latex_mode if markdown_source is not None else None,
            "smtp": {
                "host": profile.smtp_host,
                "port": profile.smtp_port,
                "username": profile.effective_username,
                "use_ssl": profile.use_ssl,
                "use_starttls": profile.use_starttls,
            },
        },
        lambda: console.print(f"[green]Email sent from {email} to {', '.join(to)}.[/green]"),
    )


@app.command(name="mark-read")
def mark_read(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    mail_id: str = typer.Option(..., "--mail-id", help="Mail localId or remoteId."),
) -> None:
    from .._facade import MailMaster

    mm = MailMaster()
    record = mm.mark_read(account, mail_id)
    _emit("mark-read", {"account": account, "mail_id": mail_id, "remote_id": record.remote_id, "mailbox": record.mailbox, "status": "read"}, lambda: console.print(f"Marked mail {mail_id} as read."))


@app.command(name="mark-unread")
def mark_unread(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    mail_id: str = typer.Option(..., "--mail-id", help="Mail localId or remoteId."),
) -> None:
    from .._facade import MailMaster

    mm = MailMaster()
    record = mm.mark_unread(account, mail_id)
    _emit("mark-unread", {"account": account, "mail_id": mail_id, "remote_id": record.remote_id, "mailbox": record.mailbox, "status": "unread"}, lambda: console.print(f"Marked mail {mail_id} as unread."))


@app.command(name="move-mail")
def move_mail(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    mail_id: str = typer.Option(..., "--mail-id", help="Mail localId or remoteId."),
    target_mailbox: str = typer.Option(..., "--target-mailbox", help="Target mailbox display name or ID."),
) -> None:
    from .._facade import MailMaster

    mm = MailMaster()
    record = mm.move_mail(account, mail_id, target_mailbox=target_mailbox)
    _emit("move-mail", {"account": account, "mail_id": mail_id, "remote_id": record.remote_id, "from_mailbox": record.mailbox, "target_mailbox": target_mailbox}, lambda: console.print(f"Moved mail {mail_id} to {target_mailbox}."))


@app.command(name="delete-mail")
def delete_mail(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID."),
    mail_id: str = typer.Option(..., "--mail-id", help="Mail localId or remoteId."),
) -> None:
    from .._facade import MailMaster

    mm = MailMaster()
    record = mm.delete_mail(account, mail_id)
    _emit("delete-mail", {"account": account, "mail_id": mail_id, "remote_id": record.remote_id, "mailbox": record.mailbox, "status": "deleted"}, lambda: console.print(f"Deleted mail {mail_id}."))
