from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.table import Table

from ..models import Account, AccountCapabilities, MailDetails, MailRecord, Mailbox

console = Console()


def _fmt_ts(ts_ms: int) -> str:
    if not ts_ms:
        return ""
    return datetime.fromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M")


def print_accounts(accounts: list[Account]) -> None:
    table = Table(title="MailMaster Accounts")
    table.add_column("ID")
    table.add_column("Email")
    table.add_column("Type")
    table.add_column("Valid")
    table.add_column("Data Path")
    for account in accounts:
        table.add_row(str(account.id), account.email, str(account.type), "yes" if account.valid else "no", str(account.data_path))
    console.print(table)


def print_capabilities(items: list[AccountCapabilities]) -> None:
    table = Table(title="Account Capabilities")
    table.add_column("ID")
    table.add_column("Email")
    table.add_column("Read")
    table.add_column("Send")
    table.add_column("Mutate")
    table.add_column("Configs")
    table.add_column("Paths")
    table.add_column("Warnings")
    for item in items:
        configs = ", ".join(
            name
            for name, enabled in (
                ("IMAP", item.has_imap_config),
                ("SMTP", item.has_smtp_config),
                ("WMSVR", item.has_wmsvr_config),
            )
            if enabled
        ) or "-"
        paths = ", ".join(item.product_paths) or "-"
        warnings = "; ".join(item.warnings) or "-"
        table.add_row(
            str(item.account_id),
            item.email,
            item.recommended_read_method,
            item.recommended_send_method,
            item.recommended_mutation_method,
            configs,
            paths,
            warnings,
        )
    console.print(table)


def print_mailboxes(mailboxes: list[Mailbox]) -> None:
    table = Table(title="Mailboxes")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Parent")
    for box in mailboxes:
        table.add_row(box.id, box.display_name, str(box.type), box.parent)
    console.print(table)


def print_mail_list(records: list[MailRecord]) -> None:
    table = Table(title="Mails")
    table.add_column("Mail ID")
    table.add_column("Received")
    table.add_column("From")
    table.add_column("Subject")
    table.add_column("Flags")
    for record in records:
        flags = "".join([
            "U" if record.unread else "",
            "★" if record.starred else "",
            "A" if record.has_attachments else "",
            "R" if record.replied else "",
            "F" if record.forwarded else "",
        ])
        sender = record.sender_email or record.sender_name
        table.add_row(str(record.local_id), _fmt_ts(record.received_ts_ms), sender, record.subject, flags)
    console.print(table)


def print_mail_details(details: MailDetails, show_html: bool = False) -> None:
    record = details.record
    console.print(f"[bold]Mail ID:[/bold] {record.local_id}")
    console.print(f"[bold]Subject:[/bold] {record.subject}")
    console.print(f"[bold]From:[/bold] {record.sender_name or record.sender_email} <{record.sender_email}>")
    console.print(f"[bold]To:[/bold] {', '.join(record.to_list)}")
    if record.cc_list:
        console.print(f"[bold]Cc:[/bold] {', '.join(record.cc_list)}")
    console.print(f"[bold]Received:[/bold] {_fmt_ts(record.received_ts_ms)}")
    console.print(f"[bold]Summary:[/bold] {record.summary}")
    if details.attachments:
        console.print("[bold]Attachments:[/bold]")
        for attachment in details.attachments:
            console.print(f"- {attachment.name or '(inline)'} [{attachment.size} bytes] {attachment.content_type}")
    console.print("[bold]Body:[/bold]")
    console.print(details.content.html_body if show_html else (details.content.text_body or ""))


def print_key_values(title: str, rows: list[tuple[str, str]]) -> None:
    table = Table(title=title, show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    for name, value in rows:
        table.add_row(name, value)
    console.print(table)


def print_string_list(title: str, items: list[str]) -> None:
    console.print(f"[bold]{title}[/bold] ({len(items)})")
    for item in items:
        console.print(f"- {item}")
