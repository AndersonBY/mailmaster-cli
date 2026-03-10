"""High-level library facade for MailMaster access."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .discovery import discover_paths
from .email_renderer import LatexMode, RenderedMarkdownEmail, render_markdown_email
from .imap_ops import delete_mail as imap_delete_mail
from .imap_ops import mark_seen, move_mail as imap_move_mail
from .imap_ops import open_imap_connection, profile_from_server_config as profile_from_imap_config
from .models import Account, MailDetails, MailRecord, Mailbox, MailMasterPaths
from .smtp import profile_from_server_config, send_email
from .store import AccountStore, MailMasterStore


class AccountAccess:
    def __init__(self, account: Account, *, install_root: Path | None = None):
        self.account = account
        self._store = AccountStore(account, install_root=install_root)

    def get_mailboxes(self) -> list[Mailbox]:
        return self._store.get_mailboxes()

    def list_mail(self, *, mailbox: str | None = None, unread_only: bool = False, limit: int = 20) -> list[MailRecord]:
        return self._store.list_mail(mailbox=mailbox, unread_only=unread_only, limit=limit)

    def search_mail(self, query: str, *, mailbox: str | None = None, limit: int = 20, include_body: bool = False) -> list[MailRecord]:
        return self._store.search_mail(query, mailbox=mailbox, limit=limit, include_body=include_body)

    def get_mail(self, mail_id: str) -> MailRecord:
        return self._store.get_mail(mail_id)

    def get_details(self, mail_id: str) -> MailDetails:
        return self._store.get_details(mail_id)

    def get_server_configs(self) -> dict[str, dict[str, object]]:
        return self._store.get_server_configs()

    def get_imap_profile(self):
        imap_cfg = self.get_server_configs().get("IMAPServerConfig")
        if not imap_cfg:
            raise ValueError(f"No IMAPServerConfig found for {self.account.email}.")
        return profile_from_imap_config(imap_cfg)

    def render_markdown_email(self, markdown_text: str, *, latex_mode: LatexMode = "auto") -> RenderedMarkdownEmail:
        return render_markdown_email(markdown_text, latex_mode=latex_mode)

    def send_email(self, *, to: list[str], cc: list[str] | None = None, bcc: list[str] | None = None, subject: str = "", body: str = "", html_body: str = "", attachments: list[Path] | None = None, inline_images: list[Any] | None = None, in_reply_to: str = "") -> None:
        smtp_cfg = self.get_server_configs().get("SMTPServerConfig")
        if not smtp_cfg:
            raise ValueError(f"No SMTPServerConfig found for {self.account.email}.")
        profile = profile_from_server_config(self.account.email, smtp_cfg)
        send_email(
            profile,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            html_body=html_body,
            attachments=attachments,
            inline_images=inline_images,
            in_reply_to=in_reply_to,
        )

    def send_markdown_email(
        self,
        *,
        to: list[str],
        markdown_text: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        latex_mode: LatexMode = "auto",
        attachments: list[Path] | None = None,
        in_reply_to: str = "",
    ) -> None:
        rendered = self.render_markdown_email(markdown_text, latex_mode=latex_mode)
        self.send_email(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=rendered.plain_text,
            html_body=rendered.html,
            attachments=attachments,
            inline_images=rendered.inline_images,
            in_reply_to=in_reply_to,
        )

    def mark_read(self, mail_id: str) -> MailRecord:
        record = self.get_mail(mail_id)
        profile = self.get_imap_profile()
        with open_imap_connection(profile) as client:
            mark_seen(client, record, seen=True)
        return record

    def mark_unread(self, mail_id: str) -> MailRecord:
        record = self.get_mail(mail_id)
        profile = self.get_imap_profile()
        with open_imap_connection(profile) as client:
            mark_seen(client, record, seen=False)
        return record

    def move_mail(self, mail_id: str, *, target_mailbox: str) -> MailRecord:
        record = self.get_mail(mail_id)
        target_mailbox_id = self._store.resolve_mailbox(target_mailbox) or target_mailbox
        profile = self.get_imap_profile()
        with open_imap_connection(profile) as client:
            imap_move_mail(client, record, target_mailbox=target_mailbox_id)
        return record

    def delete_mail(self, mail_id: str) -> MailRecord:
        record = self.get_mail(mail_id)
        profile = self.get_imap_profile()
        with open_imap_connection(profile) as client:
            imap_delete_mail(client, record)
        return record


class MailMaster:
    def __init__(self, *, app_db: Path | None = None, install_root: Path | None = None, paths: MailMasterPaths | None = None):
        if paths is None:
            paths = discover_paths()
        if app_db is not None:
            paths = MailMasterPaths(
                install_root=install_root if install_root is not None else paths.install_root,
                launcher_exe=paths.launcher_exe,
                local_root=paths.local_root,
                app_db=app_db,
                accounts_root=paths.accounts_root,
            )
        elif install_root is not None:
            paths = MailMasterPaths(
                install_root=install_root,
                launcher_exe=paths.launcher_exe,
                local_root=paths.local_root,
                app_db=paths.app_db,
                accounts_root=paths.accounts_root,
            )

        self.paths = paths
        self.store = MailMasterStore(self.paths.app_db)

    def get_accounts(self) -> list[Account]:
        return self.store.get_accounts()

    def get_account(self, identifier: str) -> Account:
        return self.store.get_account(identifier)

    def open_account(self, identifier: str) -> AccountAccess:
        return AccountAccess(self.get_account(identifier), install_root=self.paths.install_root)

    def account(self, identifier: str) -> AccountAccess:
        return self.open_account(identifier)

    def get_mailboxes(self, account: str) -> list[Mailbox]:
        return self.open_account(account).get_mailboxes()

    def list_mail(self, account: str, *, mailbox: str | None = None, unread_only: bool = False, limit: int = 20) -> list[MailRecord]:
        return self.open_account(account).list_mail(mailbox=mailbox, unread_only=unread_only, limit=limit)

    def search_mail(self, account: str, query: str, *, mailbox: str | None = None, limit: int = 20, include_body: bool = False) -> list[MailRecord]:
        return self.open_account(account).search_mail(query, mailbox=mailbox, limit=limit, include_body=include_body)

    def get_mail(self, account: str, mail_id: str) -> MailRecord:
        return self.open_account(account).get_mail(mail_id)

    def get_details(self, account: str, mail_id: str) -> MailDetails:
        return self.open_account(account).get_details(mail_id)

    def mark_read(self, account: str, mail_id: str) -> MailRecord:
        return self.open_account(account).mark_read(mail_id)

    def mark_unread(self, account: str, mail_id: str) -> MailRecord:
        return self.open_account(account).mark_unread(mail_id)

    def move_mail(self, account: str, mail_id: str, *, target_mailbox: str) -> MailRecord:
        return self.open_account(account).move_mail(mail_id, target_mailbox=target_mailbox)

    def delete_mail(self, account: str, mail_id: str) -> MailRecord:
        return self.open_account(account).delete_mail(mail_id)
