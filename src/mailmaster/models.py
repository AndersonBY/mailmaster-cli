from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class MailMasterPaths:
    install_root: Path | None
    launcher_exe: Path | None
    local_root: Path
    app_db: Path
    accounts_root: Path


@dataclass(slots=True)
class Account:
    id: int
    type: int
    valid: bool
    name: str
    email: str
    data_path: Path


@dataclass(slots=True)
class AccountCapabilities:
    account_id: int
    email: str
    name: str
    has_local_store: bool
    has_content_store: bool
    has_imap_config: bool
    has_smtp_config: bool
    has_wmsvr_config: bool
    supports_local_read: bool
    supports_smtp_send: bool
    supports_imap_mutations: bool
    supports_wmsvr_bootstrap: bool
    recommended_read_method: str
    recommended_send_method: str
    recommended_mutation_method: str
    supports_wmsvr_private_mutations: bool = False
    wmsvr_private_mutation_reason: str | None = None
    supports_wmsvr_private_send: bool = False
    wmsvr_private_send_reason: str | None = None
    supports_wmsvr_private_drafts: bool = False
    wmsvr_private_draft_reason: str | None = None
    # Round 85: the four-step private send with attachments (compose -> upload:prepare ->
    # wzp:uploadAttach -> deliver), proven live in round 84.
    supports_wmsvr_private_attachments: bool = False
    wmsvr_private_attachment_reason: str | None = None
    supports_wmsvr_private_draft_send: bool = False
    wmsvr_private_draft_send_reason: str | None = None
    # Round 93: the private read (`wzpm:getMessageData`) serves a message's raw RFC822 source,
    # which is also the cheap server-side read of an existing message's attachment metadata.
    supports_wmsvr_private_read: bool = False
    wmsvr_private_read_reason: str | None = None
    smtp_config_source: str | None = None
    smtp_settings_source: str | None = None
    smtp_credential_source: str | None = None
    product_paths: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def matches(
        self,
        *,
        query: str | None = None,
        require_local_read: bool = False,
        require_send: bool = False,
        require_mutation: bool = False,
        require_wmsvr_bootstrap: bool = False,
        require_paths: list[str] | None = None,
    ) -> bool:
        if query:
            query_lower = query.lower()
            if query_lower not in self.email.lower() and query_lower not in self.name.lower():
                return False
        if require_local_read and not self.supports_local_read:
            return False
        if require_send and not (self.supports_smtp_send or self.supports_wmsvr_private_send):
            return False
        if require_mutation and not (self.supports_imap_mutations or self.supports_wmsvr_private_mutations):
            return False
        if require_wmsvr_bootstrap and not self.supports_wmsvr_bootstrap:
            return False
        if require_paths and not all(path in self.product_paths for path in require_paths):
            return False
        return True


@dataclass(slots=True)
class Mailbox:
    id: str
    parent: str
    display_name: str
    type: int
    sync_state: int
    remind: int
    ui_flags: int


@dataclass(slots=True)
class MailAttachment:
    local_id: int
    mail_id: int
    name: str
    size: int
    content_type: str
    local_path: str


@dataclass(slots=True)
class MailRecord:
    local_id: int
    remote_id: str
    mailbox: str
    subject: str
    summary: str
    sender_name: str
    sender_email: str
    to_list: list[str]
    cc_list: list[str]
    reply_to_list: list[str]
    unread: bool
    starred: bool
    has_attachments: bool
    replied: bool
    forwarded: bool
    received_ts_ms: int
    orig_ts_ms: int
    message_id: str
    reference_ids: str


@dataclass(slots=True)
class MailContent:
    mail_id: int
    text_body: str | None = None
    html_body: str | None = None


@dataclass(slots=True)
class MailDetails:
    record: MailRecord
    attachments: list[MailAttachment] = field(default_factory=list)
    content: MailContent = field(default_factory=lambda: MailContent(mail_id=0))
