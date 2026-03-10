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

