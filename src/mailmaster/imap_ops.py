"""IMAP-based mail state mutation helpers."""
from __future__ import annotations

import imaplib
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator, Literal, Protocol, cast

from .models import MailRecord


class ImapClientProtocol(Protocol):
    capabilities: tuple[bytes, ...] | tuple[str, ...]

    def login(self, user: str, password: str): ...
    def starttls(self): ...
    def select(self, mailbox: str, readonly: bool = False): ...
    def uid(self, command: str, *args: str): ...
    def expunge(self): ...
    def logout(self): ...


@dataclass
class ImapProfile:
    host: str
    port: int
    username: str
    password: str
    use_ssl: bool = True
    use_starttls: bool = False


ImapMutation = Literal["mark-read", "mark-unread", "move-mail", "delete-mail"]


def profile_from_server_config(config: dict[str, object]) -> ImapProfile:
    password = str(config.get("password") or "")
    if not password:
        raise ValueError("No decryptable IMAP password for this account.")

    ssl_type = _to_int(config.get("sslType"), default=0)
    port = _to_int(config.get("port"), default=993)
    use_ssl = ssl_type == 1 or port == 993
    use_starttls = not use_ssl and port == 143
    return ImapProfile(
        host=str(config.get("host") or ""),
        port=port,
        username=str(config.get("user") or ""),
        password=password,
        use_ssl=use_ssl,
        use_starttls=use_starttls,
    )


def _ensure_ok(result: tuple[str, list[bytes] | list[object]], operation: str) -> list[bytes] | list[object]:
    status, data = result
    if status != "OK":
        raise RuntimeError(f"IMAP {operation} failed: {data}")
    return data


def _to_int(value: object, *, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore").strip()
        return int(text or default)
    text = str(value).strip()
    return int(text or default)


def _has_move_capability(client: ImapClientProtocol) -> bool:
    caps = getattr(client, "capabilities", ())
    normalized = {cap.decode("ascii", errors="ignore") if isinstance(cap, bytes) else str(cap) for cap in caps}
    return "MOVE" in normalized


@contextmanager
def open_imap_connection(profile: ImapProfile, client_factory: type[imaplib.IMAP4] | type[imaplib.IMAP4_SSL] | None = None) -> Generator[ImapClientProtocol, None, None]:
    client: ImapClientProtocol
    if profile.use_ssl:
        factory = client_factory or imaplib.IMAP4_SSL
        client = cast(ImapClientProtocol, factory(profile.host, profile.port))
    else:
        factory = client_factory or imaplib.IMAP4
        client = cast(ImapClientProtocol, factory(profile.host, profile.port))
        if profile.use_starttls:
            _ensure_ok(client.starttls(), "STARTTLS")

    try:
        _ensure_ok(client.login(profile.username, profile.password), "LOGIN")
        yield client
    finally:
        try:
            client.logout()
        except Exception:
            pass


def _select_mailbox(client: ImapClientProtocol, mailbox: str) -> None:
    _ensure_ok(client.select(mailbox, readonly=False), f"SELECT {mailbox}")


def mark_seen(client: ImapClientProtocol, record: MailRecord, *, seen: bool) -> None:
    _select_mailbox(client, record.mailbox)
    command = "+FLAGS.SILENT" if seen else "-FLAGS.SILENT"
    _ensure_ok(client.uid("STORE", record.remote_id, command, "(\\Seen)"), "STORE Seen")


def delete_mail(client: ImapClientProtocol, record: MailRecord) -> None:
    _select_mailbox(client, record.mailbox)
    _ensure_ok(client.uid("STORE", record.remote_id, "+FLAGS.SILENT", "(\\Deleted)"), "STORE Deleted")
    _ensure_ok(client.expunge(), "EXPUNGE")


def move_mail(client: ImapClientProtocol, record: MailRecord, *, target_mailbox: str) -> None:
    _select_mailbox(client, record.mailbox)
    if _has_move_capability(client):
        _ensure_ok(client.uid("MOVE", record.remote_id, target_mailbox), "UID MOVE")
        return

    _ensure_ok(client.uid("COPY", record.remote_id, target_mailbox), "UID COPY")
    _ensure_ok(client.uid("STORE", record.remote_id, "+FLAGS.SILENT", "(\\Deleted)"), "STORE Deleted")
    _ensure_ok(client.expunge(), "EXPUNGE")
