from __future__ import annotations

from collections.abc import Generator, Mapping
from contextlib import contextmanager
import json
import shutil
import sqlite3
import tempfile
import threading
from hashlib import sha1
from pathlib import Path
from typing import Any, cast

from .codec import decode_mail_body, html_to_text
from .models import Account, MailAttachment, MailContent, MailDetails, MailRecord, Mailbox
from .protocol_config import load_server_configs

_SNAPSHOT_LOCK = threading.Lock()
_SNAPSHOT_CACHE: dict[Path, tuple[Path, tuple[tuple[int, int], tuple[int, int] | None]]] = {}


def _file_signature(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return (stat.st_mtime_ns, stat.st_size)


def copy_sqlite_snapshot(path: Path) -> Path:
    resolved = path.resolve()
    src_stat = resolved.stat()
    src_sig = (src_stat.st_mtime_ns, src_stat.st_size)
    wal_sig = _file_signature(Path(f"{resolved}-wal"))
    signature = (src_sig, wal_sig)

    temp_dir = Path(tempfile.gettempdir()) / "mailmaster"
    digest = sha1(str(resolved).encode("utf-8")).hexdigest()[:10]
    target = temp_dir / f"{digest}_{resolved.name}"

    with _SNAPSHOT_LOCK:
        cached = _SNAPSHOT_CACHE.get(resolved)
        if cached is not None:
            cached_target, cached_sig = cached
            if cached_target == target and cached_sig == signature and cached_target.exists():
                return cached_target

        temp_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(resolved, target)
        for suffix in ("-wal", "-shm"):
            sidecar_src = Path(f"{resolved}{suffix}")
            sidecar_dst = Path(f"{target}{suffix}")
            if sidecar_src.exists():
                shutil.copy2(sidecar_src, sidecar_dst)
            else:
                sidecar_dst.unlink(missing_ok=True)

        _SNAPSHOT_CACHE[resolved] = (target, signature)
        return target


_copy_to_temp = copy_sqlite_snapshot


@contextmanager
def _connect_sqlite(path: Path, *, as_bytes: bool = False) -> Generator[sqlite3.Connection, None, None]:
    db = sqlite3.connect(copy_sqlite_snapshot(path))
    if as_bytes:
        db.text_factory = bytes
    try:
        yield db
    finally:
        db.close()


def _parse_jsonish(value: str | bytes | None) -> object:
    if value in (None, "", b""):
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _normalize_contacts(value: str | bytes | None) -> list[str]:
    parsed = _parse_jsonish(value)
    if parsed is None:
        return []
    if isinstance(parsed, dict):
        return [_contact_to_text(parsed)]
    if isinstance(parsed, list):
        contacts: list[str] = []
        for item in parsed:
            if isinstance(item, str):
                nested = _parse_jsonish(item)
                if isinstance(nested, dict):
                    contacts.append(_contact_to_text(nested))
                else:
                    contacts.append(str(item))
            elif isinstance(item, dict):
                contacts.append(_contact_to_text(item))
            else:
                contacts.append(str(item))
        return contacts
    return [str(parsed)]


def _contact_to_text(contact: dict) -> str:
    data = cast(Mapping[str, Any], contact)
    name = str(data.get("name") or "").strip()
    mail = str(data.get("mail") or "").strip()
    if name and mail:
        return f"{name} <{mail}>"
    return mail or name


def _sender_info(value: str | bytes | None) -> tuple[str, str]:
    parsed = _parse_jsonish(value)
    if isinstance(parsed, dict):
        data = cast(Mapping[str, Any], parsed)
        return str(data.get("name") or "").strip(), str(data.get("mail") or "").strip()
    return "", ""


def _sqlite_text(value: object) -> str | bytes | None:
    if value is None or isinstance(value, (str, bytes)):
        return value
    return str(value)


def _sqlite_int(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, bytes):
        return int(value.decode("utf-8", errors="ignore") or 0)
    return int(str(value) or 0)


class LocalLookupError(ValueError):
    """A local identifier did not resolve; carries a stable code for the CLI layer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class MailMasterStore:
    def __init__(self, app_db_path: Path):
        self.app_db_path = app_db_path

    def get_accounts(self) -> list[Account]:
        with _connect_sqlite(self.app_db_path) as conn:
            rows = conn.execute(
                "SELECT ID, Type, Valid, Name, Email, DataPath FROM Account ORDER BY ID"
            ).fetchall()
        return [
            Account(
                id=int(row[0]),
                type=int(row[1]),
                valid=bool(row[2]),
                name=str(row[3] or ""),
                email=str(row[4] or ""),
                data_path=Path(str(row[5] or "")),
            )
            for row in rows
        ]

    def get_account(self, identifier: str | int) -> Account:
        ident = str(identifier)
        for account in self.get_accounts():
            if ident in {str(account.id), account.email, account.name}:
                return account
        raise LocalLookupError("account_not_found", f"Account not found: {identifier}")


class AccountStore:
    def __init__(self, account: Account, *, install_root: Path | None = None):
        self.account = account
        self.mail_db = account.data_path / "mail.db"
        self.content_db = account.data_path / "content.db"
        self.install_root = install_root

    def get_mailboxes(self) -> list[Mailbox]:
        with _connect_sqlite(self.mail_db) as conn:
            rows = conn.execute(
                "SELECT Id, Parent, DisplayName, Type, SyncState, Remind, UIFlags FROM Mailbox ORDER BY Type, Id"
            ).fetchall()
        return [
            Mailbox(
                id=str(row[0]),
                parent=str(row[1] or ""),
                display_name=str(row[2] or ""),
                type=int(row[3] or 0),
                sync_state=int(row[4] or 0),
                remind=int(row[5] or 0),
                ui_flags=int(row[6] or 0),
            )
            for row in rows
        ]

    def get_server_configs(self) -> dict[str, dict[str, object]]:
        return load_server_configs(self.mail_db, install_root=self.install_root)

    def resolve_mailbox(self, mailbox: str | None) -> str | None:
        if mailbox is None:
            return None
        for box in self.get_mailboxes():
            if mailbox in {box.id, box.display_name}:
                return box.id
        raise LocalLookupError("mailbox_not_found", f"Mailbox not found: {mailbox}")

    def list_mail(self, *, mailbox: str | None = None, unread_only: bool = False, limit: int = 20) -> list[MailRecord]:
        mailbox_id = self.resolve_mailbox(mailbox)
        clauses = ["Deleted = 0"]
        params: list[object] = []
        if mailbox_id is not None:
            clauses.append("Mailbox = ?")
            params.append(mailbox_id)
        if unread_only:
            clauses.append("Unread = 1")
        params.append(limit)

        sql = f"""
        SELECT LocalId, RemoteId, Mailbox, Subject, Summary, Froms, Tos, Ccs, ReplyTos,
               Unread, Starred, HasAttachments, Replied, Forwarded,
               ReceivedDate, OrigDate, MessageId, ReferenceIds
        FROM MailMeta
        WHERE {' AND '.join(clauses)}
        ORDER BY ReceivedDate DESC
        LIMIT ?
        """

        with _connect_sqlite(self.mail_db) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_mail_record(row) for row in rows]

    def search_mail(
        self,
        query: str,
        *,
        mailbox: str | None = None,
        limit: int = 20,
        include_body: bool = False,
    ) -> list[MailRecord]:
        mailbox_id = self.resolve_mailbox(mailbox)
        like = f"%{query}%"
        params: list[object] = [like, like, like, like, like]
        mailbox_sql = ""
        if mailbox_id is not None:
            mailbox_sql = " AND Mailbox = ?"
            params.append(mailbox_id)
        params.append(max(limit * (5 if include_body else 1), limit))

        sql = f"""
        SELECT LocalId, RemoteId, Mailbox, Subject, Summary, Froms, Tos, Ccs, ReplyTos,
               Unread, Starred, HasAttachments, Replied, Forwarded,
               ReceivedDate, OrigDate, MessageId, ReferenceIds
        FROM MailMeta
        WHERE Deleted = 0
          AND (
              Subject LIKE ? OR Summary LIKE ? OR Froms LIKE ? OR Tos LIKE ? OR Ccs LIKE ?
          )
          {mailbox_sql}
        ORDER BY ReceivedDate DESC
        LIMIT ?
        """

        with _connect_sqlite(self.mail_db) as conn:
            candidates = [self._row_to_mail_record(row) for row in conn.execute(sql, params).fetchall()]

        if not include_body:
            return candidates[:limit]

        contents = self.get_contents_bulk([record.local_id for record in candidates])
        query_lower = query.lower()
        matched: list[MailRecord] = []
        for record in candidates:
            body = contents.get(record.local_id) or MailContent(mail_id=record.local_id)
            body_text = (body.text_body or "") + "\n" + (body.html_body or "")
            if query_lower in body_text.lower() or query_lower in record.subject.lower() or query_lower in record.summary.lower():
                matched.append(record)
            if len(matched) >= limit:
                break
        return matched

    def get_mail(self, mail_id: str) -> MailRecord:
        with _connect_sqlite(self.mail_db) as conn:
            row = conn.execute(
                """
                SELECT LocalId, RemoteId, Mailbox, Subject, Summary, Froms, Tos, Ccs, ReplyTos,
                       Unread, Starred, HasAttachments, Replied, Forwarded,
                       ReceivedDate, OrigDate, MessageId, ReferenceIds
                FROM MailMeta
                WHERE LocalId = ? OR RemoteId = ?
                LIMIT 1
                """,
                (mail_id, mail_id),
            ).fetchone()
        if row is None:
            raise LocalLookupError("mail_not_found", f"Mail not found: {mail_id}")
        return self._row_to_mail_record(row)

    def get_attachments(self, mail_id: int) -> list[MailAttachment]:
        with _connect_sqlite(self.mail_db) as conn:
            rows = conn.execute(
                "SELECT LocalId, MailId, Name, Size, ContentType, LocalPath FROM MailAttachment WHERE MailId = ? ORDER BY LocalId",
                (mail_id,),
            ).fetchall()
        return [
            MailAttachment(
                local_id=int(row[0]),
                mail_id=int(row[1]),
                name=str(row[2] or ""),
                size=int(row[3] or 0),
                content_type=str(row[4] or ""),
                local_path=str(row[5] or ""),
            )
            for row in rows
        ]

    @staticmethod
    def _build_mail_content(mail_id: int, rows: list[tuple[Any, ...]]) -> MailContent:
        text_body: str | None = None
        html_body: str | None = None
        html_as_text: str | None = None
        for row in rows:
            _, content_type, body, compress_type = row
            decoded = decode_mail_body(body, _sqlite_int(compress_type))
            if _sqlite_int(content_type) == 1:
                html_body = decoded
                html_as_text = html_to_text(decoded)
            else:
                text_body = decoded
        if html_as_text and (
            not text_body
            or text_body.strip().lower().startswith("this is an html email")
            or len(text_body.strip()) < 80
        ):
            text_body = html_as_text
        return MailContent(mail_id=mail_id, text_body=text_body, html_body=html_body)

    def get_content(self, mail_id: int) -> MailContent:
        with _connect_sqlite(self.content_db, as_bytes=True) as conn:
            rows = conn.execute(
                "SELECT MailId, ContentType, OrigBody, CompressType FROM MailContent WHERE MailId = ? ORDER BY ContentType DESC",
                (mail_id,),
            ).fetchall()
        return self._build_mail_content(mail_id, rows)

    def get_contents_bulk(self, mail_ids: list[int]) -> dict[int, MailContent]:
        unique_ids = list(dict.fromkeys(mail_ids))
        if not unique_ids:
            return {}
        if not self.content_db.exists():
            return {mid: MailContent(mail_id=mid) for mid in unique_ids}

        grouped: dict[int, list[tuple[Any, ...]]] = {mid: [] for mid in unique_ids}
        with _connect_sqlite(self.content_db, as_bytes=True) as conn:
            for start in range(0, len(unique_ids), 500):
                batch = unique_ids[start : start + 500]
                placeholders = ", ".join("?" for _ in batch)
                rows = conn.execute(
                    f"SELECT MailId, ContentType, OrigBody, CompressType FROM MailContent WHERE MailId IN ({placeholders}) ORDER BY MailId, ContentType DESC",
                    batch,
                ).fetchall()
                for row in rows:
                    row_mail_id = _sqlite_int(row[0])
                    if row_mail_id in grouped:
                        grouped[row_mail_id].append(row)

        return {mid: self._build_mail_content(mid, grouped[mid]) for mid in unique_ids}

    def get_details(self, mail_id: str) -> MailDetails:
        record = self.get_mail(mail_id)
        return MailDetails(
            record=record,
            attachments=self.get_attachments(record.local_id),
            content=self.get_content(record.local_id),
        )

    def _row_to_mail_record(self, row: tuple[object, ...]) -> MailRecord:
        sender_name, sender_email = _sender_info(_sqlite_text(row[5]))
        return MailRecord(
            local_id=_sqlite_int(row[0]),
            remote_id=str(row[1] or ""),
            mailbox=str(row[2] or ""),
            subject=str(row[3] or ""),
            summary=str(row[4] or ""),
            sender_name=sender_name,
            sender_email=sender_email,
            to_list=_normalize_contacts(_sqlite_text(row[6])),
            cc_list=_normalize_contacts(_sqlite_text(row[7])),
            reply_to_list=_normalize_contacts(_sqlite_text(row[8])),
            unread=bool(row[9]),
            starred=bool(row[10]),
            has_attachments=bool(row[11]),
            replied=bool(row[12]),
            forwarded=bool(row[13]),
            received_ts_ms=_sqlite_int(row[14]),
            orig_ts_ms=_sqlite_int(row[15]),
            message_id=str(row[16] or ""),
            reference_ids=str(row[17] or ""),
        )
