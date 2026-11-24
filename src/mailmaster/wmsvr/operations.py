"""Wmsvr compose, send, draft, and attachment upload helpers and session mixin."""

from __future__ import annotations

import json
import mimetypes
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .d1_wire import WmsvrD1Frame, WmsvrD1RequestContext, build_wmsvr_d1_binary_request_frame
from .lz4 import (
    COMPOSE_ACTION_CONTINUE,
    COMPOSE_ACTION_DELIVER,
    COMPOSE_ACTION_SAVE,
    COMPOSE_MAILER_EXT,
    DEFAULT_ATTACHMENT_CONTENT_TYPE,
    DEFAULT_UPLOAD_CHUNK_SIZE,
    DRAFT_FOLDER_FID,
    DRAFT_INFO_FIELDS,
    ERROR_COMPOSE_ID_UNKNOWN,
    ERROR_DRAFT_NOT_FOUND,
    ERROR_METHOD_REJECTED,
    ERROR_NOT_VERIFIED,
    ERROR_UPLOAD_REJECTED,
    MESSAGE_INFO_FIELDS,
    METHOD_COMPOSE,
    METHOD_LIST_MESSAGES,
    METHOD_RESTORE_DRAFT,
    METHOD_UPLOAD_ATTACH,
    METHOD_UPLOAD_PREPARE,
    REPLY_CODE_DRAFT_RECREATED,
    REPLY_CODE_ID_NOT_FOUND,
    SENT_FOLDER_FID,
    SENT_READBACK_FIELDS,
    WmsvrMailError,
    parse_business_reply,
    raise_for_reply,
)
from .tlv import TAG_UPLOAD_METADATA

if TYPE_CHECKING:
    from .bootstrap import WmsvrSession


@dataclass(frozen=True)
class WmsvrAttachment:
    """One attachment to upload with the private protocol (`wzp:uploadAttach`).

    `content_type` goes into the chunk metadata; the bytes go into the request body.
    """

    file_name: str
    data: bytes
    content_type: str = DEFAULT_ATTACHMENT_CONTENT_TYPE

    @property
    def size(self) -> int:
        return len(self.data)

    @classmethod
    def from_path(cls, path: str | Path) -> WmsvrAttachment:
        """Read a local file into an attachment; the content type comes from the suffix."""
        resolved = Path(path)
        return cls(
            file_name=resolved.name,
            data=resolved.read_bytes(),
            content_type=guess_attachment_content_type(resolved.name),
        )


def guess_attachment_content_type(file_name: str) -> str:
    """The metadata `contentType`: the suffix's registered type, else the generic one."""
    guessed = mimetypes.guess_type(str(file_name))[0]
    return guessed or DEFAULT_ATTACHMENT_CONTENT_TYPE


def build_upload_metadata(
    *,
    compose_id: str,
    file_name: str,
    content_type: str,
    attachment_id: int,
    size: int,
    offset: int = 0,
) -> dict[str, Any]:
    """The chunk metadata that rides record `0x0103` (RE §4.87/§4.88/§4.90)."""
    return {
        "offset": int(offset),
        "composeId": str(compose_id),
        "fileName": str(file_name),
        "contentType": str(content_type),
        "attachmentId": int(attachment_id),
        "size": int(size),
    }


def _first_int(*values: Any) -> int | None:
    """The server echoes ids/sizes as either numbers or strings; take either."""
    for value in values:
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
    return None


def _saved_sent_remote_id(saved_sent: Mapping[str, Any]) -> str | None:
    """Build the sent copy's remote id (`<msid>:<mid>`) from the reply's `savedSent`."""
    mid = saved_sent.get("mid")
    if not mid:
        return None
    msid = saved_sent.get("msid")
    if msid is None:
        return str(mid)
    return f"{msid}:{mid}"


class _WmsvrComposeOperationsMixin:
    """Compose, send, draft, and attachment-upload methods mixed into `WmsvrMailSession`."""

    if TYPE_CHECKING:
        session: WmsvrSession
        session_key: bytes

        def _next_seq(self) -> int: ...
        def _send_recv(self, frame: WmsvrD1Frame, *, timeout: float | None = None) -> WmsvrD1Frame: ...
        def _business_context(self) -> WmsvrD1RequestContext: ...
        def request(self, method: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]: ...
        def request_lenient(self, method: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]: ...
        def _records_by_mid(
            self,
            ids: list[str],
            *,
            fields: Iterable[str] = MESSAGE_INFO_FIELDS,
        ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]: ...

    # -- send / compose ----------------------------------------------------
    def create_compose(self) -> dict[str, Any]:
        """Mint a compose object with `mbox:compose` + `action:"continue"`."""
        reply = self.request(
            METHOD_COMPOSE,
            {
                "action": COMPOSE_ACTION_CONTINUE,
                "returnInfo": True,
                "xMailerExt": COMPOSE_MAILER_EXT,
            },
        )
        records = reply.get("records")
        compose = records if isinstance(records, dict) else {}
        if not compose.get("id"):
            raise WmsvrMailError(
                ERROR_METHOD_REJECTED,
                "the compose call was accepted but its reply carried no compose id",
                details={"code": reply.get("code"), "action": COMPOSE_ACTION_CONTINUE},
            )
        return compose

    def _compose_attrs(
        self,
        *,
        account: str,
        to: Iterable[str],
        cc: Iterable[str],
        bcc: Iterable[str],
        subject: str,
        html_body: str,
        text_body: str,
        save_sent_copy: bool,
        request_read_receipt: bool,
        show_one_rcpt: bool,
        what: str,
    ) -> dict[str, Any]:
        """The `attrs` block the client sends for both `deliver` and `save` (rounds 62/69)."""
        recipients = [str(item) for item in to]
        if not recipients:
            raise ValueError(f"a {what} needs at least one recipient.")
        content = html_body or text_body
        if not content:
            raise ValueError(f"a {what} needs a body (`html_body` or `text_body`).")
        return {
            "account": account,
            "to": recipients,
            "cc": [str(item) for item in cc],
            "bcc": [str(item) for item in bcc],
            "content": content,
            "isHtml": bool(html_body),
            "requestReadReceipt": bool(request_read_receipt),
            "saveSentCopy": bool(save_sent_copy),
            "showOneRcpt": bool(show_one_rcpt),
            "subject": subject,
        }

    def _compose_body(
        self, action: str, attrs: Mapping[str, Any], compose_id: str
    ) -> dict[str, Any]:
        """The three-step compose body shared by `deliver` and `save` (rounds 62/66/69)."""
        return {
            "action": action,
            "attrs": dict(attrs),
            "id": compose_id,
            "mailTrace": True,
            "notReturn": ["content", "headers", "attachments"],
            "returnInfo": True,
            "returnSavedSent": True,
            "xMailerExt": COMPOSE_MAILER_EXT,
        }

    def _check_uploads_completed(self, result: dict[str, Any], message: str) -> None:
        incomplete = [
            item for item in result.get("attachments") or [] if not item.get("completed")
        ]
        if incomplete:
            result.update(
                {
                    "state_change_verified": False,
                    "upload_incomplete": incomplete,
                }
            )
            raise WmsvrMailError(ERROR_UPLOAD_REJECTED, message, details=result)

    def _resolve_folder_record(
        self,
        direct_id: str | None,
        *,
        subject: str,
        folder_fid: int,
        fields: Iterable[str],
        readback_limit: int,
        fallback_if_missing_record: bool,
    ) -> tuple[str | None, dict[str, Any], Any, bool]:
        """Resolve a saved/sent copy by direct id or fallback newest-first folder listing."""
        fallback = False
        record: dict[str, Any] = {}
        read_back_code: Any = None
        resolved_id = direct_id
        if resolved_id:
            by_mid, read_back = self._records_by_mid([resolved_id], fields=fields)
            record = by_mid.get(resolved_id) or {}
            read_back_code = read_back.get("code")
        should_fallback = (not record) if fallback_if_missing_record else (not resolved_id)
        if should_fallback:
            fallback = True
            listing = self.request_lenient(
                METHOD_LIST_MESSAGES,
                {"desc": True, "fids": [int(folder_fid)], "limit": int(readback_limit)},
            )
            listed = listing.get("records")
            candidates = (
                [item for item in listed if isinstance(item, str)] if isinstance(listed, list) else []
            )
            if candidates:
                by_mid, read_back = self._records_by_mid(candidates, fields=fields)
                read_back_code = read_back.get("code")
                matched = next(
                    (
                        candidate
                        for candidate in candidates
                        if subject
                        and str((by_mid.get(candidate) or {}).get("subject") or "") == subject
                    ),
                    None,
                )
                resolved_id = matched or candidates[0]
                record = by_mid.get(resolved_id) or {}
        return resolved_id, record, read_back_code, fallback

    def _verify_sent_copy(
        self,
        result: dict[str, Any],
        *,
        subject: str,
        sent_folder_fid: int,
        readback_limit: int,
        include_size: bool,
        failure_message: str,
    ) -> dict[str, Any]:
        """Read back the delivered copy from the sent folder and verify it resolved."""
        saved_sent = result.get("saved_sent") or {}
        sent_id, record, read_back_code, fallback = self._resolve_folder_record(
            _saved_sent_remote_id(saved_sent),
            subject=subject,
            folder_fid=sent_folder_fid,
            fields=SENT_READBACK_FIELDS,
            readback_limit=readback_limit,
            fallback_if_missing_record=False,
        )
        folder = record.get("fid")
        resolved_folder = int(folder) if isinstance(folder, (int, float)) else None
        subject_matched = (not subject) or str(record.get("subject") or "") == subject
        verified = bool(record) and subject_matched
        update: dict[str, Any] = {
            "sent_id": sent_id,
            "sent_folder_fid": resolved_folder,
            "sent_subject": record.get("subject"),
            "read_back_code": read_back_code,
            "readback_fallback": fallback,
            "state_change_verified": verified,
        }
        if include_size:
            update["sent_size"] = record.get("size")
        result.update(update)
        if not verified:
            raise WmsvrMailError(ERROR_NOT_VERIFIED, failure_message, details=result)
        return result

    def send_mail(
        self,
        *,
        account: str,
        to: Iterable[str],
        cc: Iterable[str] = (),
        bcc: Iterable[str] = (),
        subject: str = "",
        html_body: str = "",
        text_body: str = "",
        save_sent_copy: bool = True,
        request_read_receipt: bool = False,
        show_one_rcpt: bool = False,
        compose_id: str | None = None,
    ) -> dict[str, Any]:
        """Send one mail with the compose family; returns the delivery outcome."""
        attrs = self._compose_attrs(
            account=account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            save_sent_copy=save_sent_copy,
            request_read_receipt=request_read_receipt,
            show_one_rcpt=show_one_rcpt,
            what="send",
        )
        resolved_compose_id = compose_id or str(self.create_compose()["id"])
        reply = self.request(
            METHOD_COMPOSE, self._compose_body(COMPOSE_ACTION_DELIVER, attrs, resolved_compose_id)
        )
        records = reply.get("records")
        records = records if isinstance(records, dict) else {}
        saved_sent = records.get("savedSent")
        return {
            "transport": "wmsvr-private",
            "method": METHOD_COMPOSE,
            "action": COMPOSE_ACTION_DELIVER,
            "compose_id": resolved_compose_id,
            "account": account,
            "to": attrs["to"],
            "cc": attrs["cc"],
            "bcc": attrs["bcc"],
            "subject": subject,
            "save_sent_copy": bool(save_sent_copy),
            "code": reply.get("code"),
            "delivery_msg_type": records.get("deliveryMsgType"),
            "sent_tinfo": records.get("sentTInfo"),
            "saved_sent": saved_sent if isinstance(saved_sent, dict) else {},
        }

    # -- attachments -------------------------------------------------------
    def prepare_attachment(
        self,
        *,
        compose_id: str,
        file_name: str,
        size: int,
    ) -> dict[str, Any]:
        """`upload:prepare` — declare one attachment on a compose and let the server id it."""
        reply = self.request(
            METHOD_UPLOAD_PREPARE,
            {
                "composeId": str(compose_id),
                "attachmentId": 0,
                "fileName": str(file_name),
                "size": int(size),
            },
        )
        records = reply.get("records")
        records = records if isinstance(records, dict) else {}
        attachment_id = _first_int(records.get("attachmentId"))
        if attachment_id is None:
            raise WmsvrMailError(
                ERROR_UPLOAD_REJECTED,
                "the server accepted upload:prepare but its reply carried no attachment id",
                details={"compose_id": compose_id, "records": records},
            )
        return {
            "transport": "wmsvr-private",
            "method": METHOD_UPLOAD_PREPARE,
            "code": reply.get("code"),
            "compose_id": str(compose_id),
            "attachment_id": attachment_id,
            "file_name": records.get("fileName"),
            "size": _first_int(records.get("size"), size),
            "records": dict(records),
        }

    def upload_attachment(
        self,
        *,
        compose_id: str,
        attachment_id: int,
        file_name: str,
        content_type: str,
        data: bytes,
        chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
    ) -> dict[str, Any]:
        """`wzp:uploadAttach` — upload one attachment as one or more packets (RE §4.90)."""
        payload = bytes(data)
        total = len(payload)
        step = max(1, int(chunk_size))
        packets: list[dict[str, Any]] = []
        offset = 0
        while True:
            chunk = payload[offset : offset + step]
            metadata = build_upload_metadata(
                compose_id=compose_id,
                file_name=file_name,
                content_type=content_type,
                attachment_id=attachment_id,
                size=total,
                offset=offset,
            )
            metadata_json = json.dumps(
                metadata, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            frame = build_wmsvr_d1_binary_request_frame(
                self._business_context(),
                self.session,
                METHOD_UPLOAD_ATTACH,
                payload=chunk,
                records=((TAG_UPLOAD_METADATA, metadata_json),),
                seq=self._next_seq(),
            )
            reply = parse_business_reply(self._send_recv(frame), self.session_key)
            records = reply.get("records")
            records = records if isinstance(records, dict) else {}
            actual_size = _first_int(records.get("actualSize"))
            packet = {
                "offset": offset,
                "length": len(chunk),
                "code": reply.get("code"),
                "word0": reply.get("word0"),
                "actual_size": actual_size,
                "size": _first_int(records.get("size"), total),
                "attachment_id": _first_int(records.get("attachmentId"), attachment_id),
                "metadata": metadata,
                "records": dict(records),
            }
            packets.append(packet)
            if reply.get("code") != "S_OK":
                raise WmsvrMailError(
                    ERROR_UPLOAD_REJECTED,
                    "the server rejected an attachment packet",
                    details={
                        "transport": "wmsvr-private",
                        "method": METHOD_UPLOAD_ATTACH,
                        "compose_id": str(compose_id),
                        "attachment_id": attachment_id,
                        "file_name": file_name,
                        "offset": offset,
                        "length": len(chunk),
                        "sent": offset + len(chunk),
                        "size": total,
                        "code": reply.get("code"),
                        "packets": packets,
                        "records": dict(records),
                    },
                )
            expected = offset + len(chunk)
            if actual_size is not None and actual_size != expected:
                raise WmsvrMailError(
                    ERROR_UPLOAD_REJECTED,
                    "the server's cumulative byte count does not match what was sent",
                    details={
                        "transport": "wmsvr-private",
                        "method": METHOD_UPLOAD_ATTACH,
                        "compose_id": str(compose_id),
                        "attachment_id": attachment_id,
                        "file_name": file_name,
                        "offset": offset,
                        "length": len(chunk),
                        "expected_actual_size": expected,
                        "actual_size": actual_size,
                        "size": total,
                        "packets": packets,
                        "records": dict(records),
                    },
                )
            offset = expected
            if offset >= total:
                break
        last = packets[-1]
        return {
            "transport": "wmsvr-private",
            "method": METHOD_UPLOAD_ATTACH,
            "compose_id": str(compose_id),
            "code": last["code"],
            "word0": last["word0"],
            "attachment_id": last["attachment_id"],
            "file_name": file_name,
            "content_type": content_type,
            "size": total,
            "sent": offset,
            "chunk_size": step,
            "packets": packets,
            "actual_size": last["actual_size"],
            "completed": (
                last["actual_size"] == total
                if last["actual_size"] is not None
                else offset == total
            ),
            "metadata": last["metadata"],
            "records": last["records"],
        }

    def _upload_attachments(
        self,
        compose_id: str,
        attachments: Iterable[WmsvrAttachment],
        *,
        chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
    ) -> list[dict[str, Any]]:
        """prepare + chunked `wzp:uploadAttach` for every attachment (shared by send/save)."""
        prepared = [
            item if isinstance(item, WmsvrAttachment) else WmsvrAttachment(**item)
            for item in attachments
        ]
        uploaded: list[dict[str, Any]] = []
        for item in prepared:
            declaration = self.prepare_attachment(
                compose_id=compose_id, file_name=item.file_name, size=item.size
            )
            chunk = self.upload_attachment(
                compose_id=compose_id,
                attachment_id=int(declaration["attachment_id"]),
                file_name=item.file_name,
                content_type=item.content_type,
                data=item.data,
                chunk_size=chunk_size,
            )
            uploaded.append(
                {
                    "file_name": item.file_name,
                    "content_type": item.content_type,
                    "size": item.size,
                    "attachment_id": chunk["attachment_id"],
                    "declared_attachment_id": declaration["attachment_id"],
                    "actual_size": chunk["actual_size"],
                    "sent": chunk["sent"],
                    "packets": len(chunk["packets"]),
                    "completed": chunk["completed"],
                }
            )
        return uploaded

    def send_mail_with_attachments(
        self,
        *,
        account: str,
        to: Iterable[str],
        cc: Iterable[str] = (),
        bcc: Iterable[str] = (),
        subject: str = "",
        html_body: str = "",
        text_body: str = "",
        attachments: Iterable[WmsvrAttachment] = (),
        save_sent_copy: bool = True,
        request_read_receipt: bool = False,
        show_one_rcpt: bool = False,
        compose_id: str | None = None,
        upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
    ) -> dict[str, Any]:
        """Send one mail with attachments over the private protocol (RE §4.88/§4.90)."""
        prepared = list(attachments)
        attrs = self._compose_attrs(
            account=account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            save_sent_copy=save_sent_copy,
            request_read_receipt=request_read_receipt,
            show_one_rcpt=show_one_rcpt,
            what="send",
        )
        resolved_compose_id = compose_id or str(self.create_compose()["id"])
        uploaded = self._upload_attachments(
            resolved_compose_id, prepared, chunk_size=upload_chunk_size
        )
        entries = [{"id": int(item["attachment_id"]), "deleted": False} for item in uploaded]
        body = self._compose_body(COMPOSE_ACTION_DELIVER, attrs, resolved_compose_id)
        if entries:
            body["attachments"] = entries
        reply = self.request(METHOD_COMPOSE, body)
        records = reply.get("records")
        records = records if isinstance(records, dict) else {}
        saved_sent = records.get("savedSent")
        return {
            "transport": "wmsvr-private",
            "method": METHOD_COMPOSE,
            "action": COMPOSE_ACTION_DELIVER,
            "compose_id": resolved_compose_id,
            "account": account,
            "to": attrs["to"],
            "cc": attrs["cc"],
            "bcc": attrs["bcc"],
            "subject": subject,
            "save_sent_copy": bool(save_sent_copy),
            "code": reply.get("code"),
            "delivery_msg_type": records.get("deliveryMsgType"),
            "sent_tinfo": records.get("sentTInfo"),
            "saved_sent": saved_sent if isinstance(saved_sent, dict) else {},
            "attachments": uploaded,
            "attachment_entries": entries,
        }

    # -- drafts ------------------------------------------------------------
    def save_draft(
        self,
        *,
        account: str,
        to: Iterable[str] = (),
        cc: Iterable[str] = (),
        bcc: Iterable[str] = (),
        subject: str = "",
        html_body: str = "",
        text_body: str = "",
        save_sent_copy: bool = True,
        compose_id: str | None = None,
        attachments: Iterable[WmsvrAttachment] = (),
        upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
    ) -> dict[str, Any]:
        """Create or update a server-side DRAFT with the compose family (`action:"save"`)."""
        attrs = self._compose_attrs(
            account=account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            save_sent_copy=save_sent_copy,
            request_read_receipt=False,
            show_one_rcpt=False,
            what="draft",
        )
        resolved_compose_id = compose_id or str(self.create_compose()["id"])
        uploaded = self._upload_attachments(
            resolved_compose_id, attachments, chunk_size=upload_chunk_size
        )
        body = self._compose_body(COMPOSE_ACTION_SAVE, attrs, resolved_compose_id)
        if uploaded:
            body["attachments"] = [
                {"id": int(item["attachment_id"]), "deleted": False} for item in uploaded
            ]
        reply = self.request_lenient(METHOD_COMPOSE, body)
        code = reply.get("code")
        records = reply.get("records")
        records = records if isinstance(records, dict) else {}
        draft_id = records.get("draftId")
        recreated = bool(not draft_id and code == REPLY_CODE_DRAFT_RECREATED)
        if not draft_id and not recreated:
            if code == REPLY_CODE_ID_NOT_FOUND:
                raise WmsvrMailError(
                    ERROR_COMPOSE_ID_UNKNOWN,
                    "the compose id was not recognised by the server: it was never issued, or it has "
                    "expired (round 76 measured an id from ~2 h earlier being refused this way)",
                    details={
                        "code": code,
                        "action": COMPOSE_ACTION_SAVE,
                        "compose_id_supplied": bool(compose_id),
                    },
                )
            if code != "S_OK":
                raise_for_reply(reply, method=METHOD_COMPOSE)
            raise WmsvrMailError(
                ERROR_METHOD_REJECTED,
                "the save call was accepted but its reply carried no draft id",
                details={"code": code, "action": COMPOSE_ACTION_SAVE},
            )
        return {
            "transport": "wmsvr-private",
            "method": METHOD_COMPOSE,
            "action": COMPOSE_ACTION_SAVE,
            "mode": "update" if compose_id else "create",
            "recreated": recreated,
            "compose_id": resolved_compose_id,
            "account": account,
            "to": attrs["to"],
            "cc": attrs["cc"],
            "bcc": attrs["bcc"],
            "subject": subject,
            "save_sent_copy": bool(save_sent_copy),
            "code": code,
            "draft_id": str(draft_id) if draft_id else None,
            "delivery_msg_type": records.get("deliveryMsgType"),
            "records_id": records.get("id"),
            "attachments": uploaded,
            "attachment_entries": body.get("attachments") or [],
        }

    def save_draft_verified(
        self,
        *,
        account: str,
        to: Iterable[str] = (),
        cc: Iterable[str] = (),
        bcc: Iterable[str] = (),
        subject: str = "",
        html_body: str = "",
        text_body: str = "",
        compose_id: str | None = None,
        draft_folder_fid: int = DRAFT_FOLDER_FID,
        readback_limit: int = 5,
        attachments: Iterable[WmsvrAttachment] = (),
        upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
    ) -> dict[str, Any]:
        """Save a draft and verify it resolves on the server in the same session."""
        result = self.save_draft(
            account=account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            compose_id=compose_id,
            attachments=attachments,
            upload_chunk_size=upload_chunk_size,
        )
        self._check_uploads_completed(
            result, "the draft was saved but an attachment upload did not complete"
        )
        draft_id, record, read_back_code, fallback = self._resolve_folder_record(
            result.get("draft_id"),
            subject=subject,
            folder_fid=draft_folder_fid,
            fields=DRAFT_INFO_FIELDS,
            readback_limit=readback_limit,
            fallback_if_missing_record=True,
        )
        folder = record.get("fid")
        resolved_folder = int(folder) if isinstance(folder, (int, float)) else None
        subject_matched = (not subject) or str(record.get("subject") or "") == subject
        verified = bool(record) and subject_matched
        result.update(
            {
                "draft_id": draft_id,
                "draft_folder_fid": resolved_folder,
                "draft_subject": record.get("subject"),
                "draft_size": record.get("size"),
                "read_back_code": read_back_code,
                "readback_fallback": fallback,
                "state_change_verified": verified,
            }
        )
        if not verified:
            raise WmsvrMailError(
                ERROR_NOT_VERIFIED,
                "the server accepted the draft but it does not resolve in the drafts folder",
                details=result,
            )
        return result

    def send_mail_verified(
        self,
        *,
        account: str,
        to: Iterable[str],
        cc: Iterable[str] = (),
        bcc: Iterable[str] = (),
        subject: str = "",
        html_body: str = "",
        text_body: str = "",
        sent_folder_fid: int = SENT_FOLDER_FID,
        readback_limit: int = 5,
    ) -> dict[str, Any]:
        """Send mail and verify the sent copy resolves on the server in the same session."""
        result = self.send_mail(
            account=account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            save_sent_copy=True,
        )
        return self._verify_sent_copy(
            result,
            subject=subject,
            sent_folder_fid=sent_folder_fid,
            readback_limit=readback_limit,
            include_size=False,
            failure_message="the server accepted the delivery but the sent copy does not resolve in its sent folder",
        )

    def send_mail_with_attachments_verified(
        self,
        *,
        account: str,
        to: Iterable[str],
        cc: Iterable[str] = (),
        bcc: Iterable[str] = (),
        subject: str = "",
        html_body: str = "",
        text_body: str = "",
        attachments: Iterable[WmsvrAttachment] = (),
        sent_folder_fid: int = SENT_FOLDER_FID,
        readback_limit: int = 5,
        upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK_SIZE,
    ) -> dict[str, Any]:
        """Send with attachments and verify it in the same session."""
        result = self.send_mail_with_attachments(
            account=account,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            attachments=attachments,
            save_sent_copy=True,
            upload_chunk_size=upload_chunk_size,
        )
        self._check_uploads_completed(
            result, "the server did not confirm the full byte count for every attachment"
        )
        return self._verify_sent_copy(
            result,
            subject=subject,
            sent_folder_fid=sent_folder_fid,
            readback_limit=readback_limit,
            include_size=False,
            failure_message="the server accepted the delivery but the sent copy does not resolve in its sent folder",
        )

    def restore_draft(self, draft_id: str) -> dict[str, Any]:
        """Re-open a stored draft as a compose object (`mbox:restoreDraft`, round 88)."""
        reply = self.request_lenient(METHOD_RESTORE_DRAFT, {"id": str(draft_id)})
        code = reply.get("code")
        records = reply.get("records")
        records = records if isinstance(records, dict) else {}
        compose_id = records.get("id")
        if not compose_id:
            if str(code) == "FA_MAIL_NOT_FOUND":
                raise WmsvrMailError(
                    ERROR_DRAFT_NOT_FOUND,
                    "the server does not hold a draft with that id (deleted by another client, "
                    "or the id belongs to a different mailbox)",
                    details={
                        "code": code,
                        "draft_id": str(draft_id),
                        "method": METHOD_RESTORE_DRAFT,
                    },
                )
            if code != "S_OK":
                raise_for_reply(reply, method=METHOD_RESTORE_DRAFT)
            raise WmsvrMailError(
                ERROR_METHOD_REJECTED,
                "the restore call was accepted but its reply carried no compose id",
                details={
                    "code": code,
                    "draft_id": str(draft_id),
                    "method": METHOD_RESTORE_DRAFT,
                },
            )
        descriptors: list[dict[str, Any]] = []
        entries: list[dict[str, Any]] = []
        raw_attachments = records.get("attachments")
        if isinstance(raw_attachments, list):
            for item in raw_attachments:
                if not isinstance(item, dict):
                    continue
                descriptors.append(
                    {
                        "attachment_id": item.get("id"),
                        "type": item.get("type"),
                        "file_name": item.get("name"),
                        "content_type": item.get("contentType"),
                        "size": item.get("size"),
                    }
                )
                if item.get("id") is not None:
                    entries.append({"id": int(item["id"]), "deleted": False})
        return {
            "transport": "wmsvr-private",
            "method": METHOD_RESTORE_DRAFT,
            "draft_id": str(draft_id),
            "compose_id": str(compose_id),
            "code": code,
            "account": records.get("account"),
            "to": [str(item) for item in records.get("to") or []],
            "cc": [str(item) for item in records.get("cc") or []],
            "bcc": [str(item) for item in records.get("bcc") or []],
            "charset": records.get("charset"),
            "subject": records.get("subject") or "",
            "content": records.get("content") or "",
            "is_html": records.get("isHtml"),
            "save_sent_copy": records.get("saveSentCopy"),
            "delivery_msg_type": records.get("deliveryMsgType"),
            "attachments": descriptors,
            "attachment_entries": entries,
        }

    def find_draft(
        self, *, subject: str = "", draft_folder_fid: int = DRAFT_FOLDER_FID, limit: int = 20
    ) -> dict[str, Any]:
        """Resolve one draft in the drafts folder (newest first, the client's own listing)."""
        listing = self.request_lenient(
            METHOD_LIST_MESSAGES,
            {"desc": True, "fids": [int(draft_folder_fid)], "limit": int(limit)},
        )
        listed = listing.get("records")
        ids = [item for item in listed if isinstance(item, str)] if isinstance(listed, list) else []
        if not ids:
            raise WmsvrMailError(
                ERROR_DRAFT_NOT_FOUND,
                "the drafts folder is empty",
                details={"code": listing.get("code"), "draft_folder_fid": int(draft_folder_fid)},
            )
        by_mid, read_back = self._records_by_mid(ids, fields=DRAFT_INFO_FIELDS)
        matched = next(
            (
                mid
                for mid in ids
                if subject and str((by_mid.get(mid) or {}).get("subject") or "") == subject
            ),
            None,
        )
        resolved = matched or (ids[0] if not subject else None)
        if resolved is None:
            raise WmsvrMailError(
                ERROR_DRAFT_NOT_FOUND,
                "no draft in the drafts folder carries that subject",
                details={"code": read_back.get("code"), "subject": subject, "candidates": len(ids)},
            )
        record = by_mid.get(resolved) or {}
        return {
            "transport": "wmsvr-private",
            "method": METHOD_LIST_MESSAGES,
            "draft_id": resolved,
            "draft_folder_fid": record.get("fid"),
            "subject": record.get("subject"),
            "size": record.get("size"),
            "code": read_back.get("code"),
            "fallback": not bool(matched) and bool(subject),
        }

    def send_draft(
        self,
        *,
        draft_id: str,
        to: Iterable[str] | None = None,
        cc: Iterable[str] | None = None,
        bcc: Iterable[str] | None = None,
        subject: str | None = None,
        html_body: str | None = None,
        text_body: str | None = None,
        save_sent_copy: bool = True,
    ) -> dict[str, Any]:
        """Send a stored draft, carrying whatever attachments it already holds (round 88)."""
        restored = self.restore_draft(draft_id)
        attrs: dict[str, Any] = {
            "account": restored.get("account") or "",
            "to": list(restored.get("to") or []),
            "cc": list(restored.get("cc") or []),
            "bcc": list(restored.get("bcc") or []),
            "content": restored.get("content") or "",
            "isHtml": bool(restored.get("is_html")),
            "requestReadReceipt": False,
            "saveSentCopy": bool(save_sent_copy),
            "showOneRcpt": False,
            "subject": restored.get("subject") or "",
        }
        if to is not None:
            attrs["to"] = [str(item) for item in to]
        if cc is not None:
            attrs["cc"] = [str(item) for item in cc]
        if bcc is not None:
            attrs["bcc"] = [str(item) for item in bcc]
        if subject is not None:
            attrs["subject"] = subject
        if html_body is not None:
            attrs["content"] = html_body
            attrs["isHtml"] = True
        elif text_body is not None:
            attrs["content"] = text_body
            attrs["isHtml"] = False
        if not attrs["to"]:
            raise ValueError("sending a draft needs at least one recipient (`to`).")
        if not attrs["content"]:
            raise ValueError("sending a draft needs a body (the draft's content or `html_body`).")
        compose_id = restored["compose_id"]
        body = self._compose_body(COMPOSE_ACTION_DELIVER, attrs, compose_id)
        entries = list(restored.get("attachment_entries") or [])
        if entries:
            body["attachments"] = entries
        reply = self.request_lenient(METHOD_COMPOSE, body)
        code = reply.get("code")
        records = reply.get("records")
        records = records if isinstance(records, dict) else {}
        saved_sent = records.get("savedSent")
        return {
            "transport": "wmsvr-private",
            "method": METHOD_COMPOSE,
            "action": COMPOSE_ACTION_DELIVER,
            "from_draft": True,
            "draft_id": restored["draft_id"],
            "compose_id": compose_id,
            "account": attrs["account"],
            "to": attrs["to"],
            "cc": attrs["cc"],
            "bcc": attrs["bcc"],
            "subject": attrs["subject"],
            "save_sent_copy": bool(save_sent_copy),
            "code": code,
            "delivery_msg_type": records.get("deliveryMsgType"),
            "sent_tinfo": records.get("sentTInfo"),
            "saved_sent": saved_sent if isinstance(saved_sent, dict) else {},
            "attachments": restored.get("attachments") or [],
            "attachment_entries": entries,
        }

    def send_draft_verified(
        self,
        *,
        draft_id: str,
        to: Iterable[str] | None = None,
        cc: Iterable[str] | None = None,
        bcc: Iterable[str] | None = None,
        subject: str | None = None,
        html_body: str | None = None,
        text_body: str | None = None,
        sent_folder_fid: int = SENT_FOLDER_FID,
        readback_limit: int = 5,
    ) -> dict[str, Any]:
        """Send a stored draft and verify the sent copy resolves in the same session."""
        result = self.send_draft(
            draft_id=draft_id,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            save_sent_copy=True,
        )
        sent_subject = str(result.get("subject") or "")
        return self._verify_sent_copy(
            result,
            subject=sent_subject,
            sent_folder_fid=sent_folder_fid,
            readback_limit=readback_limit,
            include_size=True,
            failure_message=(
                "the server accepted the draft's delivery but the sent copy does not resolve in "
                "its sent folder"
            ),
        )
