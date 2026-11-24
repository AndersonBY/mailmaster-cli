"""Live Wmsvr private-protocol mailbox session (`WmsvrMailSession`) and handshake."""

from __future__ import annotations

import hashlib
import json
import secrets
import select
import socket
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from .bootstrap import (
    WmsvrLoginContext,
    WmsvrPeerCandidate,
    WmsvrSession,
    build_default_wmsvr_login_client_id,
)
from .d1_wire import (
    WmsvrD1Frame,
    WmsvrD1RequestContext,
    WmsvrTransportError,
    build_wmsvr_d1_encrypted_frame,
    build_wmsvr_d1_request_frame,
    build_wmsvr_key_exchange_frame,
    decrypt_wmsvr_d1_slice,
    exchange_get_settings,
    generate_wmsvr_d1_session_key,
    open_d1_socket,
    recv_d1_frame,
    send_d1_frame,
)
from .login import (
    build_loginone_body,
    build_update_message_infos_body,
    build_wmsvr_login_frame,
)
from .lz4 import (
    ACCOUNT_DESC_PREFIX,
    APP_SUBVERSION,
    BUSINESS_PORT,
    BUSINESS_WORD2,
    DELETE_TYPE_ACCOUNT,
    DELETE_TYPE_BATCH,
    ERROR_BOOTSTRAP_MISSING,
    ERROR_LOGIN_CREDENTIAL_MISSING,
    ERROR_LOGIN_MATERIAL_MISSING,
    ERROR_LOGIN_REJECTED,
    ERROR_NOT_VERIFIED,
    ERROR_READ_FRAME_LIMIT,
    ERROR_READ_STREAM_INCOMPLETE,
    ERROR_SOURCE_NOT_FOUND,
    ERROR_TRANSPORT,
    HEAD_PREVIEW_CHARS,
    LOGIN_WORD2,
    LOGIN_WORD4,
    MESSAGE_INFO_FIELDS,
    METHOD_DELETE_MESSAGES,
    METHOD_GET_ALL_FOLDERS,
    METHOD_GET_MESSAGE_DATA,
    METHOD_GET_MESSAGE_INFOS,
    METHOD_UPDATE_MESSAGE_INFOS,
    PART_SCAN_LIMIT,
    PART_SOURCE_HEAD,
    READ_ACK_PEEK_TIMEOUT,
    READ_MARKER_FIRST,
    READ_MARKER_LAST,
    READ_MARKER_MIDDLE,
    READ_MAX_CHUNK_FRAMES,
    SESSION_REGISTRATION_MODE,
    SESSION_REGISTRATION_WORD2,
    WmsvrMailError,
    decode_wmsvr_payload,
    is_empty_read_ack,
    parse_business_reply,
    raise_for_reply,
)
from .operations import _WmsvrComposeOperationsMixin
from .tlv import (
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_KEY_VERSION,
    LOGIN_METHOD_LOGINONE,
    STARTUP_TAG_APPVER_INNER,
    STARTUP_TAG_CONFIG_ID,
    STARTUP_TAG_DEVICE_ID,
    STARTUP_TAG_METHOD,
    STARTUP_TAG_MODE,
    STARTUP_TAG_NONCE_HEX,
    STARTUP_TAG_OPAQUE_TOKEN,
    STARTUP_TAG_STARTUP_FLAG,
    STARTUP_TAG_UNIX_TIME,
    TAG_CLIENT_ID,
    TAG_MASTER_DI,
    TAG_MASTER_FP,
    TAG_MASTER_SDID,
    _resolve_wmsvr_hook,
    encode_tlv_envelope,
)


def build_session_registration_envelope(
    context: WmsvrLoginContext,
    *,
    token: str,
    client_id: str,
) -> bytes:
    """The `GET_SETTINGS` RPC envelope that registers the session (round 51)."""
    nonce = secrets.token_hex(8)
    records = [
        (STARTUP_TAG_STARTUP_FLAG, b"1"),
        (STARTUP_TAG_UNIX_TIME, str(int(time.time())).encode()),
        (STARTUP_TAG_NONCE_HEX, nonce.encode()),
        (STARTUP_TAG_METHOD, b"GET_SETTINGS"),
        (STARTUP_TAG_DEVICE_ID, context.device_id.encode()),
        (STARTUP_TAG_APPVER_INNER, APP_SUBVERSION.encode()),
        (STARTUP_TAG_CONFIG_ID, b"10"),
        (STARTUP_TAG_OPAQUE_TOKEN, token.encode()),
        (STARTUP_TAG_MODE, SESSION_REGISTRATION_MODE.encode()),
        (TAG_MASTER_FP, context.master_fp.encode()),
        (TAG_MASTER_SDID, context.master_sdid.encode()),
        (TAG_MASTER_DI, context.device_info_json.encode()),
        (TAG_CLIENT_ID, client_id.encode()),
    ]
    return encode_tlv_envelope(records)


def _extract_login_material(reply_json: Mapping[str, Any]) -> tuple[str, str, str]:
    """Pull `(token, route, host)` out of an accepted login reply."""
    route = ""
    cookies = reply_json.get("cookie") or []
    if isinstance(cookies, list):
        route = next(
            (item for item in cookies if isinstance(item, str) and item.startswith("Coremail:")),
            "",
        )
    parts = route.split("%")
    token = parts[1] if len(parts) >= 3 else ""
    host = str(reply_json.get("host") or "")
    return token, route, host


@dataclass
class WmsvrMailSession(_WmsvrComposeOperationsMixin):
    """One live private-protocol session: login material plus the open socket."""

    login_context: WmsvrLoginContext
    session: WmsvrSession
    session_key: bytes
    client_id: str
    sock: socket.socket
    peer: WmsvrPeerCandidate
    login_reply: dict[str, Any] = field(default_factory=dict)
    registration_reply: dict[str, Any] = field(default_factory=dict)
    seq: int = 0
    account_id: str = "0"
    _pending_read_ack: bool = False

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> WmsvrMailSession:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- transport ---------------------------------------------------------
    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _send_frame(self, frame: WmsvrD1Frame) -> None:
        sender = _resolve_wmsvr_hook("send_d1_frame", send_d1_frame, _ORIG_SEND_D1_FRAME)
        try:
            sender(self.sock, frame)
        except (OSError, WmsvrTransportError) as exc:
            raise WmsvrMailError(
                ERROR_TRANSPORT,
                f"the d1 connection failed while sending a request: {exc}",
                details={"peer": f"{self.peer.host}:{self.peer.port}"},
            ) from exc

    def _recv_frame(self, *, timeout: float | None = None) -> WmsvrD1Frame:
        receiver = _resolve_wmsvr_hook("recv_d1_frame", recv_d1_frame, _ORIG_RECV_D1_FRAME)
        try:
            return receiver(self.sock, timeout=timeout)
        except (OSError, WmsvrTransportError) as exc:
            raise WmsvrMailError(
                ERROR_TRANSPORT,
                f"the d1 connection failed while waiting for a reply: {exc}",
                details={"peer": f"{self.peer.host}:{self.peer.port}"},
            ) from exc

    def _send_recv(self, frame: WmsvrD1Frame, *, timeout: float | None = None) -> WmsvrD1Frame:
        self._send_frame(frame)
        return self._recv_frame(timeout=timeout)

    def _recv_payload_frame(self) -> tuple[bytes | None, dict[str, Any], dict[str, Any]]:
        """Read one already-requested reply and decode its slice1 payload."""
        reply_frame = self._recv_frame()
        reply = parse_business_reply(reply_frame, self.session_key)
        payload: bytes | None = None
        meta: dict[str, Any] = {}
        if reply_frame.slice1:
            plain = decrypt_wmsvr_d1_slice(reply_frame.slice1, self.session_key)
            payload, meta = decode_wmsvr_payload(plain)
        return payload, meta, reply

    def _parse_reply_skipping_ack(self, reply_frame: WmsvrD1Frame) -> dict[str, Any]:
        """Parse one reply, skipping a late empty read ack that the peek window missed."""
        reply = parse_business_reply(reply_frame, self.session_key)
        if (
            self._pending_read_ack
            and not reply_frame.slice1
            and is_empty_read_ack(None, reply)
        ):
            self._pending_read_ack = False
            reply_frame = self._recv_frame()
            reply = parse_business_reply(reply_frame, self.session_key)
        self._pending_read_ack = False
        return reply

    def request_lenient(self, method: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Issue one business request (`word2=0x0080`) and return the parsed reply."""
        if not self.session.token or not self.session.route:
            raise WmsvrMailError(
                ERROR_LOGIN_MATERIAL_MISSING,
                "the session has no token/route, so no business request can be built",
                details={"method": method},
            )
        context = self._business_context()
        frame = build_wmsvr_d1_request_frame(
            context,
            self.session,
            method,
            body=None if body is None else dict(body),
            seq=self._next_seq(),
        )
        reply_frame = self._send_recv(frame)
        return self._parse_reply_skipping_ack(reply_frame)

    def request(self, method: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Issue one business request (`word2=0x0080`) and raise unless the code is `S_OK`."""
        reply = self.request_lenient(method, body)
        raise_for_reply(reply, method=method)
        return reply

    def _request_with_payload(
        self,
        method: str,
        body: Mapping[str, Any],
    ) -> tuple[bytes | None, dict[str, Any], dict[str, Any]]:
        """Issue one request and return `(payload_bytes, payload_meta, parsed_reply)`."""
        if not self.session.token or not self.session.route:
            raise WmsvrMailError(
                ERROR_LOGIN_MATERIAL_MISSING,
                "the session has no token/route, so no business request can be built",
                details={"method": method},
            )
        context = self._business_context()
        frame = build_wmsvr_d1_request_frame(
            context,
            self.session,
            method,
            body=dict(body),
            seq=self._next_seq(),
        )
        self._send_frame(frame)
        return self._recv_payload_frame()

    def _drain_read_ack(self) -> dict[str, Any] | None:
        """Consume the empty ack the server sends after a rejected read, if one is pending."""
        if self.sock is None:
            return None
        try:
            readable, _, _ = select.select([self.sock], [], [], READ_ACK_PEEK_TIMEOUT)
        except (OSError, ValueError) as exc:
            raise WmsvrMailError(
                ERROR_TRANSPORT,
                f"the d1 connection failed while checking for a read ack: {exc}",
                details={"peer": f"{self.peer.host}:{self.peer.port}"},
            ) from exc
        if not readable:
            return None
        payload, _meta, reply = self._recv_payload_frame()
        return {
            "code": reply.get("code"),
            "extra16": reply.get("extra16"),
            "len0": reply.get("len0"),
            "len1": reply.get("len1"),
            "payload_len": len(payload) if payload else 0,
            "read_marker": reply.get("read_marker"),
            "empty_ack": is_empty_read_ack(payload, reply),
        }

    def _business_context(self) -> WmsvrD1RequestContext:
        return WmsvrD1RequestContext(
            key_version=DEFAULT_D1_KEY_VERSION,
            key_digest16=DEFAULT_D1_FALLBACK_KEY_DIGEST16,
            master_fp=self.login_context.master_fp,
            master_sdid=self.login_context.master_sdid,
            device_info_json=self.login_context.device_info_json,
            session_key=self.session_key,
            word2=BUSINESS_WORD2,
            word4=LOGIN_WORD4,
        )

    # -- mailbox read & mutation operations --------------------------------
    def get_message_infos(
        self,
        ids: Iterable[str],
        *,
        fields: Iterable[str] = MESSAGE_INFO_FIELDS,
    ) -> list[dict[str, Any]]:
        """Read `fid/flags/label0/...` for the given remote ids."""
        resolved = [str(item) for item in ids]
        if not resolved:
            raise ValueError("`wzp:getMessageInfos` needs at least one message id.")
        reply = self.request(
            METHOD_GET_MESSAGE_INFOS,
            {"filter": list(fields), "ids": resolved},
        )
        records = reply.get("records")
        return list(records) if isinstance(records, list) else []

    def get_message_flags(self, ids: Iterable[str]) -> list[dict[str, Any]]:
        """Return just the `flags` maps of the given remote ids, in request order."""
        return [dict(record.get("flags") or {}) for record in self.get_message_infos(ids)]

    def get_message_folders(self, ids: Iterable[str]) -> list[int | None]:
        """Return the `fid` (folder id) of each remote id, in request order."""
        folders: list[int | None] = []
        for record in self.get_message_infos(ids):
            fid = record.get("fid")
            folders.append(int(fid) if isinstance(fid, (int, float)) else None)
        return folders

    def list_folders(self) -> list[dict[str, Any]]:
        """Read the server folder list (`mbox:getAllFolders`, empty body)."""
        reply = self.request(METHOD_GET_ALL_FOLDERS, {})
        records = reply.get("records")
        return list(records) if isinstance(records, list) else []

    def read_message_slice(
        self,
        message_id: str,
        *,
        part: int,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Read one slice of a message (`wzpm:getMessageData`); a miss is data, not an error."""
        body = {
            "mid": str(message_id),
            "part": int(part),
            "offset": int(offset),
            "extra": "",
        }
        payload, meta, reply = self._request_with_payload(METHOD_GET_MESSAGE_DATA, body)
        skipped_acks = 0
        while self._pending_read_ack and is_empty_read_ack(payload, reply):
            self._pending_read_ack = False
            skipped_acks += 1
            payload, meta, reply = self._recv_payload_frame()
        self._pending_read_ack = False
        code = reply.get("code")
        markers: list[int | None] = [reply.get("read_marker")]
        payloads: list[bytes] = [payload] if payload else []
        frame_count = 1
        chunked_stream = markers[0] in (READ_MARKER_FIRST, READ_MARKER_MIDDLE)
        if chunked_stream:
            while True:
                if frame_count >= READ_MAX_CHUNK_FRAMES:
                    raise WmsvrMailError(
                        ERROR_READ_FRAME_LIMIT,
                        (
                            f"the read stream exceeded {READ_MAX_CHUNK_FRAMES} frames "
                            "without its final marker"
                        ),
                        details={
                            "method": METHOD_GET_MESSAGE_DATA,
                            "mid": str(message_id),
                            "part": int(part),
                            "offset": int(offset),
                            "frames": frame_count,
                            "markers": markers,
                        },
                    )
                chunk, _chunk_meta, chunk_reply = self._recv_payload_frame()
                frame_count += 1
                chunk_marker = chunk_reply.get("read_marker")
                if chunk_reply.get("code") not in (None, "S_OK"):
                    markers.append(chunk_marker)
                    raise WmsvrMailError(
                        ERROR_READ_STREAM_INCOMPLETE,
                        (
                            f"the read stream stopped at frame {frame_count} with "
                            f"{chunk_reply.get('code')!r}"
                        ),
                        details={
                            "method": METHOD_GET_MESSAGE_DATA,
                            "mid": str(message_id),
                            "part": int(part),
                            "offset": int(offset),
                            "frames": frame_count,
                            "last_code": chunk_reply.get("code"),
                            "markers": markers,
                        },
                    )
                markers.append(chunk_marker)
                if chunk:
                    payloads.append(chunk)
                if chunk_marker == READ_MARKER_LAST:
                    break
                if chunk_marker is None:
                    raise WmsvrMailError(
                        ERROR_READ_STREAM_INCOMPLETE,
                        (
                            f"the read stream stopped at frame {frame_count} without "
                            "its final marker"
                        ),
                        details={
                            "method": METHOD_GET_MESSAGE_DATA,
                            "mid": str(message_id),
                            "part": int(part),
                            "offset": int(offset),
                            "frames": frame_count,
                            "markers": markers,
                        },
                    )
        full_payload = b"".join(payloads)
        served = code in (None, "S_OK") and bool(full_payload)
        verdict: Any = None
        if payload is not None and code not in (None, "S_OK"):
            try:
                verdict = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                verdict = None
        ack = None if served else self._drain_read_ack()
        self._pending_read_ack = (not served) and ack is None
        return {
            "method": METHOD_GET_MESSAGE_DATA,
            "mid": str(message_id),
            "part": int(part),
            "offset": int(offset),
            "served": served,
            "empty": payload is None,
            "code": code,
            "verdict": verdict,
            "extra16": reply.get("extra16"),
            "len1": reply.get("len1"),
            "payload_meta": meta,
            "payload": full_payload,
            "length": len(full_payload),
            "sha256": hashlib.sha256(full_payload).hexdigest() if served else None,
            "records": reply.get("records"),
            "frames": frame_count,
            "chunked": frame_count > 1,
            "markers": markers,
            "chunk_lengths": [len(chunk) for chunk in payloads],
            "skipped_acks": skipped_acks,
            "ack_drained": ack,
            "extra_frames_drained": 1 if ack is not None else 0,
        }

    def fetch_message_source(
        self,
        message_id: str,
        *,
        max_part: int = PART_SCAN_LIMIT,
    ) -> dict[str, Any]:
        """Return a message's raw RFC822 source, identified by its content, not by a slot."""
        candidates: list[dict[str, Any]] = []
        payloads: dict[int, bytes] = {}
        misses: list[dict[str, Any]] = []
        for part in range(max_part + 1):
            read = self.read_message_slice(message_id, part=part, offset=0)
            if read["served"]:
                payloads[part] = read["payload"]
                candidates.append(
                    {
                        "part": part,
                        "length": read["length"],
                        "sha256": read["sha256"],
                        "head": read["payload"][:HEAD_PREVIEW_CHARS].decode("ascii", "replace"),
                        "is_source": read["payload"].startswith(PART_SOURCE_HEAD),
                    }
                )
            else:
                misses.append(
                    {
                        "part": part,
                        "code": read["code"],
                        "empty": read["empty"],
                    }
                )
        sources = [item for item in candidates if item["is_source"]]
        if not sources:
            raise WmsvrMailError(
                ERROR_SOURCE_NOT_FOUND,
                (
                    f"none of the slots 0..{max_part} of that message carried a source slice "
                    f"({len(candidates)} slice(s) served, none starting with "
                    f"{PART_SOURCE_HEAD.decode('ascii')!r})"
                ),
                details={
                    "method": METHOD_GET_MESSAGE_DATA,
                    "mid": str(message_id),
                    "slots_tried": sorted(
                        [item["part"] for item in candidates]
                        + [item["part"] for item in misses]
                    ),
                    "served_slots": [item["part"] for item in candidates],
                    "misses": misses,
                },
            )
        chosen = sources[0]
        return {
            "method": METHOD_GET_MESSAGE_DATA,
            "mid": str(message_id),
            "offset": 0,
            "part_slot": chosen["part"],
            "source": payloads[chosen["part"]],
            "length": chosen["length"],
            "sha256": chosen["sha256"],
            "candidates": candidates,
            "source_slots": [item["part"] for item in sources],
            "misses": misses,
        }

    def set_message_read(self, ids: Iterable[str], *, read: bool) -> dict[str, Any]:
        """Set the read flag for the given remote ids; returns the `S_OK` reply."""
        body = build_update_message_infos_body(ids, read=read)
        return self.request(METHOD_UPDATE_MESSAGE_INFOS, body)

    def set_message_folder(self, ids: Iterable[str], *, fid: int) -> dict[str, Any]:
        """Move the given remote ids to folder `fid` (round 58: `attrs.fid` is the move)."""
        resolved = [str(item) for item in ids]
        if not resolved:
            raise ValueError("a move needs at least one message id.")
        return self.request(
            METHOD_UPDATE_MESSAGE_INFOS,
            {"attrs": {"fid": int(fid)}, "ids": resolved},
        )

    def set_message_folder_verified(self, ids: Iterable[str], *, fid: int) -> dict[str, Any]:
        """Move messages and verify the new folder within this same session."""
        resolved = [str(item) for item in ids]
        folders_before = self.get_message_folders(resolved)
        write_reply = self.set_message_folder(resolved, fid=fid)
        folders_after = self.get_message_folders(resolved)
        target = int(fid)
        moved = bool(folders_after) and all(item == target for item in folders_after)
        result = {
            "transport": "wmsvr-private",
            "method": METHOD_UPDATE_MESSAGE_INFOS,
            "code": write_reply.get("code"),
            "ids": resolved,
            "target_fid": target,
            "remote_folders_before": folders_before,
            "remote_folders_after": folders_after,
            "state_change_verified": moved,
        }
        if not moved:
            raise WmsvrMailError(
                ERROR_NOT_VERIFIED,
                "the server accepted the move but the read-back still shows another folder",
                details=result,
            )
        return result

    def set_message_read_verified(
        self,
        ids: Iterable[str],
        *,
        read: bool,
        expected_before: Mapping[str, bool] | None = None,
    ) -> dict[str, Any]:
        """Set the read flag and verify the change within this same session."""
        resolved = [str(item) for item in ids]
        flags_before = self.get_message_flags(resolved)
        write_reply = self.set_message_read(resolved, read=read)
        flags_after = self.get_message_flags(resolved)
        changes = [
            bool((before or {}).get("read", False)) != bool((after or {}).get("read", False))
            for before, after in zip(flags_before, flags_after, strict=False)
        ]
        verified = bool(changes) and all(changes)
        if expected_before is not None and len(resolved) == 1:
            was_read = bool((flags_before[0] if flags_before else {}).get("read", False))
            expected = bool(expected_before.get(resolved[0], False))
            if was_read != expected:
                verified = False
        result = {
            "transport": "wmsvr-private",
            "method": METHOD_UPDATE_MESSAGE_INFOS,
            "code": write_reply.get("code"),
            "ids": resolved,
            "remote_flags_before": flags_before,
            "remote_flags_after": flags_after,
            "state_change_verified": verified,
        }
        if not verified:
            raise WmsvrMailError(
                ERROR_NOT_VERIFIED,
                "the server accepted the write but the read-back shows no state change",
                details=result,
            )
        return result

    # -- delete ------------------------------------------------------------
    def _records_by_mid(
        self,
        ids: list[str],
        *,
        fields: Iterable[str] = MESSAGE_INFO_FIELDS,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        """Read `wzp:getMessageInfos` and key the (possibly partial) records by `mid`."""
        reply = self.request_lenient(
            METHOD_GET_MESSAGE_INFOS,
            {"filter": list(fields), "ids": list(ids)},
        )
        records = reply.get("records")
        by_mid: dict[str, dict[str, Any]] = {}
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict) and record.get("mid"):
                    by_mid[str(record["mid"])] = record
        return by_mid, reply

    def delete_messages(
        self,
        ids: Iterable[str],
        *,
        delete_type: str = DELETE_TYPE_BATCH,
    ) -> dict[str, Any]:
        """Send `mbox:deleteMessages`; returns the `S_OK` reply."""
        resolved = [str(item) for item in ids]
        if not resolved:
            raise ValueError("a delete needs at least one message id.")
        if delete_type not in (DELETE_TYPE_BATCH, DELETE_TYPE_ACCOUNT):
            raise ValueError(
                f"delete_type must be {DELETE_TYPE_BATCH!r} or {DELETE_TYPE_ACCOUNT!r}."
            )
        return self.request(
            METHOD_DELETE_MESSAGES,
            {"deleteType": delete_type, "ids": resolved},
        )

    def delete_messages_verified(
        self,
        ids: Iterable[str],
        *,
        delete_type: str = DELETE_TYPE_BATCH,
    ) -> dict[str, Any]:
        """Delete messages and verify they left the mailbox within this same session."""
        resolved = [str(item) for item in ids]
        if not resolved:
            raise ValueError("a delete needs at least one message id.")
        before, _ = self._records_by_mid(resolved)
        write_reply = self.delete_messages(resolved, delete_type=delete_type)
        after, after_reply = self._records_by_mid(resolved)
        folders_before = [
            (before[item].get("fid") if item in before else None) for item in resolved
        ]
        folders_after = [
            (after[item].get("fid") if item in after else None) for item in resolved
        ]
        gone = [item in before and item not in after for item in resolved]
        relocated = [
            item in before
            and item in after
            and after[item].get("fid") != before[item].get("fid")
            for item in resolved
        ]
        already_absent = [item not in before and item not in after for item in resolved]
        verified = all(
            g or r or a
            for g, r, a in zip(gone, relocated, already_absent, strict=False)
        )
        result = {
            "transport": "wmsvr-private",
            "method": METHOD_DELETE_MESSAGES,
            "code": write_reply.get("code"),
            "delete_type": delete_type,
            "ids": resolved,
            "remote_folders_before": folders_before,
            "remote_folders_after": folders_after,
            "gone": gone,
            "already_absent": already_absent,
            "read_back_code": after_reply.get("code"),
            "state_change_verified": verified,
        }
        if not verified:
            raise WmsvrMailError(
                ERROR_NOT_VERIFIED,
                "the server accepted the delete but the read-back still resolves the message",
                details=result,
            )
        return result


def open_wmsvr_mail_session(
    context: WmsvrLoginContext,
    *,
    master_session_token: str,
    client_id: str = "",
    account_id: str = "0",
    peer_index: int = 0,
    timeout: float = 30.0,
    password: str | None = None,
) -> WmsvrMailSession:
    """Run the recovered handshake and return a ready session."""
    if not context.peer_candidates:
        raise WmsvrMailError(
            ERROR_BOOTSTRAP_MISSING,
            "no d1 peer candidates are available for this account",
            details={"account": context.account},
        )
    if peer_index < 0 or peer_index >= len(context.peer_candidates):
        raise WmsvrMailError(
            ERROR_BOOTSTRAP_MISSING,
            f"peer index {peer_index} is out of range ({len(context.peer_candidates)} peers)",
            details={"account": context.account, "peer_count": len(context.peer_candidates)},
        )
    if password is not None:
        context = _replace_password(context, password)
    if not context.password:
        raise WmsvrMailError(
            ERROR_LOGIN_CREDENTIAL_MISSING,
            "this Wmsvr account has no stored password, and a password is what loginone sends",
            details={"account": context.account, "login_method": LOGIN_METHOD_LOGINONE},
        )
    if not master_session_token:
        raise WmsvrMailError(
            ERROR_BOOTSTRAP_MISSING,
            "the init/session token is required to register the d1 session; refresh it first",
            details={"account": context.account},
        )

    peer = context.peer_candidates[peer_index]
    resolved_client_id = client_id or build_default_wmsvr_login_client_id(
        context, method=LOGIN_METHOD_LOGINONE
    )
    session_key = generate_wmsvr_d1_session_key()
    kex_builder = _resolve_wmsvr_hook(
        "build_wmsvr_key_exchange_frame",
        build_wmsvr_key_exchange_frame,
        _ORIG_BUILD_KEY_EXCHANGE,
    )
    key_exchange_frame, session_key = kex_builder(
        key_version=DEFAULT_D1_KEY_VERSION,
        key_digest16=DEFAULT_D1_FALLBACK_KEY_DIGEST16,
        session_key=session_key,
    )
    opener = _resolve_wmsvr_hook("open_d1_socket", open_d1_socket, _ORIG_OPEN_D1_SOCKET)
    exchanger = _resolve_wmsvr_hook(
        "exchange_get_settings",
        exchange_get_settings,
        _ORIG_EXCHANGE_GET_SETTINGS,
    )
    try:
        sock = opener(peer, timeout=timeout)
    except OSError as exc:
        raise WmsvrMailError(
            ERROR_TRANSPORT,
            f"could not open the d1 connection to {peer.host}:{peer.port}: {exc}",
            details={"peer": f"{peer.host}:{peer.port}"},
        ) from exc

    session = WmsvrMailSession(
        login_context=context,
        session=WmsvrSession(),
        session_key=session_key,
        client_id=resolved_client_id,
        sock=sock,
        peer=peer,
        account_id=account_id,
    )
    seq = session._next_seq
    try:
        ack = exchanger(sock, request=key_exchange_frame, timeout=timeout)
        session.login_reply["key_exchange_business_code"] = ack.business_code

        registration_frame = build_wmsvr_d1_encrypted_frame(
            build_session_registration_envelope(
                context, token=master_session_token, client_id=resolved_client_id
            ),
            session_key=session_key,
            seq=seq(),
            word2=SESSION_REGISTRATION_WORD2,
        )
        registration_reply = parse_business_reply(
            session._send_recv(registration_frame, timeout=timeout), session_key
        )
        session.registration_reply = {
            "code": registration_reply.get("code"),
            "code_int": registration_reply.get("code_int"),
            "extra16": registration_reply.get("extra16"),
        }

        login_body = build_loginone_body(context)
        login_frame, _, _ = build_wmsvr_login_frame(
            context,
            body=login_body,
            word2=LOGIN_WORD2,
            word4=LOGIN_WORD4,
            seq=seq(),
            session_key=session_key,
        )
        login_reply = parse_business_reply(
            session._send_recv(login_frame, timeout=timeout), session_key
        )
    except WmsvrMailError:
        session.close()
        raise
    except (WmsvrTransportError, OSError) as exc:
        session.close()
        raise WmsvrMailError(
            ERROR_TRANSPORT,
            f"the login handshake failed: {exc}",
            details={"peer": f"{peer.host}:{peer.port}"},
        ) from exc

    payload_json = login_reply.get("records")
    if login_reply.get("code") is not None or not isinstance(payload_json, dict):
        session.close()
        raise WmsvrMailError(
            ERROR_LOGIN_REJECTED,
            f"the login service answered with a code instead of a result: {login_reply.get('code')}",
            details={"reply_code": login_reply.get("code"), "extra16": login_reply.get("extra16")},
        )
    session.login_reply.update(
        {
            "result": payload_json.get("result"),
            "extra16": login_reply.get("extra16"),
            "len1": login_reply.get("len1"),
            "auth_token_present": bool(payload_json.get("authToken")),
            "cookie_count": len(payload_json.get("cookie") or []),
        }
    )
    if payload_json.get("result") is not True:
        session.close()
        raise WmsvrMailError(
            ERROR_LOGIN_REJECTED,
            "the login service refused the stored credential (result=false)",
            details={"extra16": login_reply.get("extra16")},
        )

    token, route, host = _extract_login_material(payload_json)
    if not token or not route:
        session.close()
        raise WmsvrMailError(
            ERROR_LOGIN_MATERIAL_MISSING,
            "the accepted login reply carried no Coremail cookie, so no business session can be built",
            details={"extra16": login_reply.get("extra16")},
        )
    session.session = WmsvrSession(
        token=token,
        route=route,
        host=host,
        port=BUSINESS_PORT,
        account_desc=f"{ACCOUNT_DESC_PREFIX}{context.account}",
        ticket=context.master_fp,
        trace_id=context.master_sdid,
        device_info=context.device_info_json,
        client_id=resolved_client_id,
    )
    return session


def _replace_password(context: WmsvrLoginContext, password: str) -> WmsvrLoginContext:
    return replace(context, password=password, peer_candidates=list(context.peer_candidates))


_ORIG_SEND_D1_FRAME = send_d1_frame
_ORIG_RECV_D1_FRAME = recv_d1_frame
_ORIG_OPEN_D1_SOCKET = open_d1_socket
_ORIG_EXCHANGE_GET_SETTINGS = exchange_get_settings
_ORIG_BUILD_KEY_EXCHANGE = build_wmsvr_key_exchange_frame
