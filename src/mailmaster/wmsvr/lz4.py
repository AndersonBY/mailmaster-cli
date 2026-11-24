"""Pure-Python LZ4Block decoder, business reply parsers, error model, and protocol constants."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .d1_wire import WmsvrD1Frame, decrypt_wmsvr_d1_slice
from .tlv import TAG_METHOD, decode_tlv

# Wire constants pinned by rounds 54-56.
LOGIN_WORD2 = 0x0004
LOGIN_WORD4 = 0x0003
SESSION_REGISTRATION_WORD2 = 0x0003
BUSINESS_WORD2 = 0x0080
BUSINESS_PORT = 0x003C
ACCOUNT_DESC_PREFIX = "10|"
APP_SUBVERSION = "50070021006"
SESSION_REGISTRATION_MODE = "5"

CONTAINER_MAGIC = b"LZ4Block"
CONTAINER_HEADER_LEN = 13

MESSAGE_INFO_FIELDS = ("fid", "flags", "label0", "tag", "composeExtra")
METHOD_GET_MESSAGE_INFOS = "wzp:getMessageInfos"
METHOD_UPDATE_MESSAGE_INFOS = "mbox:updateMessageInfos"
METHOD_GET_ALL_FOLDERS = "mbox:getAllFolders"
METHOD_DELETE_MESSAGES = "mbox:deleteMessages"
METHOD_LIST_MESSAGES = "wzp:listMessages"
METHOD_GET_MESSAGE_DATA = "wzpm:getMessageData"
METHOD_COMPOSE = "mbox:compose"
METHOD_RESTORE_DRAFT = "mbox:restoreDraft"
METHOD_UPLOAD_PREPARE = "upload:prepare"
METHOD_UPLOAD_ATTACH = "wzp:uploadAttach"
DEFAULT_ATTACHMENT_CONTENT_TYPE = "application/octet-stream"

PART_SOURCE_HEAD = b"Received:"
HEAD_PREVIEW_CHARS = 16
PART_SCAN_LIMIT = 8
READ_FRAME_MARKER_TAG = 0x000C
READ_MARKER_MIDDLE = 0
READ_MARKER_FIRST = 1
READ_MARKER_LAST = 2
READ_MAX_CHUNK_FRAMES = 8192
READ_ACK_PEEK_TIMEOUT = 0.5
READ_ACK_EXTRA16 = 0x00C8

DELETE_TYPE_BATCH = "batch"
DELETE_TYPE_ACCOUNT = "account"

COMPOSE_ACTION_CONTINUE = "continue"
COMPOSE_ACTION_DELIVER = "deliver"
COMPOSE_ACTION_SAVE = "save"
REPLY_CODE_DRAFT_RECREATED = "FS_UD0108"
REPLY_CODE_ID_NOT_FOUND = "FA_ID_NOT_FOUND"
COMPOSE_MAILER_EXT = "MailMasterPC/5.7.2.1006 (mailmaster-cli)"
SENT_FOLDER_FID = 3
SENT_INFO_FIELDS = ("id", "fid", "subject", "sentdate")
SENT_READBACK_FIELDS = SENT_INFO_FIELDS + ("size",)
DRAFT_FOLDER_FID = 2
DRAFT_INFO_FIELDS = ("id", "fid", "subject", "size")

# Structured error codes.
ERROR_LOGIN_CREDENTIAL_MISSING = "wmsvr_login_credential_missing"
ERROR_LOGIN_REJECTED = "wmsvr_login_rejected"
ERROR_LOGIN_MATERIAL_MISSING = "wmsvr_login_material_missing"
ERROR_SESSION_EXPIRED = "wmsvr_session_expired"
ERROR_NEEDS_AUTH2 = "wmsvr_needs_auth2"
ERROR_MAIL_NOT_FOUND = "wmsvr_mail_not_found"
ERROR_FOLDER_NOT_FOUND = "wmsvr_folder_not_found"
ERROR_COMPOSE_ID_UNKNOWN = "wmsvr_compose_id_unknown"
ERROR_METHOD_REJECTED = "wmsvr_method_rejected"
ERROR_TRANSPORT = "wmsvr_transport_error"
ERROR_BOOTSTRAP_MISSING = "wmsvr_bootstrap_missing"
ERROR_NOT_VERIFIED = "wmsvr_state_change_not_verified"
ERROR_UPLOAD_REJECTED = "wmsvr_upload_rejected"
ERROR_DRAFT_NOT_FOUND = "wmsvr_draft_not_found"
ERROR_PART_NOT_FOUND = "wmsvr_part_not_found"
ERROR_SOURCE_NOT_FOUND = "wmsvr_source_not_found"
ERROR_READ_STREAM_INCOMPLETE = "wmsvr_read_stream_incomplete"
ERROR_READ_FRAME_LIMIT = "wmsvr_read_frame_limit"

DEFAULT_UPLOAD_CHUNK_SIZE = 64 * 1024

_REPLY_CODE_TO_ERROR = {
    "FA_INVALID_SESSION": ERROR_SESSION_EXPIRED,
    "FA_NEED_AUTH2": ERROR_NEEDS_AUTH2,
    "FA_MAIL_NOT_FOUND": ERROR_MAIL_NOT_FOUND,
    "FA_FOLDER_NOT_FOUND": ERROR_FOLDER_NOT_FOUND,
    "FA_PART_NOT_FOUND": ERROR_PART_NOT_FOUND,
}

_REPLY_CODE_RE = re.compile(rb'\{"code":"([A-Za-z_0-9.]+)"\}')
_REPLY_NUMERIC_CODE_RE = re.compile(rb'\{"code":(\d+)\}')


class WmsvrMailError(Exception):
    """One Wmsvr mailbox failure, carrying a stable code for structured output.

    `details` never contains credentials, session material or message bodies: the
    product reports codes, not secrets.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details: dict[str, Any] = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


# ---------------------------------------------------------------------------
# LZ4Block container decoder
# ---------------------------------------------------------------------------


def decode_lz4_block(src: bytes, out_size: int) -> bytes | None:
    """Decode one standard LZ4 block; `None` means the bytes are not a valid block.

    Pure Python on purpose: the reply payload is the only thing the product needs
    from LZ4, and the system `lz4` package is not a dependency of this project.
    """
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        literal_len = token >> 4
        if literal_len == 15:
            while True:
                if i >= n:
                    return None
                extra = src[i]
                i += 1
                literal_len += extra
                if extra != 255:
                    break
        if i + literal_len > n:
            return None
        out += src[i : i + literal_len]
        i += literal_len
        if i == n:
            break
        if i + 2 > n:
            return None
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(out):
            return None
        match_len = token & 0x0F
        if match_len == 15:
            while True:
                if i >= n:
                    return None
                extra = src[i]
                i += 1
                match_len += extra
                if extra != 255:
                    break
        match_len += 4
        if len(out) + match_len > out_size:
            return None
        start = len(out) - offset
        for k in range(match_len):
            out.append(out[start + k])
    if len(out) != out_size:
        return None
    return bytes(out)


def strip_slice_padding(data: bytes) -> bytes:
    """Remove PKCS#7 padding from a decrypted slice (the client's own rule)."""
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def decode_wmsvr_payload(plain: bytes) -> tuple[bytes | None, dict[str, Any]]:
    """Decode a decrypted slice into payload bytes plus a small shape report.

    Handles both shapes the server uses: an `LZ4Block` container and plain JSON
    with PKCS#7 padding (login replies). Returns `(None, meta)` when neither fits.
    """
    if plain[: len(CONTAINER_MAGIC)] == CONTAINER_MAGIC:
        body = plain[len(CONTAINER_MAGIC) :]
        second = body.find(CONTAINER_MAGIC)
        head = body[:second] if second > 0 else body
        if len(head) < CONTAINER_HEADER_LEN:
            return None, {"container": True, "error": "header_too_short"}
        compressed = int.from_bytes(head[1:5], "little")
        uncompressed = int.from_bytes(head[5:9], "little")
        decoded = decode_lz4_block(head[CONTAINER_HEADER_LEN:], uncompressed or compressed)
        meta: dict[str, Any] = {
            "container": True,
            "compressed_len": compressed,
            "uncompressed_len": uncompressed,
            "trailer_len": len(body) - len(head),
        }
        if decoded is None:
            meta["error"] = "lz4_block_invalid"
            return None, meta
        return decoded, meta
    stripped = strip_slice_padding(plain)
    try:
        stripped.decode("utf-8")
    except UnicodeDecodeError:
        return None, {"container": False, "error": "not_utf8"}
    return stripped, {"container": False, "plain": True}


# ---------------------------------------------------------------------------
# Business reply parsers
# ---------------------------------------------------------------------------


def parse_reply_code(slice0_plain: bytes) -> str | None:
    """Extract the `{"code":"..."}` verdict from a decrypted reply slice0."""
    match = _REPLY_CODE_RE.search(slice0_plain)
    return match.group(1).decode("ascii") if match else None


def parse_reply_numeric_code(slice0_plain: bytes) -> int | None:
    """Extract the `{"code":<int>}` verdict the registration/startup path answers with."""
    match = _REPLY_NUMERIC_CODE_RE.search(slice0_plain)
    return int(match.group(1)) if match else None


def parse_reply_method(slice0_plain: bytes) -> str | None:
    """Extract the echoed `0x0100` method name from a decrypted reply slice0."""
    data = strip_slice_padding(slice0_plain)
    offset = 0
    while offset < len(data):
        try:
            tag, value, offset = decode_tlv(data, offset)
        except (ValueError, IndexError):
            return None
        if tag == TAG_METHOD:
            return value.decode("utf-8", "replace")
    return None


def parse_read_frame_marker(slice0_plain: bytes) -> int | None:
    """Return the read family's chunk marker (`0x000C`), or `None` when the tag is absent."""
    if not slice0_plain:
        return None
    data = strip_slice_padding(slice0_plain)
    offset = 0
    while offset < len(data):
        try:
            tag, value, offset = decode_tlv(data, offset)
        except (ValueError, IndexError):
            return None
        if tag == READ_FRAME_MARKER_TAG:
            if len(value) != 2:
                return None
            return int.from_bytes(value, "big")
    return None


def is_empty_read_ack(payload: bytes | None, reply: Mapping[str, Any]) -> bool:
    """True for the empty ack the server sends after a rejected read (r113/r117)."""
    return (
        payload is None
        and reply.get("code") is None
        and reply.get("extra16") == READ_ACK_EXTRA16
        and reply.get("len1") is None
    )


def parse_business_reply(frame: WmsvrD1Frame, session_key: bytes) -> dict[str, Any]:
    """Decrypt and describe one business reply frame."""
    slice0_plain = decrypt_wmsvr_d1_slice(frame.slice0, session_key) if frame.slice0 else b""
    slice1_plain = decrypt_wmsvr_d1_slice(frame.slice1, session_key) if frame.slice1 else b""
    payload, meta = decode_wmsvr_payload(slice1_plain) if slice1_plain else (None, {})
    records: Any = None
    if payload:
        try:
            records = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            records = None
    return {
        "word0": frame.header.word0,
        "word2": frame.header.word2,
        "extra16": frame.header.extra16,
        "len0": frame.header.len0,
        "len1": frame.header.len1,
        "code": parse_reply_code(slice0_plain),
        "code_int": parse_reply_numeric_code(slice0_plain),
        "method": parse_reply_method(slice0_plain),
        "read_marker": parse_read_frame_marker(slice0_plain),
        "records": records,
        "payload_meta": meta,
        "payload_len": len(payload) if payload else 0,
    }


def raise_for_reply(reply: Mapping[str, Any], *, method: str) -> None:
    """Turn a non-`S_OK` business verdict into a structured error."""
    code = reply.get("code")
    if code == "S_OK":
        return
    error_code = _REPLY_CODE_TO_ERROR.get(str(code), ERROR_METHOD_REJECTED)
    message = f"{method} was rejected by the server: {code or 'no code in reply'}"
    raise WmsvrMailError(
        error_code,
        message,
        details={
            "method": method,
            "reply_code": code,
            "reply_word0": reply.get("word0"),
            "reply_extra16": reply.get("extra16"),
        },
    )
