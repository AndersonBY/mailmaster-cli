"""TLV/LEB128 wire codec and Wmsvr protocol tag/method constants."""

from __future__ import annotations

import re as _re
import struct
import sys
from collections.abc import Iterable, Mapping
from typing import Any, TypeVar, cast

_T = TypeVar("_T")


def _resolve_wmsvr_hook(name: str, local: _T, orig: _T) -> _T:
    """Resolve a helper that tests may monkeypatch on `mailmaster.wmsvr`."""
    if local is not orig:
        return local
    pkg = sys.modules.get("mailmaster.wmsvr")
    if pkg is not None:
        candidate = getattr(pkg, name, orig)
        if candidate is not orig:
            return cast(_T, candidate)
    return orig


# ---------------------------------------------------------------------------
# TLV codec
# ---------------------------------------------------------------------------


def encode_tag(tag: int) -> bytes:
    """Encode a 16-bit tag in big-endian (network byte order)."""
    return struct.pack(">H", tag & 0xFFFF)


def decode_tag(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a 2-byte big-endian tag. Returns (tag, new_offset)."""
    tag = struct.unpack_from(">H", data, offset)[0]
    return tag, offset + 2


def encode_leb128(value: int) -> bytes:
    """Encode an unsigned integer as LEB128 (variable-length, 7-bit chunks, MSB continuation)."""
    if value < 0:
        raise ValueError("LEB128 encode requires non-negative value")
    parts: list[int] = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value > 0:
            byte |= 0x80
        parts.append(byte)
        if value == 0:
            break
    return bytes(parts)


def decode_leb128(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a LEB128 unsigned integer. Returns (value, new_offset)."""
    value = 0
    shift = 0
    while offset < len(data) and shift < 35:
        byte = data[offset]
        value |= (byte & 0x7F) << shift
        offset += 1
        if (byte & 0x80) == 0:
            return value, offset
        shift += 7
    raise ValueError("Truncated or invalid LEB128")


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a single TLV record: [2B tag BE] [LEB128 len] [value]."""
    return encode_tag(tag) + encode_leb128(len(value)) + value


def decode_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Decode one TLV record. Returns (tag, value_bytes, new_offset)."""
    tag, offset = decode_tag(data, offset)
    length, offset = decode_leb128(data, offset)
    value = data[offset : offset + length]
    if len(value) < length:
        raise ValueError(f"Truncated TLV value for tag 0x{tag:04x}: expected {length}, got {len(value)}")
    return tag, value, offset + length


def encode_tlv_envelope(records: list[tuple[int, bytes]]) -> bytes:
    """Encode a list of (tag, value) pairs into a TLV envelope."""
    parts: list[bytes] = []
    for tag, value in records:
        parts.append(encode_tlv(tag, value))
    return b"".join(parts)


def decode_tlv_envelope(data: bytes) -> list[tuple[int, bytes]]:
    """Decode all TLV records from a binary envelope."""
    records: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = decode_tlv(data, offset)
        records.append((tag, value))
    return records


# ---------------------------------------------------------------------------
# Tag and protocol constants (from live capture + disassembly)
# ---------------------------------------------------------------------------

TAG_VERSION = 0x0107       # 4 bytes: protocol version (always 0x00000001)
TAG_METHOD = 0x0100        # UTF-8: method name, e.g. "mbox:updateMessageInfos"
TAG_TOKEN = 0x0101         # 32 bytes: session auth token
TAG_ROUTE = 0x0102         # UTF-8: "Coremail:<seed>%<token>%wzp-session-..."
TAG_HOST = 0x0200          # UTF-8: backend host IP
TAG_PORT = 0x0201          # 2 bytes BE: backend port
TAG_ACCOUNT = 0x0016       # UTF-8: "accountId|email"
TAG_TICKET = 0x0113        # runtime tail: observed to carry MasterFP
TAG_TRACE_ID = 0x0115      # runtime tail: observed to carry MasterSdid
TAG_DEVICE_INFO = 0x0114   # runtime tail JSON: observed to carry MasterDI
TAG_CLIENT_ID = 0x0014     # UTF-8: client marker "mailwin|..."
# The per-class payload the shared request header writer emits (RE §4.87/§4.88): the upload
# family's chunk carries its metadata JSON here while the body carries the raw file bytes.
TAG_UPLOAD_METADATA = 0x0103

TAG_MASTER_FP = TAG_TICKET
TAG_MASTER_SDID = TAG_TRACE_ID
TAG_MASTER_DI = TAG_DEVICE_INFO

WMSVR_SERVICE_TYPE_D1 = 3
DEFAULT_WMSVR_LOGIN_LOCALE = "zh_CN"
DEFAULT_WMSVR_LOGIN_CLIENT_PHASE = 0

WMSVR_ROUTE_PREFIX = "Coremail:"
_WMSVR_ROUTE_RE = _re.compile(
    r"^(?:(?P<prefix>Coremail):)?(?P<seed>[^%]+)%(?P<token>[^%]+)%(?P<session_host>wzp-session-[^%]+)$"
)

LOGIN_METHOD_LOGINONE = "wzpa:loginone"
LOGIN_METHOD_LOGINMAIL = "wzpa:loginmail"
LOGIN_METHOD_LOGINCORP = "wzpa:logincorp"
LOGIN_METHOD_MASTERDEVICE = "wzpmmc:masterdevice"
DEFAULT_WMSVR_LOGIN_COUNTERS: dict[str, int] = {
    LOGIN_METHOD_LOGINONE: 13,
    LOGIN_METHOD_MASTERDEVICE: 33,
}
LOGIN_FAMILY_METHODS = {
    LOGIN_METHOD_LOGINONE,
    LOGIN_METHOD_LOGINMAIL,
    LOGIN_METHOD_LOGINCORP,
}
DEFAULT_WMSVR_LOGIN_DF = "mailmaster_pc"
DEFAULT_WMSVR_LOGIN_PRODUCT = "mailmaster_win"
DEFAULT_WMSVR_LOGINMAIL_URS_CODE = "200"
DEFAULT_WMSVR_LOGINMAIL_PARTY = "mail"
DEFAULT_WMSVR_LOGIN_SWITCH_FUNCID = "switchLogin"
DEFAULT_WMSVR_LOGINONE_FUNCID = "loginone"
DEFAULT_WMSVR_LOGIN_LOGINTOKEN_FUNCID = "logintoken"

# `wzpa:loginone` password encoding. The client's `0x10a24970` pairs `passtype`
# with how the `password` field is encoded (see `build_loginone_body` and
# docs/reverse-engineering.md 4.13.10):
#   passtype "0" <=> password is `md5hex(...)`   (the normal account path)
#   passtype "1" <=> password is sent as typed   (only the `[+0x1d1]`-set branch)
# A long password is truncated to 16 characters *before* hashing (`0x10a25053`).
WMSVR_LOGINONE_PASSTYPE_MD5 = "0"
WMSVR_LOGINONE_PASSTYPE_PLAIN = "1"
WMSVR_LOGINONE_PASSWORD_MD5 = "md5"
WMSVR_LOGINONE_PASSWORD_RAW = "raw"
WMSVR_LOGINONE_MD5_SOURCE_LIMIT = 16

LOGIN_TAG_METHOD = TAG_METHOD
LOGIN_TAG_OPTIONAL_107 = 0x0107
LOGIN_TAG_DEVICE_ID = 0x010F
LOGIN_TAG_CONFIG_ID = 0x0110
LOGIN_TAG_APP_VERSION = 0x0112
LOGIN_TAG_HARDCODED_LOCALE = 0x0204

STARTUP_TAG_METHOD = 0x0100
STARTUP_TAG_OPAQUE_TOKEN = 0x0107
STARTUP_TAG_NONCE_HEX = 0x010A
STARTUP_TAG_STARTUP_FLAG = 0x010B
STARTUP_TAG_UNIX_TIME = 0x010C
STARTUP_TAG_DEVICE_ID = 0x010E
STARTUP_TAG_APPVER_INNER = 0x010F
STARTUP_TAG_CONFIG_ID = 0x0110
STARTUP_TAG_RESPONSE_FORMAT = 0x0111
STARTUP_TAG_MODE = 0x0300

CONTROL_TAG_MODE = 0x0300
CONTROL_TAG_CONTROL_ID = 0x0301
CONTROL_TAG_UNIX_TIME = 0x0308

D1_CONTROL_TAG_KEY_VERSION = 0x0001
D1_CONTROL_TAG_KEY_DIGEST = 0x0002
D1_CONTROL_TAG_MASTER_FP = 0x0113
D1_CONTROL_TAG_MASTER_SDID = 0x0115
D1_CONTROL_TAG_DEVICE_INFO = 0x0114

WMSVR_METHOD_UPDATE_MESSAGE_INFOS = "mbox:updateMessageInfos"
WMSVR_METHOD_DELETE_MESSAGES = "mbox:deleteMessages"

AIRSYNC_COMMAND_NAMES: dict[int, str] = {
    0x0001: "Sync",
    0x0002: "SendMail",
    0x0004: "SmartForward",
    0x0008: "SmartReply",
    0x000A: "GetAttachment",
    0x000C: "FolderCreate",
    0x000D: "FolderDelete",
    0x0010: "FolderSync",
    0x0040: "Settings",
    0x0080: "ItemEstimate",
    0x0100: "FolderUpdate",
    0x0200: "FolderSync",
    0x0400: "FolderCreate",
    0x1000: "FolderUpdate",
    0x2000: "MoveItems",
    0x4000: "GetItemEstimate",
    0x8000: "Provision",
    0x10000: "Search",
    0x20000: "ItemOperations",
    0x40000: "Ping",
    0x80000: "ResolveRecipients",
    0x100000: "ValidateCert",
    0x200000: "MeetingResponse",
    0x400000: "ValidateCert",
}

D1_WORD0_HAS_EXTRA16 = 0x4000
D1_WORD0_HAS_LEN0 = 0x2000
D1_WORD0_HAS_LEN1 = 0x1000

D1_TYPE_GET_SETTINGS = 0x30
D1_TYPE_SETTINGS_ACK = 0x40
D1_TYPE_ENCRYPTED_REQUEST_ALT = 0xA0
D1_TYPE_ENCRYPTED_REQUEST = 0xB0
D1_TYPE_ENCRYPTED_RESPONSE_ALT = 0xE0
D1_TYPE_ENCRYPTED_RESPONSE = 0xF0

DEFAULT_D1_KEY_VERSION = 0x00000191
DEFAULT_D1_GET_SETTINGS_WORD0 = 0x3000
DEFAULT_D1_GET_SETTINGS_WORD2 = 0x0000
DEFAULT_D1_GET_SETTINGS_WORD4 = 0x000A
DEFAULT_D1_FALLBACK_KEY_DIGEST16 = bytes.fromhex("b1f9fc8e92f8018795d29582fc9940c0")
DEFAULT_D1_PRIMARY_KEY_DIGEST16 = bytes.fromhex("4741ec3a8dc8e3603bf67c2bdcfb0275")
DEFAULT_D1_SIBLING_KEY_DIGEST16 = bytes.fromhex("74f94e4f1d3d837a5859acefcc21a5aa")
DEFAULT_D1_RPC_WORD2 = 0x0080
DEFAULT_D1_RPC_WORD4 = 0x0003
DEFAULT_D1_AES_IV = b"0102030405060708"
DEFAULT_D1_GET_SETTINGS_SIGNATURE = bytes.fromhex(
    "44063d68ff633d2bd9ee5768cdb7260af6204aacb6f6d47ccc05a64124e935faa0843d4e9ea4b5d0493f981ceee25d26"
    "f1317e28fc1dd298a032291313c8d3f6360f8cf900f3700b397b2f6e5854982bc830391815287c3f20fd40a53aeab1c2"
    "d63429d72175cc26cb6dd1a62759b7191aa1bc33f6462d7144a6bd67a5bfc680"
)
# Historical name kept for compatibility; wire evidence says slice1 of GET_SETTINGS is a
# PKCS#1 v1.5 type-2 wrapped 16-byte session key.
DEFAULT_D1_REPLAYED_WRAPPED_KEY = DEFAULT_D1_GET_SETTINGS_SIGNATURE
D1_KEY_EXCHANGE_BLOCK_LEN = 128  # RSA-1024 PKCS#1 v1.5 ciphertext length

D1_SLICE_PADDING_PKCS7 = "pkcs7"
D1_SLICE_PADDING_NUL = "nul"
DEFAULT_D1_SLICE_PADDING = D1_SLICE_PADDING_PKCS7

KNOWN_WMSVR_HARDCODED_KEY_DIGESTS: dict[str, bytes] = {
    "primary_default": DEFAULT_D1_PRIMARY_KEY_DIGEST16,
    "sibling_default": DEFAULT_D1_SIBLING_KEY_DIGEST16,
    "fallback_default": DEFAULT_D1_FALLBACK_KEY_DIGEST16,
}


# ---------------------------------------------------------------------------
# Envelope parser & captured-TLV inspection helpers
# ---------------------------------------------------------------------------


def parse_envelope(data: bytes) -> dict[int, bytes]:
    """Parse a TLV envelope into a dict of tag -> value."""
    result: dict[int, bytes] = {}
    for tag, value in decode_tlv_envelope(data):
        result[tag] = value
    return result


def describe_envelope(data: bytes) -> list[dict[str, Any]]:
    """Parse and describe all TLV records for debugging."""
    descriptions: list[dict[str, Any]] = []
    for tag, value in decode_tlv_envelope(data):
        desc: dict[str, Any] = {
            "tag": f"0x{tag:04x}",
            "length": len(value),
            "hex": value[:32].hex(),
        }
        try:
            desc["text"] = value.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            pass
        descriptions.append(desc)
    return descriptions


def decode_captured_tlv_record(record: Mapping[str, Any]) -> tuple[int, bytes]:
    """Decode one JSON capture record into `(tag, value_bytes)`."""
    tag = int(record.get("tag") or 0)
    hex_value = str(record.get("hex") or "")
    if len(hex_value) % 2 != 0:
        raise ValueError(f"Captured TLV hex length must be even for tag 0x{tag:04x}")
    return tag, bytes.fromhex(hex_value)


def split_captured_tlv_records(
    records: Iterable[Mapping[str, Any] | tuple[int, bytes]],
    *,
    boundary_tags: Iterable[int] | None = None,
) -> list[list[tuple[int, bytes]]]:
    """Split one broad capture block into logical TLV request segments."""
    raw_boundaries = (TAG_CLIENT_ID,) if boundary_tags is None else tuple(boundary_tags)
    boundaries = {int(tag) for tag in raw_boundaries}
    segments: list[list[tuple[int, bytes]]] = []
    current: list[tuple[int, bytes]] = []
    for raw_record in records:
        if isinstance(raw_record, Mapping):
            tag, value = decode_captured_tlv_record(cast(Mapping[str, Any], raw_record))
        else:
            tag, value = int(raw_record[0]), bytes(raw_record[1])
        current.append((tag, value))
        if tag in boundaries:
            segments.append(current)
            current = []
    if current:
        segments.append(current)
    return segments


def extract_captured_method_segments(
    records: Iterable[Mapping[str, Any] | tuple[int, bytes]],
) -> list[list[tuple[int, bytes]]]:
    """Extract method-centered TLV segments from one broad capture block."""
    decoded = split_captured_tlv_records(records, boundary_tags=())
    flat_records = decoded[0] if decoded else []
    if not flat_records:
        return []

    prefix_tags = {
        TAG_VERSION,
        TAG_TOKEN,
        TAG_ROUTE,
        TAG_HOST,
        TAG_PORT,
        TAG_ACCOUNT,
        D1_CONTROL_TAG_KEY_VERSION,
        D1_CONTROL_TAG_KEY_DIGEST,
        STARTUP_TAG_STARTUP_FLAG,
        STARTUP_TAG_UNIX_TIME,
        STARTUP_TAG_NONCE_HEX,
        CONTROL_TAG_MODE,
        CONTROL_TAG_CONTROL_ID,
        CONTROL_TAG_UNIX_TIME,
    }
    segments: list[list[tuple[int, bytes]]] = []
    index = 0
    total = len(flat_records)
    while index < total:
        if flat_records[index][0] != TAG_METHOD:
            index += 1
            continue
        start = index
        while start > 0 and flat_records[start - 1][0] in prefix_tags:
            start -= 1
        end = index
        while end < total and flat_records[end][0] != TAG_CLIENT_ID:
            end += 1
        if end < total:
            end += 1
        segments.append(flat_records[start:end])
        index = end
    return segments


def extract_tlv_method_name(records: Iterable[tuple[int, bytes]]) -> str:
    """Return the first UTF-8 method carried by `tag 0x0100`, if any."""
    for tag, value in records:
        if tag == TAG_METHOD:
            return value.decode("utf-8", errors="ignore")
    return ""


def classify_captured_tlv_segment(records: Iterable[tuple[int, bytes]]) -> str:
    """Classify one split TLV segment for offline reverse-engineering work."""
    record_list = list(records)
    method = extract_tlv_method_name(record_list)
    tag_set = {tag for tag, _ in record_list}
    if method in {LOGIN_METHOD_LOGINONE, LOGIN_METHOD_MASTERDEVICE}:
        return "login"
    if tag_set & {TAG_TOKEN, TAG_ROUTE, TAG_HOST, TAG_PORT, TAG_ACCOUNT}:
        return "envelope"
    if tag_set <= {D1_CONTROL_TAG_KEY_VERSION, D1_CONTROL_TAG_KEY_DIGEST}:
        return "d1_control"
    if tag_set & {
        STARTUP_TAG_STARTUP_FLAG,
        STARTUP_TAG_UNIX_TIME,
        STARTUP_TAG_NONCE_HEX,
        STARTUP_TAG_DEVICE_ID,
        STARTUP_TAG_APPVER_INNER,
        STARTUP_TAG_CONFIG_ID,
        STARTUP_TAG_MODE,
        STARTUP_TAG_RESPONSE_FORMAT,
    }:
        return "startup"
    if tag_set & {LOGIN_TAG_DEVICE_ID, LOGIN_TAG_APP_VERSION, LOGIN_TAG_HARDCODED_LOCALE}:
        return "login"
    return "unknown"
