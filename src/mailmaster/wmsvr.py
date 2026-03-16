"""Wmsvr / Coremail Wzp private protocol implementation.
Wire format (confirmed from mastercore.dll disassembly):
  - Each TLV record: [2-byte tag BE] [LEB128 length] [raw value]
  - Request JSON is a separate logical slice from the TLV envelope
  - On the confirmed d1 request path, the raw plaintext layout is:
    [LEB128(padded_json_len)?] [encrypted(padded_tlv || padded_json)]
Transport status note (updated 2026-03-15):
  - The earlier HTTP/TLS hypothesis for Wmsvr writes is stale.
  - Live capture now confirms real Wmsvr write operations ride a proprietary
    d1 framing layer over raw TCP on long-lived connections (ports 443/8080).
  - The TLV helpers in this module are still valid.
  - The HTTP helper code further below should be treated as legacy analysis
    scaffolding, not as the confirmed production write path.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re as _re
import shutil
import socket
import sqlite3
import struct
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import md5, sha1
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .discovery import discover_paths
from .protocol_config import decrypt_runtime_protected_blob

logger = logging.getLogger(__name__)


# TLV codec
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
        raise ValueError(f"Truncated TLV value for tag 0x{tag:04x}: expected {length}, got {len(value)}
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
# Tag constants (from live capture + disassembly)
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

TAG_MASTER_FP = TAG_TICKET
TAG_MASTER_SDID = TAG_TRACE_ID
TAG_MASTER_DI = TAG_DEVICE_INFO

WMSVR_SERVICE_TYPE_D1 = 3
DEFAULT_WMSVR_LOGIN_LOCALE = "zh_CN"

WMSVR_ROUTE_PREFIX = "Coremail:"
_WMSVR_ROUTE_RE = _re.compile(
    r"^(?:(?P<prefix>Coremail):)?(?P<seed>[^%]+)%(?P<token>[^%]+)%(?P<session_host>wzp-session-[^%]+)$"
)

LOGIN_METHOD_LOGINONE = "wzpa:loginone"
LOGIN_METHOD_MASTERDEVICE = "wzpmmc:masterdevice"

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
WMSVR_STATIC_LOGIN_METHOD_TERMS = (
    "user:validateSession",
    "wzpa:loginone",
    "wzpa:loginmail",
    "wzpa:logincorp",
    "wzpmmc:masterdevice",
)
WMSVR_STATIC_LOGIN_REQUEST_FIELD_TERMS = (
    "Function-Wzp-Config",
    "switchLogin",
    "funcid",
    "passtype",
    "app-version",
    "returnToken",
    "returnUrs",
    "device-id",
    "ignore",
    "smslogin_trust",
    "ursCode",
    "logintoken",
    "party",
    "qiye_use_md5",
)
WMSVR_STATIC_AUTH_RESPONSE_FIELD_TERMS = (
    "authToken",
    "coremailToken",
    "ntessessToken",
    "mixmailToken",
    "refreshToken",
    "coremailCookie",
    "qiyeToken",
)
WMSVR_STATIC_JSBRIDGE_METHOD_TERMS = (
    "LOGIN_ACCOUNT",
    "RENEW_ACCOUNT_AUTH",
    "GET_ACCOUNT_AUTH_LIST",
    "GET_SECOND_ACCOUNT_AUTH_INFO",
    "LOGIN_MASTER",
    "VALIDATE_MASTER_SESSION",
    "LOGIN_MASTER_BY_VENDOR",
    "AUTOLOGIN_COREMAIL_COOKIE",
    "AUTOLOGIN_URS_COOKIE",
)
WMSVR_STATIC_HTTP_AUTH_TYPE_TERMS = (
    "masterToken",
    "mixmailToken",
    "coremailToken",
)
WMSVR_STATIC_ENDPOINT_HINT_TERMS = (
    "/client/batchGetValue.do",
    "/client/getValue.do",
    "/msg/list",
    "/msg/confirm",
    "/ud_proxy/config",
    "/ud_proxy/info",
    "/recall_mail",
    "mail.163.com",
    "dashi.163.com",
)
WMSVR_RUNTIME_SEARCH_TERMS = tuple(
    dict.fromkeys(
        WMSVR_STATIC_LOGIN_METHOD_TERMS
        + WMSVR_STATIC_AUTH_RESPONSE_FIELD_TERMS
        + WMSVR_STATIC_JSBRIDGE_METHOD_TERMS
        + WMSVR_STATIC_ENDPOINT_HINT_TERMS
        + (
            "mastersess",
            "mixmailtokens",
            "masterfp",
            "masterdi",
            "sdid",
        )
    )
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class WmsvrRouteParts:
    """Parsed view of the normal Wmsvr route/ticket string family."""
    seed: str
    token: str
    session_host: str
    has_coremail_prefix: bool = True
    @property
    def route(self) -> str:
        prefix = WMSVR_ROUTE_PREFIX if self.has_coremail_prefix else ""
        return f"{prefix}{self.seed}%{self.token}%{self.session_host}"

    @property
    def http_ticket(self) -> str:
        return f"{self.seed}%{self.token}%{self.session_host}"


def _coerce_wmsvr_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def classify_wmsvr_auth_token(value: bytes | str | None) -> str:
    """Classify an observed Wmsvr auth/session token family.

    Current confirmed families:
    - startup-family `0x0107`: `2A2E48M6-...` -> `mastersess`
    - startup-family `0x0107`: `COMMON_TOKEN_<uuid>` -> `common_token`
    - HTTP `mixmailtokens`: `1B1...` / `1D1...`
    - several normal methods also use 4-byte integer flags in `0x0107`
    """
    if value is None:
        return "empty"
    if isinstance(value, bytes) and len(value) == 4:
        return "flag"
    text = _coerce_wmsvr_text(value)
    if not text:
        return "empty"
    if text.startswith("2A2E48M6-"):
        return "mastersess"
    if text.startswith("COMMON_TOKEN_"):
        return "common_token"
    if text.startswith(("1B1", "1D1")):
        return "mixmailtokens"
    return "unknown"


def lookup_airsync_command_name(command: int) -> str:
    """Return the static AirSync-style command name for a numeric command flag.

    Confirmed from the command switch around `0x1088ef70` in the current build.
    Unknown values intentionally return an empty string.
    """
    return AIRSYNC_COMMAND_NAMES.get(command, "")


def infer_wmsvr_http_auth_type(value: bytes | str | None) -> str:
    """Infer the observed HTTP `X-AUTH-TYPE` value from a confirmed token family.

    Current confirmed mappings from local artifacts:
    - `mastersess` -> `masterToken`
    - `mixmailtokens` -> `mixmailToken`

    No confirmed runtime mapping is encoded yet for `COMMON_TOKEN_*` or other
    opaque families, so those intentionally return an empty string.
    """
    if isinstance(value, str) and value in {
        "mastersess",
        "mixmailtokens",
        "common_token",
        "flag",
        "unknown",
    }:
        kind = value
    else:
        kind = classify_wmsvr_auth_token(value)
    if kind == "mastersess":
        return "masterToken"
    if kind == "mixmailtokens":
        return "mixmailToken"
    return ""


def parse_wmsvr_route(route: str) -> WmsvrRouteParts | None:
    """Parse a normal Wmsvr route (`tag 0x0102`) or HTTP `ticket` string."""
    match = _WMSVR_ROUTE_RE.fullmatch(route)
    if not match:
        return None
    return WmsvrRouteParts(
        seed=match.group("seed"),
        token=match.group("token"),
        session_host=match.group("session_host"),
        has_coremail_prefix=bool(match.group("prefix")),
    )


def route_to_http_ticket(route: str) -> str:
    """Convert a normal Wmsvr route (`Coremail:...`) into the HTTP `ticket` form."""
    parts = parse_wmsvr_route(route)
    if parts is None:
        raise ValueError(f"Unsupported Wmsvr route format: {route!r}")
    return parts.http_ticket


def ticket_to_wmsvr_route(ticket: str) -> str:
    """Convert an HTTP `ticket` header value into the normal TLV route form."""
    parts = parse_wmsvr_route(ticket)
    if parts is None:
        raise ValueError(f"Unsupported Wmsvr ticket format: {ticket!r}")
    parts.has_coremail_prefix = True
    return parts.route


@dataclass(slots=True)
class WmsvrSession:
    """Session state needed to construct Wmsvr requests.

    All fields correspond to TLV tags in the request envelope.
    HTTP transport fields are used for request headers.
    """

    # TLV envelope fields
    token: str = ""          # tag 0x101 — 32-char auth token
    route: str = ""          # tag 0x102 — "Coremail:<seed>%<token>%wzp-session-..."
    host: str = ""           # tag 0x200 — backend IP
    port: int = 0            # tag 0x201 — backend port
    account_desc: str = ""   # tag 0x16  — "accountId|email"
    ticket: str = ""         # compatibility alias for tag 0x113 / MasterFP
    trace_id: str = ""       # compatibility alias for tag 0x115 / MasterSdid
    device_info: str = ""    # compatibility alias for tag 0x114 / MasterDI JSON
    client_id: str = ""      # tag 0x14  — "mailwin|..."

    # HTTP transport header fields / candidate runtime cache slots.
    # `device_id` is directly readable as a plain string; the `X-MC-*` family
    # below is still modeled here because live HTTP captures prove the headers
    # exist, but the singleton slots are not yet proven to be plain string
    # storage in the current build.
    device_id: str = ""      # singleton +0x00 — X-CM-DEVICE-ID / X-MC-DEVICE-ID
    seed_token: str = ""     # candidate slot near singleton +0xc0 — X-MC-SEED-TOKEN family
    eh_seed: str = ""        # candidate slot near singleton +0xa8 — X-MC-EH-SEED family
    mc_token: str = ""       # candidate slot near singleton +0xd8 — X-MC-TOKEN family
    app_version: str = ""    # singleton +0x108 — X-MC-APPVERINNER
    product: str = ""        # singleton +0x120 — X-MC-PRODUCT
    mastersess: str = ""     # observed HTTP `mastersess` / `/init/session` `token`
    mixmailtokens: str = ""  # observed HTTP `mixmailtokens`
    proto: str = "https"     # protocol scheme (https or http)

    @property
    def master_fp(self) -> str:
        return self.ticket

    @master_fp.setter
    def master_fp(self, value: str) -> None:
        self.ticket = value

    @property
    def master_sdid(self) -> str:
        return self.trace_id

    @master_sdid.setter
    def master_sdid(self, value: str) -> None:
        self.trace_id = value

    @property
    def master_device_info_json(self) -> str:
        return self.device_info

    @master_device_info_json.setter
    def master_device_info_json(self, value: str) -> None:
        self.device_info = value

    @property
    def route_parts(self) -> WmsvrRouteParts | None:
        return parse_wmsvr_route(self.route)

    @property
    def http_ticket(self) -> str:
        return route_to_http_ticket(self.route) if self.route else ""


@dataclass(slots=True)
class WmsvrRequest:
    """A fully constructed Wmsvr protocol request."""

    method: str
    body_json: str
    envelope: bytes = b""
    session: WmsvrSession = field(default_factory=WmsvrSession)

    def to_wire(self) -> tuple[bytes, bytes]:
        """Return (envelope_bytes, body_bytes) ready for transmission."""
        return self.envelope, self.body_json.encode("utf-8")

    def to_d1_plain_layout(self) -> WmsvrD1PlainLayout:
        """Return the confirmed pre-encryption d1 body layout.

        This only models the plaintext layout now confirmed by offline analysis.
        It does not perform the private encrypted-region transform.
        """
        return build_d1_plain_layout(self.envelope, self.body_json.encode("utf-8"))


@dataclass(slots=True)
class WmsvrLoginPayload:
    """Method-specific TLV payload used during the Wmsvr login chain.

    Important: these login-method tags are method-specific and must not be
    conflated with the later post-login outer-envelope tag meanings.
    """

    method: str
    records: list[tuple[int, bytes]] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return encode_tlv_envelope(self.records)

    def describe(self) -> list[dict[str, Any]]:
        return describe_envelope(self.to_bytes())


@dataclass(slots=True)
class WmsvrStartupPayload:
    """Observed TLV payload for the special startup-family d1 request path.

    Important scope note:
    - These tag meanings are specific to the startup-family requests captured
      around methods like `GET_SETTINGS`, `GET_GROUPS`,
      `LIST_WRITEMAIL_TEMP_IDS`, and similar bootstrap/control methods.
    - They are not globally interchangeable with the normal post-login Wmsvr
      outer-envelope tag meanings.
    """

    method: str = ""
    opaque_token: bytes = b""
    nonce_hex: str = ""
    timestamp: str = ""
    device_id: str = ""
    appver_inner: str = ""
    config_id: str = ""
    mode: bytes = b""
    startup_flag: bytes = b"1"
    response_format: bytes = b""
    ticket: str = ""
    trace_id: str = ""
    device_info_json: str = ""
    client_id: str = ""
    extra_records: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def encoded_len(self) -> int:
        return len(self.to_bytes())

    @property
    def aligned_len(self) -> int:
        return len(align16(self.to_bytes()))

    @property
    def token_kind(self) -> str:
        return classify_wmsvr_auth_token(self.opaque_token)

    @property
    def master_fp(self) -> str:
        return self.ticket

    @master_fp.setter
    def master_fp(self, value: str) -> None:
        self.ticket = value

    @property
    def master_sdid(self) -> str:
        return self.trace_id

    @master_sdid.setter
    def master_sdid(self, value: str) -> None:
        self.trace_id = value

    def to_records(self) -> list[tuple[int, bytes]]:
        records: list[tuple[int, bytes]] = []
        if self.startup_flag:
            records.append((STARTUP_TAG_STARTUP_FLAG, self.startup_flag))
        if self.timestamp:
            records.append((STARTUP_TAG_UNIX_TIME, self.timestamp.encode("utf-8")))
        if self.nonce_hex:
            records.append((STARTUP_TAG_NONCE_HEX, self.nonce_hex.encode("utf-8")))
        if self.method:
            records.append((STARTUP_TAG_METHOD, self.method.encode("utf-8")))
        if self.device_id:
            records.append((STARTUP_TAG_DEVICE_ID, self.device_id.encode("utf-8")))
        if self.appver_inner:
            records.append((STARTUP_TAG_APPVER_INNER, self.appver_inner.encode("utf-8")))
        if self.config_id:
            records.append((STARTUP_TAG_CONFIG_ID, self.config_id.encode("utf-8")))
        if self.opaque_token:
            records.append((STARTUP_TAG_OPAQUE_TOKEN, self.opaque_token))
        if self.mode:
            records.append((STARTUP_TAG_MODE, self.mode))
        if self.response_format:
            records.append((STARTUP_TAG_RESPONSE_FORMAT, self.response_format))
        records.extend(
            _build_wmsvr_runtime_tail_records(
                ticket=self.ticket,
                trace_id=self.trace_id,
                device_info_json=self.device_info_json,
                client_id=self.client_id,
            )
        )
        records.extend(self.extra_records)
        return records

    def to_bytes(self) -> bytes:
        return encode_tlv_envelope(self.to_records())


@dataclass(slots=True)
class WmsvrControlPayload:
    """Observed TLV payload for the lightweight control-family request path."""

    mode: bytes = b""
    control_id_hex: str = ""
    timestamp: str = ""
    ticket: str = ""
    trace_id: str = ""
    device_info_json: str = ""
    client_id: str = ""
    extra_records: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def encoded_len(self) -> int:
        return len(self.to_bytes())

    @property
    def aligned_len(self) -> int:
        return len(align16(self.to_bytes()))

    @property
    def master_fp(self) -> str:
        return self.ticket

    @master_fp.setter
    def master_fp(self, value: str) -> None:
        self.ticket = value

    @property
    def master_sdid(self) -> str:
        return self.trace_id

    @master_sdid.setter
    def master_sdid(self, value: str) -> None:
        self.trace_id = value

    def to_records(self) -> list[tuple[int, bytes]]:
        records: list[tuple[int, bytes]] = []
        if self.mode:
            records.append((CONTROL_TAG_MODE, self.mode))
        if self.control_id_hex:
            records.append((CONTROL_TAG_CONTROL_ID, self.control_id_hex.encode("utf-8")))
        if self.timestamp:
            records.append((CONTROL_TAG_UNIX_TIME, self.timestamp.encode("utf-8")))
        records.extend(
            _build_wmsvr_runtime_tail_records(
                ticket=self.ticket,
                trace_id=self.trace_id,
                device_info_json=self.device_info_json,
                client_id=self.client_id,
            )
        )
        records.extend(self.extra_records)
        return records

    def to_bytes(self) -> bytes:
        return encode_tlv_envelope(self.to_records())


@dataclass(slots=True)
class WmsvrD1PlainLayout:
    """Confirmed plaintext layout before the private d1 block transform."""

    section_len: int
    padded_json_len: int
    body_prefix: bytes
    padded_envelope: bytes
    padded_json: bytes

    @property
    def padded_slice0(self) -> bytes:
        return self.padded_envelope

    @property
    def padded_slice1(self) -> bytes:
        return self.padded_json

    @property
    def slice0_len(self) -> int:
        return self.section_len

    @property
    def slice1_len(self) -> int:
        return self.padded_json_len

    @property
    def encrypted_plaintext(self) -> bytes:
        """Bytes that feed into the private encrypted-region transform."""
        return self.padded_envelope + self.padded_json

    @property
    def body_len(self) -> int:
        """Plain body length before region encryption is applied."""
        return len(self.body_prefix) + len(self.encrypted_plaintext)

    def to_unencrypted_body(self) -> bytes:
        """Return `[body_prefix][encrypted_plaintext]` for analysis/debugging."""
        return self.body_prefix + self.encrypted_plaintext


@dataclass(slots=True)
class WmsvrD1Header:
    """Parsed/constructed raw d1 frame header."""

    word0: int
    word2: int
    word4: int
    seq: int = 0
    extra16: int | None = None
    len0: int | None = None
    len1: int | None = None

    @property
    def frame_type(self) -> int:
        return (self.word0 >> 8) & 0xFF

    @property
    def has_extra16(self) -> bool:
        return bool(self.word0 & D1_WORD0_HAS_EXTRA16)

    @property
    def has_len0(self) -> bool:
        return bool(self.word0 & D1_WORD0_HAS_LEN0)

    @property
    def has_len1(self) -> bool:
        return bool(self.word0 & D1_WORD0_HAS_LEN1)

    def to_bytes(self) -> bytes:
        parts = [
            b"\xD1",
            struct.pack(">H", self.word0 & 0xFFFF),
            struct.pack(">H", self.word4 & 0xFFFF),
            struct.pack(">H", self.word2 & 0xFFFF),
            struct.pack(">H", self.seq & 0xFFFF),
        ]
        if self.has_extra16:
            parts.append(struct.pack(">H", int(self.extra16 or 0) & 0xFFFF))
        if self.has_len0:
            parts.append(encode_leb128(int(self.len0 or 0)))
        if self.has_len1:
            parts.append(encode_leb128(int(self.len1 or 0)))
        return b"".join(parts)


@dataclass(slots=True)
class WmsvrD1Frame:
    """Structured raw d1 frame with optional split slices."""

    header: WmsvrD1Header
    slice0: bytes = b""
    slice1: bytes = b""
    remainder: bytes = b""

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.slice0 + self.slice1 + self.remainder


@dataclass(slots=True)
class WmsvrGetSettingsResponse:
    """Parsed metadata from a raw d1 `GET_SETTINGS` response frame."""

    business_code: int | None = None
    key_version: int | None = None
    key_blob: bytes = b""
    frame: WmsvrD1Frame | None = None


@dataclass(slots=True)
class WmsvrD1RequestContext:
    """Low-level material needed to build raw encrypted d1 requests."""

    key_version: int = DEFAULT_D1_KEY_VERSION
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16
    master_fp: str = ""
    master_sdid: str = ""
    device_info_json: str = ""
    session_key: bytes = b""
    word2: int = DEFAULT_D1_RPC_WORD2
    word4: int = DEFAULT_D1_RPC_WORD4

    @property
    def key_digest32(self) -> bytes:
        return normalize_d1_key_digest(self.key_digest16)

    def with_session_key(self, session_key: bytes) -> WmsvrD1RequestContext:
        return WmsvrD1RequestContext(
            key_version=self.key_version,
            key_digest16=self.key_digest16,
            master_fp=self.master_fp,
            master_sdid=self.master_sdid,
            device_info_json=self.device_info_json,
            session_key=session_key,
            word2=self.word2,
            word4=self.word4,
        )


# ---------------------------------------------------------------------------
# Public-key helpers
# ---------------------------------------------------------------------------

KNOWN_WMSVR_HARDCODED_KEY_DIGESTS: dict[str, bytes] = {
    "primary_default": DEFAULT_D1_PRIMARY_KEY_DIGEST16,
    "sibling_default": DEFAULT_D1_SIBLING_KEY_DIGEST16,
    "fallback_default": DEFAULT_D1_FALLBACK_KEY_DIGEST16,
}

_PUBLIC_KEY_PEM_PATTERN = _re.compile(
    rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----",
    _re.S,
)


@dataclass(slots=True, frozen=True)
class WmsvrHardcodedPublicKey:
    """One public key block extracted from `mastercore.dll`."""

    label: str
    pem: str
    digest16: bytes
    bits: int
    exponent: int
    source_path: str = ""
    source_index: int = -1

    @property
    def digest_hex(self) -> str:
        return self.digest16.hex()


@dataclass(slots=True)
class WmsvrDecodedKeyUpdate:
    """Decoded runtime key material from a `GET_SETTINGS -> 0x01f0` response."""

    version: int
    der_bytes: bytes
    pem: str
    digest16: bytes
    matched_hardcoded_key: str = ""

    @property
    def digest_hex(self) -> str:
        return self.digest16.hex()


_HARDCODED_WMSVR_KEYS_CACHE: dict[Path | None, dict[str, WmsvrHardcodedPublicKey]] = {}


def _iter_mastercore_dll_candidates(install_root: Path | None = None) -> list[Path]:
    root = install_root if install_root is not None else discover_paths().install_root
    if root is None or not root.exists():
        return []
    return sorted(
        root.rglob("mastercore.dll"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def _normalize_public_key_pem(pem: bytes) -> bytes:
    normalized = pem.replace(b"\r\r\n", b"\n").replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = [line.strip() for line in normalized.split(b"\n") if line.strip()]
    return b"\n".join(lines) + b"\n"


def _load_rsa_public_key(key_data: bytes | str) -> rsa.RSAPublicKey:
    raw = key_data.encode("ascii") if isinstance(key_data, str) else key_data
    public_key = (
        serialization.load_pem_public_key(raw)
        if b"-----BEGIN" in raw
        else serialization.load_der_public_key(raw)
    )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Only RSA public keys are supported for Wmsvr key handling.")
    return public_key


def compute_wmsvr_public_key_digest(key_data: bytes | str) -> bytes:
    """Compute the confirmed MailMaster digest for one RSA public key."""
    public_key = _load_rsa_public_key(key_data)
    numbers = public_key.public_numbers()
    modulus_hex_upper = format(numbers.n, "X")
    exponent_hex_lower = format(numbers.e, "x").zfill(((numbers.e.bit_length() + 7) // 8) * 2)
    digest_text = f"{modulus_hex_upper},{exponent_hex_lower}".encode("ascii")
    return md5(digest_text).digest()


def _describe_public_key(
    key_data: bytes | str,
    *,
    label: str,
    source_path: str = "",
    source_index: int = -1,
) -> WmsvrHardcodedPublicKey:
    public_key = _load_rsa_public_key(key_data)
    digest16 = compute_wmsvr_public_key_digest(key_data)
    numbers = public_key.public_numbers()
    pem_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return WmsvrHardcodedPublicKey(
        label=label,
        pem=pem_bytes.decode("ascii"),
        digest16=digest16,
        bits=public_key.key_size,
        exponent=numbers.e,
        source_path=source_path,
        source_index=source_index,
    )


def load_wmsvr_hardcoded_public_keys(install_root: Path | None = None) -> dict[str, WmsvrHardcodedPubli
    """Scan the latest installed `mastercore.dll` for embedded public keys."""
    cache_key = install_root.resolve() if install_root is not None else None
    cached = _HARDCODED_WMSVR_KEYS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    label_by_digest = {
        digest.hex(): label
        for label, digest in KNOWN_WMSVR_HARDCODED_KEY_DIGESTS.items()
    }

    for dll_path in _iter_mastercore_dll_candidates(install_root):
        try:
            raw = dll_path.read_bytes()
        except OSError:
            continue

        found: dict[str, WmsvrHardcodedPublicKey] = {}
        seen_digests: set[bytes] = set()
        for index, match in enumerate(_PUBLIC_KEY_PEM_PATTERN.finditer(raw)):
            pem = _normalize_public_key_pem(match.group(0))
            try:
                digest16 = compute_wmsvr_public_key_digest(pem)
                label = label_by_digest.get(digest16.hex(), f"embedded_{index}")
                key = _describe_public_key(
                    pem,
                    label=label,
                    source_path=str(dll_path),
                    source_index=index,
                )
            except (TypeError, ValueError):
                continue
            if key.digest16 in seen_digests:
                continue
            seen_digests.add(key.digest16)
            found[key.label] = key

        if found:
            _HARDCODED_WMSVR_KEYS_CACHE[cache_key] = found
            return found

    result: dict[str, WmsvrHardcodedPublicKey] = {}
    _HARDCODED_WMSVR_KEYS_CACHE[cache_key] = result
    return result


def get_wmsvr_hardcoded_public_key(
    label: str,
    *,
    install_root: Path | None = None,
) -> WmsvrHardcodedPublicKey:
    """Return one labeled hardcoded key from `mastercore.dll`."""
    keys = load_wmsvr_hardcoded_public_keys(install_root)
    try:
        return keys[label]
    except KeyError as exc:
        raise ValueError(f"Wmsvr hardcoded public key not found: {label}") from exc


def unwrap_wmsvr_key_update_blob(
    key_blob: bytes,
    sibling_public_key: bytes | str | WmsvrHardcodedPublicKey,
) -> bytes:
    """Recover the inner DER payload from a `0x01f0` sibling-slot key-update blob."""
    key_data = sibling_public_key.pem if isinstance(sibling_public_key, WmsvrHardcodedPublicKey) else s
    public_key = _load_rsa_public_key(key_data)
    public_numbers = public_key.public_numbers()
    block_size = (public_key.key_size + 7) // 8
    if len(key_blob) != block_size:
        raise ValueError(f"Key-update blob must be {block_size} bytes, got {len(key_blob)}")

    cipher_int = int.from_bytes(key_blob, "big")
    plain_int = pow(cipher_int, public_numbers.e, public_numbers.n)
    encoded_message = plain_int.to_bytes(block_size, "big")

    if not encoded_message.startswith(b"\x00\x01"):
        raise ValueError("Key-update blob is not a PKCS#1 type-1 block.")
    separator = encoded_message.find(b"\x00", 2)
    if separator < 10:
        raise ValueError("Key-update blob has invalid PKCS#1 padding.")
    if any(byte != 0xFF for byte in encoded_message[2:separator]):
        raise ValueError("Key-update blob contains non-0xFF PKCS#1 padding bytes.")
    return encoded_message[separator + 1 :]


def der_bytes_to_public_key_pem(der_bytes: bytes) -> str:
    """Wrap DER public-key bytes as a canonical PEM block."""
    public_key = _load_rsa_public_key(der_bytes)
    pem_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


def decode_get_settings_key_update(
    response: WmsvrGetSettingsResponse,
    *,
    install_root: Path | None = None,
    sibling_public_key: bytes | str | WmsvrHardcodedPublicKey | None = None,
) -> WmsvrDecodedKeyUpdate:
    """Decode a `GET_SETTINGS` key-update response into runtime key material."""
    if response.business_code != 0x01F0:
        raise ValueError(f"Expected business_code=0x01f0, got {response.business_code!r}")
    if response.key_version is None:
        raise ValueError("Key-update response is missing tag 0x0001 version.")
    if not response.key_blob:
        raise ValueError("Key-update response is missing slice1 key blob.")

    sibling_key = sibling_public_key
    if sibling_key is None:
        sibling_key = get_wmsvr_hardcoded_public_key(
            "sibling_default",
            install_root=install_root,
        )

    der_bytes = unwrap_wmsvr_key_update_blob(response.key_blob, sibling_key)
    pem = der_bytes_to_public_key_pem(der_bytes)
    digest16 = compute_wmsvr_public_key_digest(pem)

    matched_hardcoded_key = ""
    for label, key in load_wmsvr_hardcoded_public_keys(install_root).items():
        if key.digest16 == digest16:
            matched_hardcoded_key = label
            break

    return WmsvrDecodedKeyUpdate(
        version=response.key_version,
        der_bytes=der_bytes,
        pem=pem,
        digest16=digest16,
        matched_hardcoded_key=matched_hardcoded_key,
    )


# ---------------------------------------------------------------------------
# No-Frida bootstrap material from app.db
# ---------------------------------------------------------------------------

DEFAULT_WMSVR_APP_CONFIG_KEYS = (
    "CloudInfo",
    "MasterDI",
    "MasterFP",
    "MasterSdid",
    "FakeDeviceId",
    "LocateCache",
    "WzpLocateAddresses",
    "WebuiPubKey",
)


@dataclass(slots=True, frozen=True)
class WmsvrPeerCandidate:
    """A located Wmsvr peer candidate."""

    host: str
    port: int
    is_ip_v6: bool = False


@dataclass(slots=True)
class WmsvrLocateId:
    """Identity of a locate-cache entry."""

    service_type: int
    user: str = ""
    locate_user: str = ""


@dataclass(slots=True)
class WmsvrLocateEntry:
    """A single parsed LocateCache entry from app.db."""

    locate_id: WmsvrLocateId
    candidates: list[WmsvrPeerCandidate] = field(default_factory=list)
    prefer_ipv6: bool = False

    @property
    def service_type(self) -> int:
        return self.locate_id.service_type

    @property
    def is_global(self) -> bool:
        return not _normalize_account(self.locate_id.user) and not _normalize_account(self.locate_id.lo

    def matches_account(self, account: str | None) -> bool:
        normalized = _normalize_account(account)
        if not normalized:
            return True
        return normalized in {
            _normalize_account(self.locate_id.user),
            _normalize_account(self.locate_id.locate_user),
        }


@dataclass(slots=True)
class WmsvrMasterDeviceInfo:
    """Persisted app-level device information used by Wmsvr auth/bootstrap."""

    app_version: str = ""
    config_id: str = ""
    dev_type: str = ""
    device_id: str = ""
    md5_sign: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> WmsvrMasterDeviceInfo:
        extras = {
            str(key): value
            for key, value in data.items()
            if key not in {"appVersion", "configId", "devType", "deviceId", "md5Sign"}
        }
        return cls(
            app_version=str(data.get("appVersion") or ""),
            config_id=str(data.get("configId") or ""),
            dev_type=str(data.get("devType") or ""),
            device_id=str(data.get("deviceId") or ""),
            md5_sign=str(data.get("md5Sign") or ""),
            extras=extras,
        )

    def to_mapping(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "appVersion": self.app_version,
            "configId": self.config_id,
            "devType": self.dev_type,
            "deviceId": self.device_id,
            "md5Sign": self.md5_sign,
        }
        payload.update(self.extras)
        return payload

    def to_json(self) -> str:
        mapping = self.to_mapping()
        if not any(mapping.values()):
            return ""
        return json.dumps(mapping, ensure_ascii=False, separators=(",", ":"))


@dataclass(slots=True)
class WmsvrCloudInfo:
    """Persisted master-cloud auth material loaded from `AppConfig.CloudInfo`."""

    cloud_id: str = ""
    cloud_token: str = ""
    relate_emails: list[str] = field(default_factory=list)
    sync_tag: Any = None
    apple: Any = None
    mobile: Any = None
    qq: Any = None
    weibo: Any = None
    weixin: Any = None
    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> WmsvrCloudInfo:
        relate_emails_raw = data.get("RelateEmails")
        if isinstance(relate_emails_raw, list):
            relate_emails = [str(item) for item in relate_emails_raw if item not in (None, "")]
        elif relate_emails_raw in (None, ""):
            relate_emails = []
        else:
            relate_emails = [str(relate_emails_raw)]

        extras = {
            str(key): value
            for key, value in data.items()
            if key
            not in {
                "CloudId",
                "CloudToken",
                "RelateEmails",
                "SyncTag",
                "apple",
                "mobile",
                "qq",
                "weibo",
                "weixin",
            }
        }
        return cls(
            cloud_id=str(data.get("CloudId") or ""),
            cloud_token=str(data.get("CloudToken") or ""),
            relate_emails=relate_emails,
            sync_tag=data.get("SyncTag"),
            apple=data.get("apple"),
            mobile=data.get("mobile"),
            qq=data.get("qq"),
            weibo=data.get("weibo"),
            weixin=data.get("weixin"),
            extras=extras,
        )

    @property
    def master_id(self) -> str:
        return self.cloud_id

    @property
    def mastersess(self) -> str:
        return self.cloud_token

    def to_mapping(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "CloudId": self.cloud_id,
            "CloudToken": self.cloud_token,
            "RelateEmails": self.relate_emails,
            "SyncTag": self.sync_tag,
            "apple": self.apple,
            "mobile": self.mobile,
            "qq": self.qq,
            "weibo": self.weibo,
            "weixin": self.weixin,
        }
        payload.update(self.extras)
        return payload

    def to_json(self) -> str:
        mapping = self.to_mapping()
        if not any(value not in (None, "", [], {}) for value in mapping.values()):
            return ""
        return json.dumps(mapping, ensure_ascii=False, separators=(",", ":"))


@dataclass(slots=True)
class WmsvrAccountConfig:
    """Decrypted Wmsvr account config from `AccountConfig.WmsvrServerConfig`."""

    user: str = ""
    password: str = ""
    area: str = ""
    system: str = ""
    corp_oauth: str = ""
    qiye_token: str = ""
    pass2fa: str = ""
    extras: dict[str, Any] = field(default_factory=dict)
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> WmsvrAccountConfig:
        extras = {
            str(key): value
            for key, value in data.items()
            if key not in {"user", "password", "area", "sys", "refreshToken", "corpOAuth", "qiyeToken",
        }
        return cls(
            user=str(data.get("user") or ""),
            password=str(data.get("password") or ""),
            area=str(data.get("area") or ""),
            system=str(data.get("sys") or ""),
            refresh_token=str(data.get("refreshToken") or ""),
            corp_oauth=str(data.get("corpOAuth") or ""),
            qiye_token=str(data.get("qiyeToken") or ""),
            pass2fa=str(data.get("pass2fa") or ""),
            extras=extras,
        )
@dataclass(slots=True)
class WmsvrLoginContext:
    """Persisted + decrypted inputs now known to feed the login chain."""

    account: str = ""
    user: str = ""
    password: str = ""
    area: str = ""
    system: str = ""
    locale: str = DEFAULT_WMSVR_LOGIN_LOCALE
    config_id: str = ""
    app_version: str = ""
    appver_inner: int = 0
    device_id: str = ""
    fake_device_id: str = ""
    cloud_id: str = ""
    cloud_token: str = ""
    master_fp: str = ""
    master_sdid: str = ""
    webui_pub_key: str = ""
    device_info_json: str = ""
    peer_candidates: list[WmsvrPeerCandidate] = field(default_factory=list)

    @property
    def appver_inner_bytes(self) -> bytes:
        if self.appver_inner <= 0:
            return b""
        return struct.pack(">Q", self.appver_inner)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account": self.account,
            "user": self.user,
            "password": self.password,
            "area": self.area,
            "system": self.system,
            "locale": self.locale,
            "config_id": self.config_id,
            "app_version": self.app_version,
            "appver_inner": self.appver_inner,
            "device_id": self.device_id,
            "fake_device_id": self.fake_device_id,
            "cloud_id": self.cloud_id,
            "cloud_token": self.cloud_token,
            "master_fp": self.master_fp,
            "master_sdid": self.master_sdid,
            "webui_pub_key": self.webui_pub_key,
            "device_info_json": self.device_info_json,
            "peer_candidates": [
                {"host": peer.host, "port": peer.port, "is_ip_v6": peer.is_ip_v6}
                for peer in self.peer_candidates
            ],
        }


@dataclass(slots=True)
class WmsvrBootstrap:
    """Persisted no-Frida bootstrap material loaded from `app.db`."""

    cloud_info: WmsvrCloudInfo = field(default_factory=WmsvrCloudInfo)
    master_device_info: WmsvrMasterDeviceInfo = field(default_factory=WmsvrMasterDeviceInfo)
    master_fp: str = ""
    master_sdid: str = ""
    fake_device_id: str = ""
    webui_pub_key: str = ""
    cloud_info_ciphertext_b64: str = ""
    wzp_locate_addresses_b64: str = ""
    locate_entries: list[WmsvrLocateEntry] = field(default_factory=list)
    app_db_path: str = ""

    @classmethod
    def from_app_config(
        cls,
        app_config: Mapping[str, str | bytes],
        *,
        app_db_path: Path | None = None,
    ) -> WmsvrBootstrap:
        cloud_info_blob = app_config.get("CloudInfo")
        cloud_info_ciphertext_b64 = ""
        if isinstance(cloud_info_blob, bytes):
            cloud_info_ciphertext_b64 = base64.b64encode(cloud_info_blob).decode("ascii")

        locate_blob = app_config.get("WzpLocateAddresses")
        locate_blob_b64 = ""
        if isinstance(locate_blob, bytes):
            locate_blob_b64 = base64.b64encode(locate_blob).decode("ascii")
        elif isinstance(locate_blob, str):
            locate_blob_b64 = locate_blob

        return cls(
            cloud_info=parse_wmsvr_cloud_info(cloud_info_blob),
            master_device_info=parse_master_device_info(app_config.get("MasterDI")),
            master_fp=_as_text(app_config.get("MasterFP")),
            master_sdid=_as_text(app_config.get("MasterSdid")),
            fake_device_id=_as_text(app_config.get("FakeDeviceId")),
            webui_pub_key=_as_text(app_config.get("WebuiPubKey")),
            cloud_info_ciphertext_b64=cloud_info_ciphertext_b64,
            wzp_locate_addresses_b64=locate_blob_b64,
            locate_entries=parse_locate_cache(app_config.get("LocateCache")),
            app_db_path=str(app_db_path) if app_db_path is not None else "",
        )

    def get_locate_entries(
        self,
        *,
        account: str | None = None,
        service_types: Iterable[int] | None = None,
        include_global: bool = True,
    ) -> list[WmsvrLocateEntry]:
        """Return locate-cache entries filtered for an account and/or service types."""
        normalized = _normalize_account(account)
        wanted_service_types = {int(value) for value in service_types} if service_types is not None els
        matched: list[WmsvrLocateEntry] = []
        global_entries: list[WmsvrLocateEntry] = []
        for entry in self.locate_entries:
            if wanted_service_types is not None and entry.service_type not in wanted_service_types:
                continue
            if not normalized:
                matched.append(entry)
                continue
            if entry.matches_account(normalized):
                matched.append(entry)
            elif include_global and entry.is_global:
                global_entries.append(entry)
        return matched + global_entries

    def get_candidate_peers(
        self,
        *,
        account: str | None = None,
        service_types: Iterable[int] | None = None,
        include_global: bool = True,
    ) -> list[WmsvrPeerCandidate]:
        """Return deduplicated peer candidates from the filtered locate entries."""
        seen: set[tuple[str, int, bool]] = set()
        peers: list[WmsvrPeerCandidate] = []
        for entry in self.get_locate_entries(
            account=account,
            service_types=service_types,
            include_global=include_global,
        ):
            for candidate in entry.candidates:
                key = (candidate.host, candidate.port, candidate.is_ip_v6)
                if key in seen:
                    continue
                seen.add(key)
                peers.append(candidate)
        return peers

    def get_d1_candidate_peers(
        self,
        *,
        account: str | None = None,
        include_global: bool = True,
    ) -> list[WmsvrPeerCandidate]:
        return self.get_candidate_peers(
            account=account,
            service_types=[WMSVR_SERVICE_TYPE_D1],
            include_global=include_global,
        )


@dataclass(slots=True)
class WmsvrLoginStaticHints:
    """Static login/auth hints extracted from the installed `mastercore.dll`."""

    source_dll: str = ""
    login_methods: list[str] = field(default_factory=list)
    login_request_fields: list[str] = field(default_factory=list)
    auth_response_fields: list[str] = field(default_factory=list)
    jsbridge_methods: list[str] = field(default_factory=list)
    http_auth_types: list[str] = field(default_factory=list)
    endpoint_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_dll": self.source_dll,
            "login_methods": self.login_methods,
            "login_request_fields": self.login_request_fields,
            "auth_response_fields": self.auth_response_fields,
            "jsbridge_methods": self.jsbridge_methods,
            "http_auth_types": self.http_auth_types,
            "endpoint_hints": self.endpoint_hints,
        }


@dataclass(slots=True)
class WmsvrCookieHint:
    """Relevant Chromium cookie metadata discovered on disk."""

    name: str = ""
    value_len: int = 0
    encrypted_len: int = 0
    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "name": self.name,
            "value_len": self.value_len,
            "encrypted_len": self.encrypted_len,
        }
@dataclass(slots=True)
class WmsvrRuntimeArtifactHit:
    """One runtime-storage/cache hit related to Wmsvr auth/session discovery."""
    source: str = ""
    path: str = ""
    term: str = ""
    snippet: str = ""
    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "path": self.path,
            "term": self.term,
            "snippet": self.snippet,
        }

@dataclass(slots=True)
class WmsvrWebRuntimeState:
    """Structured snapshot of on-disk Chromium web state relevant to Wmsvr auth."""

    source_root: str = ""
    snapshot_root: str = ""
    cookie_hints: list[WmsvrCookieHint] = field(default_factory=list)
    relevant_servers: list[str] = field(default_factory=list)
    hits: list[WmsvrRuntimeArtifactHit] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_root": self.source_root,
            "snapshot_root": self.snapshot_root,
            "cookie_hints": [item.to_dict() for item in self.cookie_hints],
            "relevant_servers": self.relevant_servers,
            "hits": [item.to_dict() for item in self.hits],
        }


@dataclass(slots=True)
class WmsvrAuthSurface:
    """Combined static + runtime auth/session discovery surface."""

    static_hints: WmsvrLoginStaticHints = field(default_factory=WmsvrLoginStaticHints)
    web_runtime_state: WmsvrWebRuntimeState = field(default_factory=WmsvrWebRuntimeState)

    def to_dict(self) -> dict[str, Any]:
        return {
            "static_hints": self.static_hints.to_dict(),
            "web_runtime_state": self.web_runtime_state.to_dict(),
        }


@dataclass(slots=True)
class WmsvrInitSessionResult:
    """Response from the observed `config.dashi.163.com /init/session` refresh."""

    status_code: int = 0
    http_version: str = ""
    code: int = 0
    desc: str = ""
    success: bool = False
    token: str = ""
    token_refresh_interval: int = 0
    raw_payload: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status_code == 200 and self.success and bool(self.token)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "http_version": self.http_version,
            "code": self.code,
            "desc": self.desc,
            "success": self.success,
            "token": self.token,
            "token_refresh_interval": self.token_refresh_interval,
            "raw_payload": self.raw_payload,
        }


def _copy_sqlite_for_read(path: Path) -> Path:
    temp_dir = Path(tempfile.gettempdir()) / "mailmaster"
    temp_dir.mkdir(parents=True, exist_ok=True)
    digest = sha1(str(path).encode("utf-8")).hexdigest()[:10]
    target = temp_dir / f"{digest}_{path.name}"
    shutil.copy2(path, target)
    return target


def _connect_sqlite(path: Path, *, as_bytes: bool = False) -> sqlite3.Connection:
    connection = sqlite3.connect(_copy_sqlite_for_read(path))
    if as_bytes:
        connection.text_factory = bytes
    return connection


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _normalize_account(value: str | None) -> str:
    return str(value or "").strip().lower()


def load_wmsvr_app_config(
    app_db: Path,
    *,
    keys: Iterable[str] | None = None,
) -> dict[str, str | bytes]:
    """Read Wmsvr-relevant app-level config values from `app.db`."""
    app_db = Path(app_db)
    if not app_db.exists():
        raise FileNotFoundError(f"MailMaster app db not found: {app_db}")

    wanted_keys = tuple(dict.fromkeys(keys or DEFAULT_WMSVR_APP_CONFIG_KEYS))
    if not wanted_keys:
        return {}

    placeholders = ", ".join("?" for _ in wanted_keys)
    with _connect_sqlite(app_db, as_bytes=True) as conn:
        rows = conn.execute(
            f"SELECT Key, Value FROM AppConfig WHERE Key IN ({placeholders})",
            wanted_keys,
        ).fetchall()

    config: dict[str, str | bytes] = {}
    for raw_key, raw_value in rows:
        key = _as_text(raw_key)
        if key in {"CloudInfo", "WzpLocateAddresses"} and isinstance(raw_value, bytes):
            config[key] = raw_value
        else:
            config[key] = _as_text(raw_value)
    return config


def parse_master_device_info(raw_value: str | bytes | Mapping[str, Any] | None) -> WmsvrMasterDeviceInf
    """Parse the persisted `MasterDI` JSON blob."""
    if raw_value in (None, "", b""):
        return WmsvrMasterDeviceInfo()
    if isinstance(raw_value, Mapping):
        return WmsvrMasterDeviceInfo.from_mapping(cast(Mapping[str, Any], raw_value))
    try:
        payload = json.loads(_as_text(raw_value))
    except json.JSONDecodeError:
        return WmsvrMasterDeviceInfo()
    if not isinstance(payload, Mapping):
        return WmsvrMasterDeviceInfo()
    return WmsvrMasterDeviceInfo.from_mapping(payload)


def parse_wmsvr_cloud_info(
    raw_value: str | bytes | Mapping[str, Any] | None,
    *,
    install_root: Path | None = None,
) -> WmsvrCloudInfo:
    """Parse the persisted `CloudInfo` blob, including runtime-password decryption."""
    if raw_value in (None, "", b""):
        return WmsvrCloudInfo()
    payload: object
    if isinstance(raw_value, Mapping):
        payload = raw_value
    elif isinstance(raw_value, bytes):
            payload = json.loads(decrypt_runtime_protected_blob(raw_value, install_root).decode("utf-8"
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return WmsvrCloudInfo()
    else:
        try:
            payload = json.loads(_as_text(raw_value))
        except json.JSONDecodeError:
            return WmsvrCloudInfo()
    if not isinstance(payload, Mapping):
        return WmsvrCloudInfo()
    return WmsvrCloudInfo.from_mapping(cast(Mapping[str, Any], payload))
def parse_wmsvr_account_config(raw_value: Mapping[str, Any] | None) -> WmsvrAccountConfig:
    """Parse the decrypted `WmsvrServerConfig` mapping."""
    if raw_value is None:
        return WmsvrAccountConfig()
    return WmsvrAccountConfig.from_mapping(raw_value)
def app_version_to_inner(app_version: str) -> int:
    """Convert `5.5.2.1006`-style version text into the observed appverInner integer.
    Current build mapping is inferred from the confirmed live singleton pair:
    `5.5.2.1006 -> 50050021006`.
    numbers = [int(part) for part in _re.findall(r"\d+", app_version)]
    if len(numbers) < 4:
        return 0
    major, minor, patch, build = numbers[:4]
    return int(f"{major}{minor:03d}{patch:03d}{build:04d}")
def parse_locate_cache(raw_value: str | bytes | list[object] | None) -> list[WmsvrLocateEntry]:
    """Parse the persisted `LocateCache` JSON blob."""
    if raw_value in (None, "", b""):
        return []
    payload: object
    if isinstance(raw_value, list):
        payload = raw_value
    else:
            payload = json.loads(_as_text(raw_value))
        except json.JSONDecodeError:
            return []
    if not isinstance(payload, list):
        return []
    entries: list[WmsvrLocateEntry] = []
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        item_mapping = cast(Mapping[str, Any], item)
        locate_id_raw = item_mapping.get("locate_id")
        service_cache_raw = item_mapping.get("service_cache")
        if not isinstance(locate_id_raw, Mapping) or not isinstance(service_cache_raw, Mapping):
            continue
        locate_id = WmsvrLocateId(
            service_type=int(locate_id_raw.get("service_type") or 0),
            user=str(locate_id_raw.get("user") or ""),
            locate_user=str(locate_id_raw.get("locate_user") or ""),
        )
        candidates: list[WmsvrPeerCandidate] = []
        raw_candidates = service_cache_raw.get("candidates")
        if isinstance(raw_candidates, list):
            for raw_candidate in raw_candidates:
                if not isinstance(raw_candidate, Mapping):
                    continue
                host = str(raw_candidate.get("host") or "").strip()
                port = int(raw_candidate.get("port") or 0)
                if not host or port <= 0:
                    continue
                candidates.append(
                    WmsvrPeerCandidate(
                        host=host,
                        port=port,
                        is_ip_v6=bool(raw_candidate.get("is_ip_v6")),
                    )
                )
        entries.append(
            WmsvrLocateEntry(
                locate_id=locate_id,
                candidates=candidates,
                prefer_ipv6=bool(service_cache_raw.get("prefer_ipv6")),
            )
        )
    return entries


def load_wmsvr_bootstrap(app_db: Path) -> WmsvrBootstrap:
    """Load persisted no-Frida Wmsvr bootstrap material from `app.db`."""
    app_db = Path(app_db)
    return WmsvrBootstrap.from_app_config(load_wmsvr_app_config(app_db), app_db_path=app_db)


def build_wmsvr_login_context(
    account: str,
    server_configs: Mapping[str, Mapping[str, Any]],
    bootstrap: WmsvrBootstrap,
    *,
    locale: str = DEFAULT_WMSVR_LOGIN_LOCALE,
) -> WmsvrLoginContext:
    """Combine persisted bootstrap + decrypted Wmsvr config into login inputs."""
    wmsvr_raw = server_configs.get("WmsvrServerConfig")
    if not isinstance(wmsvr_raw, Mapping):
        raise ValueError(f"No WmsvrServerConfig found for {account}.")

    config = parse_wmsvr_account_config(wmsvr_raw)
    resolved_account = config.user or account
    config_id = bootstrap.master_device_info.config_id or "10"
    app_version = bootstrap.master_device_info.app_version
    device_id = bootstrap.master_device_info.device_id or bootstrap.fake_device_id
    peer_candidates = bootstrap.get_d1_candidate_peers(account=resolved_account)

    return WmsvrLoginContext(
        account=resolved_account,
        user=config.user or resolved_account,
        password=config.password,
        area=config.area,
        system=config.system,
        locale=locale,
        config_id=config_id,
        app_version=app_version,
        appver_inner=app_version_to_inner(app_version),
        device_id=device_id,
        fake_device_id=bootstrap.fake_device_id,
        cloud_id=bootstrap.cloud_info.cloud_id,
        cloud_token=bootstrap.cloud_info.cloud_token,
        master_fp=bootstrap.master_fp,
        master_sdid=bootstrap.master_sdid,
        webui_pub_key=bootstrap.webui_pub_key,
        device_info_json=bootstrap.master_device_info.to_json(),
        peer_candidates=peer_candidates,
    )


def _iter_wmsvr_mastercore_candidates(install_root: Path | None = None) -> list[Path]:
    resolved_install_root = Path(install_root) if install_root is not None else discover_paths().instal
    if resolved_install_root is None or not resolved_install_root.exists():
        return []
    return sorted(
        resolved_install_root.rglob("mastercore.dll"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def _select_present_terms(blob: bytes, terms: Iterable[str]) -> list[str]:
    return [term for term in terms if term.encode("utf-8") in blob]


def _resolve_wmsvr_web_cache_root(local_root: Path | None = None) -> Path:
    resolved_local_root = Path(local_root) if local_root is not None else discover_paths().local_root
    return resolved_local_root / "web" / "cache"


def _copy_path_best_effort(source: Path, destination: Path) -> None:
    if source.is_dir():
        for child in source.rglob("*"):
            relative = child.relative_to(source)
            target = destination / relative
            if child.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(child, target)
            except OSError:
                continue
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(source, destination)
    except OSError:
        return


def _snapshot_wmsvr_web_cache_root(web_cache_root: Path) -> Path:
    temp_root = (
        Path(tempfile.gettempdir())
        / "mailmaster"
        / f"webcache_{sha1(str(web_cache_root).encode('utf-8')).hexdigest()[:10]}"
    )
    if temp_root.exists():
        shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True, exist_ok=True)
    for relative in (
        Path("Cookies"),
        Path("Network Persistent State"),
        Path("Cache") / "data_3",
        Path("Local Storage") / "leveldb",
        Path("Session Storage"),
    ):
        source = web_cache_root / relative
        if source.exists():
            _copy_path_best_effort(source, temp_root / relative)
    return temp_root


def _ascii_window_text(blob: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else " " for byte in blob)


def _redact_wmsvr_snippet(snippet: str, *, include_values: bool) -> str:
    cleaned = _re.sub(r"\s+", " ", snippet.replace("\x00", " ")).strip()
    if include_values:
        return cleaned[:240]
    cleaned = _re.sub(r'((?:mastersess|mixmailtokens|masterfp|masterdi|sdid)\s*[:=]\s*)([A-Za-z0-9%+/_=
    cleaned = _re.sub(r'((?:authToken|coremailToken|mixmailToken|refreshToken)\s*[:=]\s*)([A-Za-z0-9%+/
    cleaned = _re.sub(r'((?:mastersess|mixmailtokens|masterfp|masterdi|sdid|authToken|coremailToken|mix
    return cleaned[:240]


def _scan_binary_file_for_terms(
    path: Path,
    *,
    source: str,
    terms: Iterable[str],
    include_values: bool = False,
    limit_per_file: int = 16,
) -> list[WmsvrRuntimeArtifactHit]:
    try:
        blob = path.read_bytes()
    except OSError:
        return []

    hits: list[WmsvrRuntimeArtifactHit] = []
    seen: set[tuple[str, str]] = set()
    for term in terms:
        encoded = term.encode("utf-8")
        start = 0
        while len(hits) < limit_per_file:
            index = blob.find(encoded, start)
            if index < 0:
                break
            window = blob[max(0, index - 96) : min(len(blob), index + len(encoded) + 160)]
            snippet = _redact_wmsvr_snippet(_ascii_window_text(window), include_values=include_values)
            key = (term, snippet)
            if key not in seen:
                seen.add(key)
                hits.append(
                    WmsvrRuntimeArtifactHit(
                        source=source,
                        path=str(path),
                        term=term,
                        snippet=snippet,
                    )
                )
            start = index + len(encoded)
    return hits


def _load_relevant_cookie_hints(cookies_path: Path) -> list[WmsvrCookieHint]:
    if not cookies_path.exists():
        return []
    try:
        with sqlite3.connect(cookies_path) as conn:
            rows = conn.execute(
                """
                SELECT host_key, name, LENGTH(value), LENGTH(encrypted_value)
                FROM cookies
                WHERE host_key LIKE '%163.com%' OR host_key LIKE '%127.net%' OR host_key LIKE '%netease
                ORDER BY host_key, name
                """
            ).fetchall()
    except sqlite3.Error:
        return []
    return [
        WmsvrCookieHint(
            host=str(host or ""),
            name=str(name or ""),
            value_len=int(value_len or 0),
            encrypted_len=int(encrypted_len or 0),
        )
        for host, name, value_len, encrypted_len in rows
    ]


def _load_relevant_network_servers(state_path: Path) -> list[str]:
    if not state_path.exists():
        return []
    try:
        payload = json.loads(state_path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []
    raw_servers = payload.get("net", {}).get("http_server_properties", {}).get("servers", [])
    if not isinstance(raw_servers, list):
        return []
    servers = {
        str(item.get("server") or "")
        for item in raw_servers
        if isinstance(item, Mapping)
        and any(term in str(item.get("server") or "") for term in ("mail.163.com", "dashi.163.com", "12
    }
    return sorted(server for server in servers if server)


def discover_wmsvr_login_static_hints(install_root: Path | None = None) -> WmsvrLoginStaticHints:
    """Scan the installed `mastercore.dll` for confirmed login/auth string hints."""
    for dll_path in _iter_wmsvr_mastercore_candidates(install_root):
            blob = dll_path.read_bytes()
        except OSError:
            continue
        return WmsvrLoginStaticHints(
            source_dll=str(dll_path),
            login_methods=_select_present_terms(blob, WMSVR_STATIC_LOGIN_METHOD_TERMS),
            login_request_fields=_select_present_terms(blob, WMSVR_STATIC_LOGIN_REQUEST_FIELD_TERMS),
            auth_response_fields=_select_present_terms(blob, WMSVR_STATIC_AUTH_RESPONSE_FIELD_TERMS),
            jsbridge_methods=_select_present_terms(blob, WMSVR_STATIC_JSBRIDGE_METHOD_TERMS),
            http_auth_types=_select_present_terms(blob, WMSVR_STATIC_HTTP_AUTH_TYPE_TERMS),
            endpoint_hints=_select_present_terms(blob, WMSVR_STATIC_ENDPOINT_HINT_TERMS),
        )
    return WmsvrLoginStaticHints()
def discover_wmsvr_web_runtime_state(
    local_root: Path | None = None,
    *,
    include_values: bool = False,
) -> WmsvrWebRuntimeState:
    """Snapshot and scan MailMaster Chromium cache/storage for Wmsvr auth traces."""
    web_cache_root = _resolve_wmsvr_web_cache_root(local_root)
    if not web_cache_root.exists():
        return WmsvrWebRuntimeState(source_root=str(web_cache_root))
    snapshot_root = _snapshot_wmsvr_web_cache_root(web_cache_root)
    runtime_state = WmsvrWebRuntimeState(
        source_root=str(web_cache_root),
        snapshot_root=str(snapshot_root),
    )
    runtime_state.cookie_hints = _load_relevant_cookie_hints(snapshot_root / "Cookies")
    runtime_state.relevant_servers = _load_relevant_network_servers(snapshot_root / "Network Persistent
    files_to_scan: list[tuple[str, Path]] = [
        ("cache", snapshot_root / "Cache" / "data_3"),
        ("local_storage", snapshot_root / "Local Storage" / "leveldb" / "000003.log"),
        ("session_storage", snapshot_root / "Session Storage" / "000003.log"),
    ]
    hits: list[WmsvrRuntimeArtifactHit] = []
    for source, path in files_to_scan:
        if path.exists():
            hits.extend(
                _scan_binary_file_for_terms(
                    path,
                    source=source,
                    terms=WMSVR_RUNTIME_SEARCH_TERMS,
                    include_values=include_values,
                )
            )
    runtime_state.hits = hits
    return runtime_state
def inspect_wmsvr_auth_surface(
    *,
    install_root: Path | None = None,
    local_root: Path | None = None,
    include_values: bool = False,
) -> WmsvrAuthSurface:
    """Return the current static + runtime auth/session discovery surface."""
    return WmsvrAuthSurface(
        static_hints=discover_wmsvr_login_static_hints(install_root),
        web_runtime_state=discover_wmsvr_web_runtime_state(local_root, include_values=include_values),
    )
def _as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")
def _as_login_value(value: bytes | str | None) -> bytes:
    return _as_bytes(value)


def _build_wmsvr_runtime_tail_records(
    *,
    ticket: str = "",
    trace_id: str = "",
    device_info_json: str = "",
    client_id: str = "",
) -> list[tuple[int, bytes]]:
    records: list[tuple[int, bytes]] = []
    if ticket:
        records.append((TAG_TICKET, ticket.encode("utf-8")))
    if trace_id:
        records.append((TAG_TRACE_ID, trace_id.encode("utf-8")))
    if device_info_json:
        records.append((TAG_DEVICE_INFO, device_info_json.encode("utf-8")))
    if client_id:
        records.append((TAG_CLIENT_ID, client_id.encode("utf-8")))
    return records


def build_wmsvr_runtime_tail_records(session: WmsvrSession) -> list[tuple[int, bytes]]:
    """Build the shared runtime tail used by normal and startup-family requests."""
    return _build_wmsvr_runtime_tail_records(
        ticket=session.ticket,
        trace_id=session.trace_id,
        device_info_json=session.device_info,
        client_id=session.client_id,
def build_wmsvr_startup_tlv(payload: WmsvrStartupPayload) -> bytes:
    """Build one canonical startup-family TLV slice from observed field semantics."""
    return payload.to_bytes()


def parse_wmsvr_startup_tlv(data: bytes) -> WmsvrStartupPayload:
    """Parse a startup-family TLV slice into a structured payload model."""
    payload = WmsvrStartupPayload()
    extras: list[tuple[int, bytes]] = []
    for tag, value in decode_tlv_envelope(data):
        if tag == STARTUP_TAG_METHOD:
            payload.method = value.decode("utf-8")
        elif tag == STARTUP_TAG_OPAQUE_TOKEN:
            payload.opaque_token = value
        elif tag == STARTUP_TAG_NONCE_HEX:
            payload.nonce_hex = value.decode("utf-8")
        elif tag == STARTUP_TAG_STARTUP_FLAG:
            payload.startup_flag = value
        elif tag == STARTUP_TAG_UNIX_TIME:
            payload.timestamp = value.decode("utf-8")
        elif tag == STARTUP_TAG_DEVICE_ID:
            payload.device_id = value.decode("utf-8")
        elif tag == STARTUP_TAG_APPVER_INNER:
            payload.appver_inner = value.decode("utf-8")
        elif tag == STARTUP_TAG_CONFIG_ID:
            payload.config_id = value.decode("utf-8")
        elif tag == STARTUP_TAG_RESPONSE_FORMAT:
            payload.response_format = value
        elif tag == STARTUP_TAG_MODE:
            payload.mode = value
        elif tag == TAG_TICKET:
            payload.ticket = value.decode("utf-8")
        elif tag == TAG_TRACE_ID:
            payload.trace_id = value.decode("utf-8")
        elif tag == TAG_DEVICE_INFO:
            payload.device_info_json = value.decode("utf-8")
        elif tag == TAG_CLIENT_ID:
            payload.client_id = value.decode("utf-8")
        else:
            extras.append((tag, value))
    payload.extra_records = extras
    return payload


def build_wmsvr_control_tlv(payload: WmsvrControlPayload) -> bytes:
    """Build one canonical control-family TLV slice from observed field semantics."""
    return payload.to_bytes()


def parse_wmsvr_control_tlv(data: bytes) -> WmsvrControlPayload:
    """Parse a control-family TLV slice into a structured payload model."""
    payload = WmsvrControlPayload()
    extras: list[tuple[int, bytes]] = []
    for tag, value in decode_tlv_envelope(data):
        if tag == CONTROL_TAG_MODE:
            payload.mode = value
        elif tag == CONTROL_TAG_CONTROL_ID:
            payload.control_id_hex = value.decode("utf-8")
        elif tag == CONTROL_TAG_UNIX_TIME:
            payload.timestamp = value.decode("utf-8")
        elif tag == TAG_TICKET:
            payload.ticket = value.decode("utf-8")
        elif tag == TAG_TRACE_ID:
            payload.trace_id = value.decode("utf-8")
        elif tag == TAG_DEVICE_INFO:
            payload.device_info_json = value.decode("utf-8")
        elif tag == TAG_CLIENT_ID:
            payload.client_id = value.decode("utf-8")
        else:
            extras.append((tag, value))
    payload.extra_records = extras
    return payload


def build_loginone_payload(
    tag_107: bytes | str | None = None,
    locale: str | None = None,
) -> WmsvrLoginPayload:
    """Build the current capture-confirmed `wzpa:loginone` TLV payload."""
    resolved_locale = locale or context.locale or DEFAULT_WMSVR_LOGIN_LOCALE
    records: list[tuple[int, bytes]] = [
        (LOGIN_TAG_METHOD, LOGIN_METHOD_LOGINONE.encode("utf-8")),
    ]
    if context.device_id:
        records.append((LOGIN_TAG_DEVICE_ID, context.device_id.encode("utf-8")))
    if context.config_id:
        records.append((LOGIN_TAG_CONFIG_ID, context.config_id.encode("utf-8")))
    if context.app_version:
        records.append((LOGIN_TAG_APP_VERSION, context.app_version.encode("utf-8")))
    optional_107 = _as_login_value(tag_107)
    if optional_107:
        records.append((LOGIN_TAG_OPTIONAL_107, optional_107))
    if resolved_locale:
        records.append((LOGIN_TAG_HARDCODED_LOCALE, resolved_locale.encode("utf-8")))
    return WmsvrLoginPayload(method=LOGIN_METHOD_LOGINONE, records=records)
def build_masterdevice_payload(
    context: WmsvrLoginContext,
    *,
    locale: str | None = None,
) -> WmsvrLoginPayload:
    """Build the current capture-confirmed `wzpmmc:masterdevice` TLV payload."""
    records: list[tuple[int, bytes]] = [
        (LOGIN_TAG_METHOD, LOGIN_METHOD_MASTERDEVICE.encode("utf-8")),
    ]
    if context.device_id:
        records.append((LOGIN_TAG_DEVICE_ID, context.device_id.encode("utf-8")))
    if context.appver_inner_bytes:
        records.append((LOGIN_TAG_APP_VERSION, context.appver_inner_bytes))
    if context.config_id:
        records.append((LOGIN_TAG_CONFIG_ID, context.config_id.encode("utf-8")))
    return WmsvrLoginPayload(method=LOGIN_METHOD_MASTERDEVICE, records=records)

def build_wmsvr_login_tlv(
    payload: WmsvrLoginPayload,
    *,
    ticket: str = "",
    trace_id: str = "",
    device_info_json: str = "",
    client_id: str = "",
) -> bytes:
    """Build one full login-family TLV segment with runtime tail records."""
    records = list(payload.records)
    records.extend(
        _build_wmsvr_runtime_tail_records(
            ticket=ticket,
            trace_id=trace_id,
            device_info_json=device_info_json,
            client_id=client_id,
        )
    )
    return encode_tlv_envelope(records)


def build_wmsvr_login_segment(
    payload: WmsvrLoginPayload,
    *,
    ticket: str = "",
    trace_id: str = "",
    device_info_json: str = "",
    client_id: str = "",
    include_d1_control: bool = False,
    key_version: int = DEFAULT_D1_KEY_VERSION,
    key_digest: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
) -> bytes:
    """Build one capture-shaped login-family segment.

    The real startup burst sometimes prefixes login-family TLVs with the same
    `0x0001/0x0002` d1 control material used by startup-family requests.
    segment = build_wmsvr_login_tlv(
        ticket=ticket,
        trace_id=trace_id,
        device_info_json=device_info_json,
        client_id=client_id,
    if not include_d1_control:
        return segment
    control = build_wmsvr_d1_control_tlv(
        WmsvrD1RequestContext(
            key_version=key_version,
            key_digest16=key_digest,
        )
    )
    return control + segment
# ---------------------------------------------------------------------------
# d1 request bootstrap + crypto
# ---------------------------------------------------------------------------
D1_CONTROL_TAG_KEY_VERSION = 0x0001
D1_CONTROL_TAG_KEY_DIGEST = 0x0002
D1_CONTROL_TAG_MASTER_FP = 0x0113
D1_CONTROL_TAG_MASTER_SDID = 0x0115
D1_CONTROL_TAG_DEVICE_INFO = 0x0114


def build_wmsvr_d1_request_context(
    login_context: WmsvrLoginContext,
    *,
    key_version: int = DEFAULT_D1_KEY_VERSION,
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    session_key: bytes = b"",
    word2: int = DEFAULT_D1_RPC_WORD2,
    word4: int = DEFAULT_D1_RPC_WORD4,
) -> WmsvrD1RequestContext:
    """Build the low-level d1 request context from login/bootstrap material."""
    return WmsvrD1RequestContext(
        master_fp=login_context.master_fp,
        master_sdid=login_context.master_sdid,
        device_info_json=login_context.device_info_json,
        word2=word2,
        word4=word4,
def build_wmsvr_d1_control_tlv(context: WmsvrD1RequestContext) -> bytes:
    """Build the confirmed `AB74A0` control-material prefix.
    Static + wire evidence currently supports only:
    - `0x0001 = key_version (u32be)`
    - `0x0002 = key_digest32`

    Session/runtime tags like `0x0113/0x0115/0x0114/0x0014` belong to the
    outer Wmsvr envelope or special bootstrap request families, not to this
    low-level control prefix itself.
    """
    return encode_tlv_envelope(
        [
            (D1_CONTROL_TAG_KEY_VERSION, struct.pack(">I", context.key_version & 0xFFFFFFFF)),
            (D1_CONTROL_TAG_KEY_DIGEST, context.key_digest32),
        ]
    )


def generate_wmsvr_d1_session_key() -> bytes:
    """Generate the client-side 16-byte AES key stored at `session+0x44`."""
    return os.urandom(16)


def _require_wmsvr_d1_session_key(session_key: bytes) -> bytes:
    if len(session_key) != 16:
        raise ValueError(f"Wmsvr d1 session key must be 16 bytes, got {len(session_key)}")
    return session_key


def _coerce_wmsvr_public_key(
    public_key: WmsvrHardcodedPublicKey | rsa.RSAPublicKey | bytes | str,
) -> rsa.RSAPublicKey:
    if isinstance(public_key, WmsvrHardcodedPublicKey):
        key_data: bytes | str = public_key.pem
    else:
        key_data = public_key
    if isinstance(key_data, rsa.RSAPublicKey):
        return key_data

    raw = key_data.encode("utf-8") if isinstance(key_data, str) else key_data
    if b"-----BEGIN PUBLIC KEY-----" in raw:
        loaded = serialization.load_pem_public_key(raw)
    else:
        loaded = serialization.load_der_public_key(raw)
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return loaded


def wrap_wmsvr_d1_session_key(
    session_key: bytes,
    public_key: WmsvrHardcodedPublicKey | rsa.RSAPublicKey | bytes | str,
) -> bytes:
    """Wrap the 16-byte d1 session key with the current Wmsvr public key.

    This follows the confirmed outbound path:
    `AB5510 -> ... -> PKCS#1 v1.5 type-2 public-key encryption`.
    """
    key = _require_wmsvr_d1_session_key(session_key)
    rsa_public_key = _coerce_wmsvr_public_key(public_key)
    return rsa_public_key.encrypt(key, padding.PKCS1v15())


def encrypt_wmsvr_d1_slice(data: bytes, session_key: bytes) -> bytes:
    """Encrypt one aligned payload slice with the confirmed AES-128-CBC transform."""
    key = _require_wmsvr_d1_session_key(session_key)
    if len(data) % 16 != 0:
        raise ValueError("Wmsvr d1 slice length must already be 16-byte aligned before encryption.")
    if not data:
        return b""
    encryptor = Cipher(algorithms.AES(key), modes.CBC(DEFAULT_D1_AES_IV)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def decrypt_wmsvr_d1_slice(data: bytes, session_key: bytes) -> bytes:
    """Decrypt one aligned payload slice with the confirmed AES-128-CBC transform."""
    key = _require_wmsvr_d1_session_key(session_key)
    if len(data) % 16 != 0:
        raise ValueError("Wmsvr d1 slice length must be a multiple of 16 bytes.")
    if not data:
        return b""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(DEFAULT_D1_AES_IV)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def build_wmsvr_d1_encrypted_frame(
    slice0: bytes,
    *,
    session_key: bytes,
    slice1_bytes: bytes = b"",
    body_bytes: bytes | None = None,
    seq: int = 1,
    word2: int = DEFAULT_D1_RPC_WORD2,
    word4: int = DEFAULT_D1_RPC_WORD4,
    word0: int | None = None,
) -> WmsvrD1Frame:
    """Build one raw encrypted d1 frame from already-encoded plaintext slices.

    For normal RPC traffic:
    - `slice0` = control-prefix + outer TLV envelope
    - `slice1` = JSON body bytes (if present)

    For special bootstrap/control packets:
    - `slice1` may be opaque binary, not JSON.
    """
    if body_bytes is not None and slice1_bytes:
        raise ValueError("Pass either `slice1_bytes` or `body_bytes`, not both.")
    resolved_slice1 = body_bytes if body_bytes is not None else slice1_bytes
    layout = build_d1_slice_layout(slice0, resolved_slice1)
    encrypted_slice0 = encrypt_wmsvr_d1_slice(layout.padded_slice0, session_key)
    encrypted_slice1 = (
        encrypt_wmsvr_d1_slice(layout.padded_slice1, session_key)
        if layout.padded_slice1
        else b""
    )
    resolved_word0 = word0 if word0 is not None else (0xB000 if encrypted_slice1 else 0xA000)
    if bool(resolved_word0 & D1_WORD0_HAS_LEN1) != bool(encrypted_slice1):
        raise ValueError("Provided `word0` does not match the presence of slice1.")
    return WmsvrD1Frame(
        header=WmsvrD1Header(
            word0=resolved_word0,
            word2=word2,
            word4=word4,
            seq=seq,
            len0=layout.slice0_len,
            len1=layout.slice1_len if encrypted_slice1 else None,
        ),
        slice0=encrypted_slice0,
        slice1=encrypted_slice1,
    )


def decrypt_wmsvr_d1_frame_slices(
    frame: WmsvrD1Frame,
    session_key: bytes,
) -> tuple[bytes, bytes]:
    """Decrypt the payload slices of one already-parsed encrypted d1 frame."""
    return (
        decrypt_wmsvr_d1_slice(frame.slice0, session_key),
        decrypt_wmsvr_d1_slice(frame.slice1, session_key) if frame.slice1 else b"",
    )


def build_wmsvr_d1_request_frame(
    context: WmsvrD1RequestContext,
    session: WmsvrSession,
    method: str,
    *,
    body: dict[str, Any] | None = None,
    seq: int = 1,
) -> WmsvrD1Frame:
    """Build a raw encrypted d1 request from bootstrap prefix + Wmsvr envelope + JSON body."""
    request = build_request(session, method, body)
    envelope = build_wmsvr_d1_control_tlv(context) + request.envelope
    session_key = context.session_key or generate_wmsvr_d1_session_key()
    return build_wmsvr_d1_encrypted_frame(
        envelope,
        slice1_bytes=request.body_json.encode("utf-8"),
        seq=seq,
        word2=context.word2,
        word4=context.word4,
# ---------------------------------------------------------------------------
# Request builder
# ---------------------------------------------------------------------------
def build_envelope(session: WmsvrSession, method: str) -> bytes:
    """Build the TLV envelope for a Wmsvr request."""
    records: list[tuple[int, bytes]] = [
        (TAG_VERSION, b"\x00\x00\x00\x01"),
        (TAG_METHOD, method.encode("utf-8")),
    ]
    if session.token:
        records.append((TAG_TOKEN, session.token.encode("utf-8")))
    if session.route:
        records.append((TAG_ROUTE, session.route.encode("utf-8")))
    if session.host:
        records.append((TAG_HOST, session.host.encode("utf-8")))
    if session.port:
        records.append((TAG_PORT, struct.pack(">H", session.port)))
    if session.account_desc:
        records.append((TAG_ACCOUNT, session.account_desc.encode("utf-8")))
    records.extend(build_wmsvr_runtime_tail_records(session))
    return encode_tlv_envelope(records)


def build_request(
    session: WmsvrSession,
    method: str,
    body: dict[str, Any] | None,
) -> WmsvrRequest:
    """Build a complete Wmsvr request with TLV envelope and JSON body."""
    body_json = "" if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    envelope = build_envelope(session, method)
    return WmsvrRequest(
        method=method,
        body_json=body_json,
        envelope=envelope,
        session=session,
    )


def align16(data: bytes) -> bytes:
    """Pad data with NUL bytes up to the next 16-byte boundary."""
    return data + (b"\x00" * ((16 - (len(data) % 16)) % 16))


def build_d1_slice_layout(slice0: bytes, slice1: bytes = b"") -> WmsvrD1PlainLayout:
    """Build the confirmed plaintext layout for one outbound d1 frame.

    The request path carries two independently sized plaintext slices:
    - `slice0`: usually control-prefix + TLV envelope
    - `slice1`: usually JSON body, but may be opaque binary on bootstrap paths
    """
    padded_envelope = align16(slice0)
    padded_json = align16(slice1) if slice1 else b""
    body_prefix = encode_leb128(len(padded_json)) if padded_json else b""
    return WmsvrD1PlainLayout(
        section_len=len(padded_envelope),
        padded_json_len=len(padded_json),
        body_prefix=body_prefix,
        padded_envelope=padded_envelope,
        padded_json=padded_json,
    )


def build_d1_plain_layout(envelope: bytes, body_bytes: bytes) -> WmsvrD1PlainLayout:
    """Backward-compatible wrapper for normal `TLV + JSON` request bodies."""
    return build_d1_slice_layout(envelope, body_bytes)


def normalize_d1_key_digest(digest: bytes) -> bytes:
    """Normalize a GET_SETTINGS key digest to the observed 32-byte wire format."""
    if len(digest) == 16:
        return digest + (b"\x00" * 16)
    if len(digest) == 32:
        return digest
    raise ValueError(f"D1 key digest must be 16 or 32 bytes, got {len(digest)}")


def build_get_settings_tlv(
    *,
    version: int = DEFAULT_D1_KEY_VERSION,
    digest: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
) -> bytes:
    """Build the confirmed plaintext TLV slice for d1 `GET_SETTINGS`."""
    records = [
        (0x0001, struct.pack(">I", version & 0xFFFFFFFF)),
        (0x0002, normalize_d1_key_digest(digest)),
    ]
    return encode_tlv_envelope(records)


def build_get_settings_frame(
    *,
    version: int = DEFAULT_D1_KEY_VERSION,
    digest: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    seq: int = 0,
    signature: bytes = DEFAULT_D1_GET_SETTINGS_SIGNATURE,
) -> WmsvrD1Frame:
    """Build the currently confirmed raw d1 `GET_SETTINGS` frame.

    Current confirmed shape:
    - `word0 = 0x3000`
    - `word4 = 0x000a`
    - `word2 = 0x0000`
    - `seq = 0` in captured baseline
    - `slice0 = TLV(version, digest32)`
    - `slice1 = 128-byte signature tail`
    """
    slice0 = build_get_settings_tlv(version=version, digest=digest)
    header = WmsvrD1Header(
        word0=DEFAULT_D1_GET_SETTINGS_WORD0,
        word2=DEFAULT_D1_GET_SETTINGS_WORD2,
        word4=DEFAULT_D1_GET_SETTINGS_WORD4,
        seq=seq,
        len0=len(slice0),
        len1=len(signature),
    )
    return WmsvrD1Frame(header=header, slice0=slice0, slice1=signature)


def parse_d1_frame(data: bytes) -> WmsvrD1Frame:
    """Parse one raw d1 frame into header + split slices + remainder."""
    if len(data) < 9 or data[0] != 0xD1:
        raise ValueError("Not a d1 frame")

    word0 = struct.unpack_from(">H", data, 1)[0]
    word4 = struct.unpack_from(">H", data, 3)[0]
    word2 = struct.unpack_from(">H", data, 5)[0]
    seq = struct.unpack_from(">H", data, 7)[0]
    offset = 9

    extra16: int | None = None
    len0: int | None = None
    len1: int | None = None

    if word0 & D1_WORD0_HAS_EXTRA16:
        if offset + 2 > len(data):
            raise ValueError("Truncated d1 extra16")
        extra16 = struct.unpack_from(">H", data, offset)[0]
        offset += 2
    if word0 & D1_WORD0_HAS_LEN0:
        len0, offset = decode_leb128(data, offset)
    if word0 & D1_WORD0_HAS_LEN1:
        len1, offset = decode_leb128(data, offset)

    start = offset
    end0 = start + (len0 or 0)
    end1 = end0 + (len1 or 0)
    if end1 > len(data):
        raise ValueError("Truncated d1 frame body")

    return WmsvrD1Frame(
        header=WmsvrD1Header(
            word0=word0,
            word2=word2,
            word4=word4,
            seq=seq,
            extra16=extra16,
            len0=len0,
            len1=len1,
        ),
        slice0=data[start:end0],
        slice1=data[end0:end1],
        remainder=data[end1:],
    )


def describe_d1_frame(data: bytes) -> dict[str, Any]:
    """Return a compact parsed description for one d1 frame."""
    frame = parse_d1_frame(data)
    header = frame.header
    return {
        "word0": f"0x{header.word0:04x}",
        "frame_type": f"0x{header.frame_type:02x}",
        "word4": f"0x{header.word4:04x}",
        "word2": f"0x{header.word2:04x}",
        "seq": header.seq,
        "extra16": None if header.extra16 is None else f"0x{header.extra16:04x}",
        "len0": header.len0,
        "len1": header.len1,
        "slice0_hex": frame.slice0[:32].hex(),
        "slice1_hex": frame.slice1[:32].hex(),
        "remainder_len": len(frame.remainder),
    }


def parse_get_settings_response(data: bytes) -> WmsvrGetSettingsResponse:
    """Parse the currently confirmed metadata from a d1 `GET_SETTINGS` response."""
    frame = parse_d1_frame(data)
    key_version: int | None = None
    if frame.slice0:
        try:
            for tag, value in decode_tlv_envelope(frame.slice0):
                if tag == 0x0001 and len(value) == 4:
                    key_version = struct.unpack(">I", value)[0]
                    break
        except ValueError:
            key_version = None
    return WmsvrGetSettingsResponse(
        business_code=frame.header.extra16,
        key_version=key_version,
        key_blob=frame.slice1,
        frame=frame,
    )


def _recv_exactly(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Socket closed while receiving d1 frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_leb128(sock: socket.socket) -> bytes:
    parts = bytearray()
    while True:
        chunk = _recv_exactly(sock, 1)
        parts.extend(chunk)
        if (chunk[0] & 0x80) == 0:
            return bytes(parts)


def recv_d1_frame(sock: socket.socket, *, timeout: float | None = None) -> WmsvrD1Frame:
    """Receive one complete d1 frame from a socket using the confirmed header layout."""
    previous_timeout = sock.gettimeout()
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        fixed = _recv_exactly(sock, 9)
        if fixed[0] != 0xD1:
            raise ValueError("Not a d1 frame")
        word0 = struct.unpack_from(">H", fixed, 1)[0]

        extra = b""
        if word0 & D1_WORD0_HAS_EXTRA16:
            extra = _recv_exactly(sock, 2)

        len0_part = b""
        len1_part = b""
        len0 = 0
        len1 = 0
        if word0 & D1_WORD0_HAS_LEN0:
            len0_part = _recv_leb128(sock)
            len0, _ = decode_leb128(len0_part)
        if word0 & D1_WORD0_HAS_LEN1:
            len1_part = _recv_leb128(sock)
            len1, _ = decode_leb128(len1_part)

        payload = _recv_exactly(sock, len0 + len1)
        raw = fixed + extra + len0_part + len1_part + payload
        return parse_d1_frame(raw)
    finally:
        if timeout is not None:
            sock.settimeout(previous_timeout)


def send_d1_frame(sock: socket.socket, frame: WmsvrD1Frame | bytes) -> None:
    """Send a raw d1 frame through an already connected socket."""
    raw = frame.to_bytes() if isinstance(frame, WmsvrD1Frame) else frame
    sock.sendall(raw)


def exchange_get_settings(
    sock: socket.socket,
    *,
    request: WmsvrD1Frame | None = None,
    timeout: float | None = None,
) -> WmsvrGetSettingsResponse:
    """Send one `GET_SETTINGS` request on an already connected socket and parse one response."""
    outbound = request or build_get_settings_frame()
    send_d1_frame(sock, outbound)
    inbound = recv_d1_frame(sock, timeout=timeout)
    return parse_get_settings_response(inbound.to_bytes())


def query_get_settings_peer(
    peer: WmsvrPeerCandidate,
    *,
    request: WmsvrD1Frame | None = None,
    timeout: float = 10.0,
) -> WmsvrGetSettingsResponse:
    """Connect to one d1 peer, send `GET_SETTINGS`, and parse the first response."""
        return exchange_get_settings(sock, request=request, timeout=timeout)
# ---------------------------------------------------------------------------
# High-level operation builders
# ---------------------------------------------------------------------------
def build_move_request(
    session: WmsvrSession,
    remote_ids: list[str],
    target_fid: int,
) -> WmsvrRequest:
    """Build a mbox:updateMessageInfos request to move messages."""
    body = {"attrs": {"fid": target_fid}, "ids": remote_ids}
    return build_request(session, "mbox:updateMessageInfos", body)
def build_delete_request(
    session: WmsvrSession,
    remote_ids: list[str],
) -> WmsvrRequest:
    """Build a mbox:deleteMessages request."""
    body = {"ids": remote_ids}
    return build_request(session, "mbox:deleteMessages", body)
def build_mark_read_request(
    session: WmsvrSession,
    remote_ids: list[str],
    read: bool = True,
) -> WmsvrRequest:
    """Build a mbox:updateMessageInfos request to mark messages read/unread."""
    body = {"attrs": {"read": read}, "ids": remote_ids}
    return build_request(session, "mbox:updateMessageInfos", body)

def build_update_tags_request(
    session: WmsvrSession,
    remote_ids: list[str],
    tags: dict[str, Any],
) -> WmsvrRequest:
    """Build a mbox:updateMessageTags request."""
    body = {"tags": tags, "ids": remote_ids}
    return build_request(session, "mbox:updateMessageTags", body)


# ---------------------------------------------------------------------------
# Envelope parser (for debugging / response parsing)
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
    """Split one broad capture block into logical TLV request segments.

    Current capture evidence shows that fully captured request fragments end at
    `tag 0x0014` (`client_id`). Any remaining low-level suffix is returned as
    the final trailing segment.
    """
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
    """Extract method-centered TLV segments from one broad capture block.

    Unlike `split_captured_tlv_records`, this helper anchors on `tag 0x0100`
    and walks backward to include any immediately adjacent control/startup or
    envelope-prefix tags that belong to the same logical request.
    """
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


# ---------------------------------------------------------------------------
# Legacy HTTP-hypothesis helpers
# ---------------------------------------------------------------------------


def build_http_url(session: WmsvrSession) -> str:
    """Build the Wmsvr HTTP endpoint URL from session fields."""
    return f"{session.proto}://{session.host}:{session.port}"


def build_http_headers(session: WmsvrSession) -> dict[str, str]:
    """Build HTTP headers for a Wmsvr request.

    Headers derived from mastercore.dll request builder at +0x8a4bf0.
    """
    headers: dict[str, str] = {
        "Content-Type": "application/octet-stream",
        "X-MC-EH-VERSION": "1",
    }
    if session.token:
        headers["Authorization"] = f"Bearer {session.token}"
    if session.device_id:
        headers["X-CM-DEVICE-ID"] = session.device_id
        headers["X-MC-DEVICE-ID"] = session.device_id
    if session.seed_token:
        headers["X-MC-SEED-TOKEN"] = session.seed_token
    if session.eh_seed:
        headers["X-MC-EH-SEED"] = session.eh_seed
    if session.mc_token:
        headers["X-MC-TOKEN"] = session.mc_token
    if session.app_version:
        headers["X-MC-APPVERINNER"] = session.app_version
    if session.product:
        headers["X-MC-PRODUCT"] = session.product
    return headers


def build_observed_runtime_headers(session: WmsvrSession) -> dict[str, str]:
    """Build the currently confirmed `mail.163.com`-style runtime HTTP headers.

    This is an analysis helper derived from live HTTP/2 captures, not the
    confirmed production write path.
    """
    headers: dict[str, str] = {}
    if session.master_fp:
        headers["masterfp"] = session.master_fp
    if session.master_device_info_json:
        headers["masterdi"] = session.master_device_info_json
    if session.master_sdid:
        headers["sdid"] = session.master_sdid
    if session.mastersess:
        headers["mastersess"] = session.mastersess
    if session.mixmailtokens:
        headers["mixmailtokens"] = session.mixmailtokens
    return headers


def build_init_session_headers(session: WmsvrSession) -> dict[str, str]:
    """Build the observed `config.dashi.163.com /init/session` header subset."""
    headers: dict[str, str] = {}
    if session.master_fp:
        headers["masterfp"] = session.master_fp
    if session.mastersess:
        headers["token"] = session.mastersess
    return headers


def refresh_wmsvr_master_session(
    bootstrap: WmsvrBootstrap,
    *,
    base_url: str = "https://config.dashi.163.com",
    timeout: float = 20.0,
    verify_ssl: bool = True,
    ftid: str | None = None,
    transport: Any = None,
) -> WmsvrInitSessionResult:
    """Refresh `mastersess` from the persisted `CloudInfo` / `MasterFP` pair.

    This is the first confirmed no-Frida runtime-auth step that works directly
    from local persisted bootstrap material.
    """
    import httpx

    mastersess = bootstrap.cloud_info.cloud_token
    if not bootstrap.master_fp:
        raise ValueError("Wmsvr bootstrap is missing MasterFP.")
    if not mastersess:
        raise ValueError("Wmsvr bootstrap is missing CloudInfo.CloudToken.")

    session = WmsvrSession(
        ticket=bootstrap.master_fp,
        mastersess=mastersess,
    )
    headers = build_init_session_headers(session)
    headers["content-type"] = "text/plain"
    headers["user-agent"] = f"MailMasterPC/{bootstrap.master_device_info.app_version or 'unknown'}"
    headers["x-ntsm-ftid"] = ftid or f"mailwin|mailmaster.init_session.{int(time.time() * 1000)}"

    with httpx.Client(
        timeout=timeout,
        verify=verify_ssl,
        transport=transport,
        http2=True,
        follow_redirects=False,
    ) as client:
        response = client.post(
            f"{base_url.rstrip('/')}/init/session",
            headers=headers,
            content=b"",
        )

    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if not isinstance(payload, Mapping):
        payload = {}
    result = payload.get("result")
    if not isinstance(result, Mapping):
        result = {}

    success_raw = payload.get("success")
    if isinstance(success_raw, bool):
        success = success_raw
    else:
        success = str(success_raw or "").strip().lower() == "true"

    return WmsvrInitSessionResult(
        status_code=response.status_code,
        http_version=response.http_version,
        code=int(payload.get("code") or 0),
        desc=str(payload.get("desc") or ""),
        success=success,
        token=str(result.get("token") or ""),
        token_refresh_interval=int(result.get("tokenRefreshInterval") or 0),
        raw_payload=dict(payload),
    )


def build_wire_body(
    envelope: bytes,
    body_json: bytes,
    *,
    length_prefixed: bool = True,
) -> bytes:
    """Combine TLV envelope and JSON body into the HTTP POST body.

    Args:
        envelope: Serialized TLV envelope bytes.
        body_json: UTF-8 encoded JSON body.
        length_prefixed: If True, prefix each part with LEB128 length.
            If False, simple concatenation (fallback format).

    The length-prefixed format matches the disassembly at sink_len (0xab4e10)
    which encodes lengths as LEB128 before writing data.
    """
    if length_prefixed:
        return (
            encode_leb128(len(envelope))
            + envelope
            + encode_leb128(len(body_json))
            + body_json
        )
    return envelope + body_json


def send_request(
    request: WmsvrRequest,
    *,
    timeout: float = 15.0,
    length_prefixed: bool = True,
    verify_ssl: bool = False,
) -> "WmsvrResponse":
    """Send a Wmsvr request via HTTP POST and return the response.

    Args:
        request: A fully constructed WmsvrRequest.
        timeout: HTTP timeout in seconds.
        length_prefixed: Whether to use LEB128 length-prefixed body format.
        verify_ssl: Whether to verify TLS certificates (backend uses internal IPs).

    Returns:
        WmsvrResponse with status code and parsed body.

    Raises:
        WmsvrTransportError: On network or HTTP errors.
    """
    import urllib.request
    import urllib.error
    import ssl

    session = request.session
    url = build_http_url(session)
    headers = build_http_headers(session)
    envelope_bytes, body_bytes = request.to_wire()
    wire_body = build_wire_body(envelope_bytes, body_bytes, length_prefixed=length_prefixed)

    logger.debug(
        "wmsvr POST %s method=%s envelope=%d body=%d wire=%d",
        url, request.method, len(envelope_bytes), len(body_bytes), len(wire_body),
    )

    # Build urllib request
    req = urllib.request.Request(url, data=wire_body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)

    # SSL context — backend uses internal IPs, certs won't match
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            resp_body = resp.read()
            logger.debug("wmsvr response status=%d len=%d", status, len(resp_body))
            return WmsvrResponse(
                status_code=status,
                raw_body=resp_body,
            )
    except urllib.error.HTTPError as e:
        resp_body = e.read() if e.fp else b""
        logger.warning("wmsvr HTTP error %d: %s", e.code, resp_body[:200])
        return WmsvrResponse(
            status_code=e.code,
            raw_body=resp_body,
            error=str(e),
        )
    except (urllib.error.URLError, OSError) as e:
        raise WmsvrTransportError(f"Network error: {e}") from e


class WmsvrTransportError(Exception):
    """Raised when the HTTP transport fails."""


@dataclass(slots=True)
class WmsvrResponse:
    """Response from a Wmsvr HTTP request."""

    status_code: int = 0
    raw_body: bytes = b""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300 and not self.error

    def parse_tlv(self) -> list[tuple[int, bytes]]:
        """Try to parse the response body as TLV records."""
        try:
            return decode_tlv_envelope(self.raw_body)
        except (ValueError, IndexError):
            return []

    def parse_json_body(self) -> dict[str, Any] | None:
        """Try to extract JSON from the response.

        The response may be: raw JSON, or TLV envelope + JSON tail.
        """
        # Try raw JSON first
        try:
            return json.loads(self.raw_body)
        except (json.JSONDecodeError, ValueError):
            pass
        # Try skipping TLV envelope (find first '{')
        idx = self.raw_body.find(b"{")
        if idx > 0:
            try:
                return json.loads(self.raw_body[idx:])
            except (json.JSONDecodeError, ValueError):
                pass
        return None
def parse_session_from_frida_log(log_text: str) -> WmsvrSession:
    """Parse a WmsvrSession from the output of session_dump_readonly.js.

    Expected log lines:
        [SESSION] +0x18 ticket (tag 0x113): <value>
        [SESSION] +0x30 trace_id (tag 0x115): <value>
        [SESSION] +0x48 device_info (tag 0x114): <json>
        [SESSION] +0xa8 eh_seed: <value>
        [SESSION] +0xc0 seed_token: <value>
        [SESSION] +0xd8 mc_token: <value>
        [SESSION] +0x108 app_version: <value>
        [SESSION] +0x120 product: <value>
        [SESSION] tag 0x101 token: <value>
        [SESSION] tag 0x102 route: <value>
        [SESSION] tag 0x200 host: <value>
        [SESSION] tag 0x201 port: <value>
        [SESSION] tag 0x16 account: <value>
        [SESSION] tag 0x14 client_id: <value>
    """
    session = WmsvrSession()

    patterns = {
        "ticket": r"\[SESSION\] (?:full_ticket|\+0x18 (?:ticket|master_fp) \(tag 0x113\)): (.+)",
        "trace_id": r"\[SESSION\] \+0x30 (?:trace_id|master_sdid) \(tag 0x115\): (.+)",
        "device_info": r"\[SESSION\] \+0x48 device_info \(tag 0x114\): (.+)",
        "token": r"\[SESSION\] tag 0x101 token: (.+)",
        "route": r"\[SESSION\] tag 0x102 route: (.+)",
        "host": r"\[SESSION\] tag 0x200 host: (.+)",
        "port": r"\[SESSION\] tag 0x201 port: (\d+)",
        "account_desc": r"\[SESSION\] tag 0x16 account: (.+)",
        "client_id": r"\[SESSION\] tag 0x14 client_id: (.+)",
        # HTTP transport fields
        "device_id": r"\[SESSION\] \+0x00 deviceId: (.+)",
        "seed_token": r"\[SESSION\] \+0xc0 seed_token: (.+)",
        "eh_seed": r"\[SESSION\] \+0xa8 eh_seed: (.+)",
        "mc_token": r"\[SESSION\] \+0xd8 mc_token: (.+)",
        "app_version": r"\[SESSION\] \+0x108 app_version: (.+)",
        "product": r"\[SESSION\] \+0x120 product: (.+)",
    }

    for field_name, pattern in patterns.items():
        match = _re.search(pattern, log_text)
        if match:
            value = match.group(1).strip()
            if value in ("null", "None", "(null)"):
                continue
            if field_name == "port":
                setattr(session, field_name, int(value))
            else:
                setattr(session, field_name, value)

    # Try to extract device_id from device_info JSON if not captured directly
    if not session.device_id and session.device_info:
        try:
            info = json.loads(session.device_info)
            session.device_id = info.get("deviceId", "")
        except (json.JSONDecodeError, ValueError):
            pass

    # Try to extract app_version from device_info JSON if not captured directly
    if not session.app_version and session.device_info:
        try:
            info = json.loads(session.device_info)
            session.app_version = info.get("appVersion", "")
        except (json.JSONDecodeError, ValueError):
            pass

    return session


def session_to_dict(session: WmsvrSession) -> dict[str, Any]:
    """Convert a WmsvrSession to a serializable dict (for caching)."""
    return {
        "token": session.token,
        "route": session.route,
        "host": session.host,
        "port": session.port,
        "account_desc": session.account_desc,
        "ticket": session.ticket,
        "trace_id": session.trace_id,
        "device_info": session.device_info,
        "client_id": session.client_id,
        "device_id": session.device_id,
        "seed_token": session.seed_token,
        "eh_seed": session.eh_seed,
        "mc_token": session.mc_token,
        "app_version": session.app_version,
        "product": session.product,
        "proto": session.proto,
    }


def session_from_dict(data: dict[str, Any]) -> WmsvrSession:
    """Reconstruct a WmsvrSession from a dict."""
    return WmsvrSession(
        token=str(data.get("token") or ""),
        route=str(data.get("route") or ""),
        host=str(data.get("host") or ""),
        port=int(data.get("port") or 0),
        account_desc=str(data.get("account_desc") or ""),
        ticket=str(data.get("ticket") or ""),
        trace_id=str(data.get("trace_id") or ""),
        device_info=str(data.get("device_info") or ""),
        client_id=str(data.get("client_id") or ""),
        device_id=str(data.get("device_id") or ""),
        seed_token=str(data.get("seed_token") or ""),
        eh_seed=str(data.get("eh_seed") or ""),
        mc_token=str(data.get("mc_token") or ""),
        app_version=str(data.get("app_version") or ""),
        product=str(data.get("product") or ""),
        proto=str(data.get("proto") or "https"),
    )


def validate_session(session: WmsvrSession) -> list[str]:
    """Return a list of missing required fields."""
    missing: list[str] = []
    if not session.token:
        missing.append("token (tag 0x101)")
    if not session.route:
        missing.append("route (tag 0x102)")
    if not session.host:
        missing.append("host (tag 0x200)")
    if not session.port:
        missing.append("port (tag 0x201)")
    if not session.account_desc:
        missing.append("account_desc (tag 0x16)")
    if not session.ticket:
        missing.append("master_fp / tag 0x113")
    if not session.device_info:
        missing.append("master_device_info_json / tag 0x114")
    if not session.client_id:
        missing.append("client_id (tag 0x14)")
    return missing


def validate_session_for_transport(session: WmsvrSession) -> list[str]:
    """Return missing fields needed for HTTP transport (superset of validate_session)."""
    missing = validate_session(session)
    if not session.device_id:
        missing.append("device_id (X-CM-DEVICE-ID)")
    return missing


# ---------------------------------------------------------------------------
# Login execution and response parsing
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class WmsvrLoginResponse:
    """Parsed Wmsvr login response."""

    # Status fields
    code: str = ""
    status: str = ""
    success: bool = False

    # Auth tokens
    auth_token: str = ""
    coremail_token: str = ""
    ntessess_token: str = ""
    mixmail_token: str = ""
    refresh_token: str = ""

    # Session identifiers
    sid: str = ""
    uid: str = ""
    aid: str = ""
    lid: str = ""

    # Cookie-derived fields
    coremail_cookie: str = ""
    ntes_sess_cookie: str = ""
    mail_sess_cookie: str = ""
    p_info_cookie: str = ""
    s_info_cookie: str = ""
    qiye_token_cookie: str = ""
    qiye_sessionid_cookie: str = ""

    # Routing
    host: str = ""

    # Raw response data
    raw_slice0: bytes = b""
    raw_slice1: bytes = b""
    raw_json: dict[str, Any] = field(default_factory=dict)


def parse_login_response_tlv(data: bytes) -> dict[int, bytes]:
    """Parse TLV records from decrypted login response slice0."""
    records: dict[int, bytes] = {}
    offset = 0

    while offset < len(data):
        if offset + 2 > len(data):
            break

        tag, offset = decode_tag(data, offset)
        if offset >= len(data):
            break

        try:
            length, offset = decode_leb128(data, offset)
        except ValueError:
            break

        if offset + length > len(data):
            break

        value = data[offset:offset + length]
        records[tag] = value
        offset += length

    return records


def parse_login_response(
    decrypted_slice0: bytes,
    decrypted_slice1: bytes,
) -> WmsvrLoginResponse:
    """Parse decrypted login response into structured data."""
    response = WmsvrLoginResponse(
        raw_slice0=decrypted_slice0,
        raw_slice1=decrypted_slice1,
    )

    # Parse TLV records from slice0
    tlv_records = parse_login_response_tlv(decrypted_slice0)

    # Extract common TLV fields
    for tag, value in tlv_records.items():
        try:
            if tag == 0x0100:
                response.code = value.decode("utf-8", errors="ignore")
            elif tag == 0x0101:
                response.auth_token = value.decode("utf-8", errors="ignore")
        except:
            pass

    # Parse JSON from slice1 if present
    if decrypted_slice1:
        try:
            json_text = decrypted_slice1.rstrip(b'\x00').decode("utf-8", errors="ignore")
            if json_text:
                response.raw_json = json.loads(json_text)

                if isinstance(response.raw_json, dict):
                    response.code = str(response.raw_json.get("code", ""))
                    response.status = str(response.raw_json.get("status", ""))
                    response.success = response.raw_json.get("success", False)
                    response.auth_token = str(response.raw_json.get("authToken", ""))
                    response.coremail_token = str(response.raw_json.get("coremailToken", ""))
                    response.ntessess_token = str(response.raw_json.get("ntessessToken", ""))
                    response.mixmail_token = str(response.raw_json.get("mixmailToken", ""))
                    response.refresh_token = str(response.raw_json.get("refreshToken", ""))
                    response.sid = str(response.raw_json.get("sid", ""))
                    response.uid = str(response.raw_json.get("uid", ""))
                    response.aid = str(response.raw_json.get("aid", ""))
                    response.lid = str(response.raw_json.get("lid", ""))
                    response.host = str(response.raw_json.get("host", ""))

        except Exception as e:
            logger.debug(f"Failed to parse login response JSON: {e}")

    return response


def build_session_from_login_response(
    response: WmsvrLoginResponse,
    context: WmsvrLoginContext,
) -> WmsvrSession:
    """Convert login response into WmsvrSession object."""
    # Build route string (simplified version)
    route = ""
    if response.coremail_cookie or response.coremail_token:
        token_part = response.coremail_token or response.auth_token
        if token_part:
            route = f"Coremail:{token_part}"

    return WmsvrSession(
        token=response.auth_token[:32] if response.auth_token else "",
        route=route,
        host=response.host,
        port=0,
        account_desc=f"0|{context.account}",
        ticket=context.master_fp,
        trace_id=context.master_sdid,
        device_info=context.device_info_json,
        client_id=f"mailwin|{context.device_id}.1.1",
        mastersess=context.cloud_token,
    )


def execute_wmsvr_login(
    context: WmsvrLoginContext,
    *,
    method: str = "wzpa:loginone",
    timeout: float = 30.0,
) -> tuple[WmsvrLoginResponse, WmsvrSession]:
    """Execute Wmsvr login and return parsed response + session.
    
    Args:
        context: Login context with account credentials and bootstrap data
        method: Login method ("wzpa:loginone" or "wzpmmc:masterdevice")
        timeout: Socket timeout in seconds
        
    Returns:
        Tuple of (login_response, session)
    """
    # Build login payload
    if method == "wzpa:loginone":
        payload = build_loginone_payload(context)
    elif method == "wzpmmc:masterdevice":
        payload = build_masterdevice_payload(context)
    else:
        raise ValueError(f"Unknown login method: {method}")

    # Build login TLV
    login_tlv = build_wmsvr_login_tlv(
        payload,
        ticket=context.master_fp,
        trace_id=context.master_sdid,
        device_info_json=context.device_info_json,
        client_id=f"mailwin|{context.device_id}.1.1",
    )

    # Generate session key
    session_key = generate_wmsvr_d1_session_key()

    # Get runtime key info (use default for now)
    key_version = DEFAULT_D1_KEY_VERSION
    key_digest16 = DEFAULT_D1_FALLBACK_KEY_DIGEST16

    # Build d1 request context
    d1_context = WmsvrD1RequestContext(
        key_version=key_version,
        key_digest16=key_digest16,
        master_fp=context.master_fp,
        master_sdid=context.master_sdid,
        device_info_json=context.device_info_json,
        session_key=session_key,
    )

    # Build control TLV + login TLV
    control_tlv = build_wmsvr_d1_control_tlv(d1_context)
    full_slice0 = control_tlv + login_tlv

    # Build encrypted d1 frame
    frame = build_wmsvr_d1_encrypted_frame(
        full_slice0,
        session_key=session_key,
        slice1_bytes=b"",  # Login requests typically have no JSON body
        seq=1,
        word2=d1_context.word2,
        word4=d1_context.word4,
    )

    # Select peer
    if not context.peer_candidates:
        raise ValueError("No d1 peer candidates available")
    peer = context.peer_candidates[0]

    # Connect and send
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((peer.host, peer.port))

        # Send login request
        send_d1_frame(sock, frame)

        # Receive response
        response_frame = recv_d1_frame(sock, timeout=timeout)

        # Decrypt response slices
        decrypted_slice0 = b""
        decrypted_slice1 = b""

        if response_frame.slice0:
            decrypted_slice0 = decrypt_wmsvr_d1_slice(response_frame.slice0, session_key)

        if response_frame.slice1:
            decrypted_slice1 = decrypt_wmsvr_d1_slice(response_frame.slice1, session_key)

        # Parse login response
        login_response = parse_login_response(decrypted_slice0, decrypted_slice1)

        # Build session from response
        session = build_session_from_login_response(login_response, context)

        return login_response, session

    finally:
        sock.close()
