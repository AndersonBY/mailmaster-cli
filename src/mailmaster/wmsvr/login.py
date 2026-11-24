"""Wmsvr session refresh, login response parsing/summarization, and d1 probe/RPC execution."""

from __future__ import annotations

import json
import logging
import socket
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .bootstrap import (
    WmsvrBootstrap,
    WmsvrLoginContext,
    WmsvrPeerCandidate,
    WmsvrSession,
    build_default_wmsvr_login_client_id,
)
from .d1_wire import (
    WmsvrD1Frame,
    WmsvrD1RequestContext,
    WmsvrGetSettingsResponse,
    build_wmsvr_d1_request_frame,
    build_wmsvr_key_exchange_frame,
    d1_socket_family,
    decrypt_wmsvr_d1_slice,
    exchange_get_settings,
    generate_wmsvr_d1_session_key,
    open_d1_socket,
    recv_d1_frame,
    send_d1_frame,
    strip_wmsvr_slice_padding,
)
from .diagnostics import build_init_session_headers
from .payloads import (
    SEC_OS_TYPE_IOS as SEC_OS_TYPE_IOS,
    SEC_OS_TYPE_MACOS as SEC_OS_TYPE_MACOS,
    SEC_OS_TYPE_WINDOWS as SEC_OS_TYPE_WINDOWS,
    WmsvrControlPayload as WmsvrControlPayload,
    WmsvrLoginPayload as WmsvrLoginPayload,
    WmsvrStartupPayload as WmsvrStartupPayload,
    _as_login_value as _as_login_value,
    _build_ordered_login_body as _build_ordered_login_body,
    _query_dns_fully_qualified_name as _query_dns_fully_qualified_name,
    build_login_response_flags_body as build_login_response_flags_body,
    build_logincorp_body as build_logincorp_body,
    build_loginmail_body as build_loginmail_body,
    build_loginmail_password_body as build_loginmail_password_body,
    build_loginone_body as build_loginone_body,
    build_loginone_payload as build_loginone_payload,
    build_logintoken_body as build_logintoken_body,
    build_masterdevice_auth_body as build_masterdevice_auth_body,
    build_masterdevice_payload as build_masterdevice_payload,
    build_sec_fingerprint_items as build_sec_fingerprint_items,
    build_update_message_infos_body as build_update_message_infos_body,
    build_update_message_infos_frame as build_update_message_infos_frame,
    build_wmsvr_control_tlv as build_wmsvr_control_tlv,
    build_wmsvr_login_frame as build_wmsvr_login_frame,
    build_wmsvr_login_segment as build_wmsvr_login_segment,
    build_wmsvr_login_tlv as build_wmsvr_login_tlv,
    build_wmsvr_startup_tlv as build_wmsvr_startup_tlv,
    local_sec_name as local_sec_name,
    local_sec_os_type as local_sec_os_type,
    parse_wmsvr_control_tlv as parse_wmsvr_control_tlv,
    parse_wmsvr_startup_tlv as parse_wmsvr_startup_tlv,
)
from .tlv import (
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_KEY_VERSION,
    DEFAULT_D1_RPC_WORD4,
    DEFAULT_D1_SLICE_PADDING,
    LOGIN_METHOD_LOGINONE,
    _resolve_wmsvr_hook,
    decode_leb128,
    decode_tag,
)

logger = logging.getLogger(__name__)

WMSVR_LOGIN_RESPONSE_FIELD_NAMES: tuple[str, ...] = (
    "authToken",
    "coremailToken",
    "ntessessToken",
    "mixmailToken",
    "refreshToken",
    "coremailCookie",
    "qiyeToken",
    "loginType",
    "loginState",
    "emailAddress",
    "code",
    "status",
    "success",
    "host",
    "sid",
    "uid",
    "aid",
    "lid",
)


# ---------------------------------------------------------------------------
# Session refresh & login response models
# ---------------------------------------------------------------------------


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


@dataclass(slots=True)
class WmsvrLoginResponse:
    """Parsed Wmsvr login response."""

    code: str = ""
    status: str = ""
    success: bool = False

    auth_token: str = ""
    coremail_token: str = ""
    ntessess_token: str = ""
    mixmail_token: str = ""
    refresh_token: str = ""

    sid: str = ""
    uid: str = ""
    aid: str = ""
    lid: str = ""

    coremail_cookie: str = ""
    ntes_sess_cookie: str = ""
    mail_sess_cookie: str = ""
    p_info_cookie: str = ""
    s_info_cookie: str = ""
    qiye_token_cookie: str = ""
    qiye_sessionid_cookie: str = ""

    host: str = ""

    raw_slice0: bytes = b""
    raw_slice1: bytes = b""
    raw_json: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class WmsvrLoginProbeResult:
    """Low-level result of one raw login-family probe."""

    method: str
    body_bytes: bytes = b""
    request_frame: WmsvrD1Frame | None = None
    response_frame: WmsvrD1Frame | None = None
    get_settings_response: WmsvrGetSettingsResponse | None = None
    session_key: bytes = b""
    client_id: str = ""
    decrypted_slice0: bytes = b""
    decrypted_slice1: bytes = b""
    error: str = ""
    key_exchange: bool = True
    key_exchange_frame: WmsvrD1Frame | None = None


# ---------------------------------------------------------------------------
# Master session HTTP/2 refresh (`/init/session`)
# ---------------------------------------------------------------------------


def refresh_wmsvr_master_session(
    bootstrap: WmsvrBootstrap,
    *,
    base_url: str = "https://config.dashi.163.com",
    timeout: float = 20.0,
    verify_ssl: bool = True,
    ftid: str | None = None,
    transport: Any = None,
) -> WmsvrInitSessionResult:
    """Refresh `mastersess` from the persisted `CloudInfo` / `MasterFP` pair."""
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


# ---------------------------------------------------------------------------
# Login response parsing & summarization
# ---------------------------------------------------------------------------


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

        value = data[offset : offset + length]
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

    tlv_records = parse_login_response_tlv(decrypted_slice0)

    for tag, value in tlv_records.items():
        try:
            if tag == 0x0100:
                response.code = value.decode("utf-8", errors="ignore")
            elif tag == 0x0101:
                response.auth_token = value.decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, ValueError):
            pass

    if decrypted_slice1:
        try:
            json_text = strip_wmsvr_slice_padding(decrypted_slice1).decode(
                "utf-8", errors="ignore"
            )
            if json_text:
                response.raw_json = json.loads(json_text)

                if isinstance(response.raw_json, dict):
                    response.code = str(response.raw_json.get("code", ""))
                    response.status = str(response.raw_json.get("status", ""))
                    response.success = bool(response.raw_json.get("success", False))
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
            logger.debug("Failed to parse login response JSON: %s", e)

    return response


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(
        1 for byte in data if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D)
    )
    return round(printable / len(data), 3)


def _is_identifier_byte(byte: int) -> bool:
    return (
        0x30 <= byte <= 0x39
        or 0x41 <= byte <= 0x5A
        or 0x61 <= byte <= 0x7A
        or byte == 0x5F
    )


def _field_name_offsets(data: bytes) -> dict[str, list[int]]:
    """Find key-like occurrences of the known response field names."""
    offsets: dict[str, list[int]] = {}
    for name in WMSVR_LOGIN_RESPONSE_FIELD_NAMES:
        needle = name.encode("ascii")
        found: list[int] = []
        start = data.find(needle)
        while start != -1 and len(found) < 4:
            before = data[start - 1] if start > 0 else 0
            after_index = start + len(needle)
            after = data[after_index] if after_index < len(data) else 0
            if not _is_identifier_byte(before) and not _is_identifier_byte(after):
                found.append(start)
            start = data.find(needle, start + len(needle))
        if found:
            offsets[name] = found
    return offsets


def describe_login_response_slice(data: bytes) -> dict[str, Any]:
    """Describe the *shape* of one decrypted response slice without assuming a format."""
    text = data.rstrip(b"\x00")
    stripped = text.strip()
    description: dict[str, Any] = {
        "length": len(data),
        "printable_ratio": _printable_ratio(text),
        "looks_like_json": stripped[:1] in (b"{", b"["),
        "field_name_offsets": _field_name_offsets(text),
    }
    if description["looks_like_json"]:
        try:
            json.loads(stripped.decode("utf-8"))
            description["json_decoded"] = True
        except (UnicodeDecodeError, ValueError):
            description["json_decoded"] = False
    return description


def summarize_login_response(
    response: WmsvrLoginResponse,
    *,
    include_secrets: bool = False,
) -> dict[str, Any]:
    """Summarize a parsed login response for a probe report."""
    raw_json = response.raw_json if isinstance(response.raw_json, dict) else {}
    token_fields = {
        "authToken": response.auth_token,
        "coremailToken": response.coremail_token,
        "ntessessToken": response.ntessess_token,
        "mixmailToken": response.mixmail_token,
        "refreshToken": response.refresh_token,
    }
    identifier_fields = {
        "sid": response.sid,
        "uid": response.uid,
        "aid": response.aid,
        "lid": response.lid,
    }
    slice0_shape = describe_login_response_slice(response.raw_slice0)
    slice0_shape["tlv_tags"] = [
        hex(tag) for tag in parse_login_response_tlv(response.raw_slice0)
    ]
    summary: dict[str, Any] = {
        "code": response.code,
        "status": response.status,
        "success": response.success,
        "json_keys": [str(key) for key in raw_json],
        "token_fields_present": sorted(
            name for name, value in token_fields.items() if value
        ),
        "identifier_fields_present": sorted(
            name for name, value in identifier_fields.items() if value
        ),
        "host": response.host,
        "raw_slice0_len": len(response.raw_slice0),
        "raw_slice1_len": len(response.raw_slice1),
        "slice0_shape": slice0_shape,
        "slice1_shape": describe_login_response_slice(response.raw_slice1),
    }
    values = {**token_fields, **identifier_fields}
    if include_secrets:
        summary["values"] = values
        summary["raw_json"] = raw_json
    else:
        summary["value_lengths"] = {
            name: len(value) for name, value in values.items() if value
        }
    return summary


def build_session_from_login_response(
    response: WmsvrLoginResponse,
    context: WmsvrLoginContext,
    *,
    client_id: str = "",
) -> WmsvrSession:
    """Convert login response into a WmsvrSession object."""
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
        client_id=client_id or build_default_wmsvr_login_client_id(context, method=LOGIN_METHOD_LOGINONE),
        mastersess=context.cloud_token,
    )


# ---------------------------------------------------------------------------
# Login & direct d1 request execution
# ---------------------------------------------------------------------------


def execute_wmsvr_login(
    context: WmsvrLoginContext,
    *,
    method: str = LOGIN_METHOD_LOGINONE,
    client_id: str = "",
    include_d1_control: bool | None = None,
    prefix_version: bool = False,
    body: Mapping[str, Any] | None = None,
    body_bytes: bytes | None = None,
    key_version: int = DEFAULT_D1_KEY_VERSION,
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    word2: int = 0x0003,
    peer_index: int = 0,
    prefetch_get_settings: bool = True,
    timeout: float = 30.0,
) -> tuple[WmsvrLoginResponse, WmsvrSession]:
    """Execute Wmsvr login and return parsed response + session."""
    frame, session_key, resolved_client_id = build_wmsvr_login_frame(
        context,
        method=method,
        client_id=client_id,
        include_d1_control=include_d1_control,
        body=body,
        body_bytes=body_bytes,
        key_version=key_version,
        key_digest16=key_digest16,
        word2=word2,
        word4=0x0003,
    )

    if not context.peer_candidates:
        raise ValueError("No d1 peer candidates available")
    if peer_index < 0 or peer_index >= len(context.peer_candidates):
        raise IndexError(f"peer_index out of range: {peer_index}")
    peer = context.peer_candidates[peer_index]

    opener = _resolve_wmsvr_hook("open_d1_socket", open_d1_socket, _ORIG_OPEN_D1_SOCKET)
    exchanger = _resolve_wmsvr_hook("exchange_get_settings", exchange_get_settings, _ORIG_EXCHANGE_GET_SETTINGS)
    sender = _resolve_wmsvr_hook("send_d1_frame", send_d1_frame, _ORIG_SEND_D1_FRAME)
    receiver = _resolve_wmsvr_hook("recv_d1_frame", recv_d1_frame, _ORIG_RECV_D1_FRAME)

    sock = opener(peer, timeout=timeout)
    try:
        if prefetch_get_settings:
            exchanger(sock, timeout=timeout)

        sender(sock, frame)
        response_frame = receiver(sock, timeout=timeout)

        decrypted_slice0 = b""
        decrypted_slice1 = b""

        if response_frame.slice0:
            decrypted_slice0 = decrypt_wmsvr_d1_slice(response_frame.slice0, session_key)

        if response_frame.slice1:
            decrypted_slice1 = decrypt_wmsvr_d1_slice(response_frame.slice1, session_key)

        login_response = parse_login_response(decrypted_slice0, decrypted_slice1)
        session = build_session_from_login_response(
            login_response,
            context,
            client_id=resolved_client_id,
        )
        return login_response, session
    finally:
        sock.close()


def execute_wmsvr_login_probe(
    context: WmsvrLoginContext,
    *,
    method: str = LOGIN_METHOD_LOGINONE,
    client_id: str = "",
    include_d1_control: bool | None = None,
    body: Mapping[str, Any] | None = None,
    body_bytes: bytes | None = None,
    key_version: int = DEFAULT_D1_KEY_VERSION,
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    word2: int = 0x0003,
    word4: int = DEFAULT_D1_RPC_WORD4,
    peer_index: int = 0,
    peer: WmsvrPeerCandidate | None = None,
    prefetch_get_settings: bool = True,
    prefix_version: bool = False,
    key_exchange: bool = True,
    install_root: Path | None = None,
    timeout: float = 30.0,
    padding: str = DEFAULT_D1_SLICE_PADDING,
) -> WmsvrLoginProbeResult:
    """Execute one raw login-family probe and return transport-level artifacts."""
    session_key = generate_wmsvr_d1_session_key()
    key_exchange_frame: WmsvrD1Frame | None = None
    exchange_error = ""
    if key_exchange:
        try:
            kex_builder = _resolve_wmsvr_hook(
                "build_wmsvr_key_exchange_frame",
                build_wmsvr_key_exchange_frame,
                _ORIG_BUILD_KEY_EXCHANGE,
            )
            key_exchange_frame, session_key = kex_builder(
                key_version=key_version,
                key_digest16=key_digest16,
                session_key=session_key,
                install_root=install_root,
            )
        except Exception as exc:  # noqa: BLE001 - reported as a structured error
            exchange_error = f"{type(exc).__name__}: {exc}"

    frame, session_key, resolved_client_id = build_wmsvr_login_frame(
        context,
        method=method,
        client_id=client_id,
        include_d1_control=include_d1_control,
        prefix_version=prefix_version,
        body=body,
        body_bytes=body_bytes,
        key_version=key_version,
        key_digest16=key_digest16,
        session_key=session_key,
        word2=word2,
        word4=word4,
        padding=padding,
    )
    result = WmsvrLoginProbeResult(
        method=method,
        body_bytes=body_bytes
        if body_bytes is not None
        else (
            json.dumps(dict(body), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if body is not None
            else b""
        ),
        request_frame=frame,
        session_key=session_key,
        client_id=resolved_client_id,
        key_exchange=key_exchange,
        key_exchange_frame=key_exchange_frame,
    )
    if exchange_error:
        result.error = exchange_error
        return result

    if not context.peer_candidates:
        result.error = "No d1 peer candidates available"
        return result
    if peer is None:
        if peer_index < 0 or peer_index >= len(context.peer_candidates):
            result.error = f"peer_index out of range: {peer_index}"
            return result
        peer = context.peer_candidates[peer_index]

    opener = _resolve_wmsvr_hook("open_d1_socket", open_d1_socket, _ORIG_OPEN_D1_SOCKET)
    exchanger = _resolve_wmsvr_hook("exchange_get_settings", exchange_get_settings, _ORIG_EXCHANGE_GET_SETTINGS)
    sender = _resolve_wmsvr_hook("send_d1_frame", send_d1_frame, _ORIG_SEND_D1_FRAME)
    receiver = _resolve_wmsvr_hook("recv_d1_frame", recv_d1_frame, _ORIG_RECV_D1_FRAME)

    sock = opener(peer, timeout=timeout)
    try:
        if prefetch_get_settings:
            result.get_settings_response = exchanger(
                sock,
                request=key_exchange_frame,
                timeout=timeout,
            )
        sender(sock, frame)
        result.response_frame = receiver(sock, timeout=timeout)
        if result.response_frame.slice0:
            try:
                result.decrypted_slice0 = decrypt_wmsvr_d1_slice(result.response_frame.slice0, session_key)
            except Exception:
                result.decrypted_slice0 = b""
        if result.response_frame.slice1:
            try:
                result.decrypted_slice1 = decrypt_wmsvr_d1_slice(result.response_frame.slice1, session_key)
            except Exception:
                result.decrypted_slice1 = b""
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    return result


def execute_wmsvr_d1_request(
    session: WmsvrSession,
    method: str,
    body: dict[str, Any] | None = None,
    *,
    timeout: float = 30.0,
) -> tuple[WmsvrD1Frame, bytes, bytes]:
    """Execute a Wmsvr business request over d1 protocol."""
    if not session.host or not session.port:
        raise ValueError("Session missing host/port")

    session_key = generate_wmsvr_d1_session_key()
    key_version = getattr(session, "key_version", DEFAULT_D1_KEY_VERSION)
    key_digest16 = getattr(session, "key_digest16", DEFAULT_D1_FALLBACK_KEY_DIGEST16)

    d1_context = WmsvrD1RequestContext(
        key_version=key_version,
        key_digest16=key_digest16,
        master_fp=session.ticket,
        master_sdid=session.trace_id,
        device_info_json=session.device_info,
        session_key=session_key,
        word2=0x0084,
        word4=0x0003,
    )

    frame = build_wmsvr_d1_request_frame(
        d1_context,
        session,
        method,
        body=body,
        seq=1,
    )

    sender = _resolve_wmsvr_hook("send_d1_frame", send_d1_frame, _ORIG_SEND_D1_FRAME)
    receiver = _resolve_wmsvr_hook("recv_d1_frame", recv_d1_frame, _ORIG_RECV_D1_FRAME)

    sock = socket.socket(d1_socket_family(session.host), socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((session.host, session.port))
        sender(sock, frame)
        response_frame = receiver(sock, timeout=timeout)

        decrypted_slice0 = b""
        decrypted_slice1 = b""
        if response_frame.slice0:
            decrypted_slice0 = decrypt_wmsvr_d1_slice(response_frame.slice0, session_key)
        if response_frame.slice1:
            decrypted_slice1 = decrypt_wmsvr_d1_slice(response_frame.slice1, session_key)
        return response_frame, decrypted_slice0, decrypted_slice1
    finally:
        sock.close()


def send_email_via_wmsvr(
    session: WmsvrSession,
    *,
    to: list[str],
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Send email via Wmsvr d1 protocol."""
    body: dict[str, Any] = {
        "action": "deliver",
        "to": to,
        "subject": subject,
    }
    if body_text:
        body["bodyText"] = body_text
    if body_html:
        body["bodyHtml"] = body_html
    if cc:
        body["cc"] = cc
    if bcc:
        body["bcc"] = bcc
    if attachments:
        body["attachments"] = attachments

    _, _, slice1 = execute_wmsvr_d1_request(
        session,
        "mbox:compose",
        body,
        timeout=timeout,
    )
    if slice1:
        try:
            return json.loads(slice1.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return {}


def mark_messages_read_via_wmsvr(
    session: WmsvrSession,
    message_ids: list[str],
    read: bool = True,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Mark messages as read/unread via Wmsvr d1 protocol."""
    body = {
        "attrs": {"flags": {"read": read}},
        "ids": message_ids,
    }
    _, _, slice1 = execute_wmsvr_d1_request(
        session,
        "mbox:updateMessageInfos",
        body,
        timeout=timeout,
    )
    if slice1:
        try:
            return json.loads(slice1.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return {}


def move_messages_via_wmsvr(
    session: WmsvrSession,
    message_ids: list[str],
    target_folder_id: int,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Move messages to a different folder via Wmsvr d1 protocol."""
    body = {
        "attrs": {"fid": target_folder_id},
        "ids": message_ids,
    }
    _, _, slice1 = execute_wmsvr_d1_request(
        session,
        "mbox:updateMessageInfos",
        body,
        timeout=timeout,
    )
    if slice1:
        try:
            return json.loads(slice1.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return {}


def delete_messages_via_wmsvr(
    session: WmsvrSession,
    message_ids: list[str],
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Delete messages via Wmsvr d1 protocol."""
    body = {"ids": message_ids}
    _, _, slice1 = execute_wmsvr_d1_request(
        session,
        "mbox:deleteMessages",
        body,
        timeout=timeout,
    )
    if slice1:
        try:
            return json.loads(slice1.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return {}


_ORIG_OPEN_D1_SOCKET = open_d1_socket
_ORIG_EXCHANGE_GET_SETTINGS = exchange_get_settings
_ORIG_SEND_D1_FRAME = send_d1_frame
_ORIG_RECV_D1_FRAME = recv_d1_frame
_ORIG_BUILD_KEY_EXCHANGE = build_wmsvr_key_exchange_frame
