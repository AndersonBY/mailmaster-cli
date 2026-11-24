"""Wmsvr startup/control/login TLV payload models, JSON body builders, and login frame builders."""

from __future__ import annotations

import json
import socket
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import md5
from typing import Any

from .bootstrap import (
    WmsvrLoginContext,
    WmsvrSession,
    build_default_wmsvr_login_client_id,
)
from .d1_wire import (
    WmsvrD1Frame,
    WmsvrD1RequestContext,
    _as_bytes,
    _build_wmsvr_runtime_tail_records,
    build_wmsvr_d1_control_tlv,
    build_wmsvr_d1_encrypted_frame,
    build_wmsvr_d1_request_frame,
    generate_wmsvr_d1_session_key,
    pad_d1_slice,
)
from .diagnostics import classify_wmsvr_auth_token
from .tlv import (
    CONTROL_TAG_CONTROL_ID,
    CONTROL_TAG_MODE,
    CONTROL_TAG_UNIX_TIME,
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_KEY_VERSION,
    DEFAULT_D1_RPC_WORD4,
    DEFAULT_D1_SLICE_PADDING,
    DEFAULT_WMSVR_LOGIN_DF,
    DEFAULT_WMSVR_LOGIN_LOCALE,
    DEFAULT_WMSVR_LOGIN_LOGINTOKEN_FUNCID,
    DEFAULT_WMSVR_LOGIN_PRODUCT,
    DEFAULT_WMSVR_LOGIN_SWITCH_FUNCID,
    DEFAULT_WMSVR_LOGINMAIL_PARTY,
    DEFAULT_WMSVR_LOGINMAIL_URS_CODE,
    DEFAULT_WMSVR_LOGINONE_FUNCID,
    LOGIN_FAMILY_METHODS,
    LOGIN_METHOD_LOGINONE,
    LOGIN_METHOD_MASTERDEVICE,
    LOGIN_TAG_APP_VERSION,
    LOGIN_TAG_CONFIG_ID,
    LOGIN_TAG_DEVICE_ID,
    LOGIN_TAG_HARDCODED_LOCALE,
    LOGIN_TAG_METHOD,
    LOGIN_TAG_OPTIONAL_107,
    STARTUP_TAG_APPVER_INNER,
    STARTUP_TAG_CONFIG_ID,
    STARTUP_TAG_DEVICE_ID,
    STARTUP_TAG_METHOD,
    STARTUP_TAG_MODE,
    STARTUP_TAG_NONCE_HEX,
    STARTUP_TAG_OPAQUE_TOKEN,
    STARTUP_TAG_RESPONSE_FORMAT,
    STARTUP_TAG_STARTUP_FLAG,
    STARTUP_TAG_UNIX_TIME,
    TAG_CLIENT_ID,
    TAG_DEVICE_INFO,
    TAG_TICKET,
    TAG_TRACE_ID,
    TAG_VERSION,
    WMSVR_LOGINONE_MD5_SOURCE_LIMIT,
    WMSVR_LOGINONE_PASSWORD_MD5,
    WMSVR_LOGINONE_PASSWORD_RAW,
    WMSVR_LOGINONE_PASSTYPE_MD5,
    WMSVR_LOGINONE_PASSTYPE_PLAIN,
    WMSVR_METHOD_UPDATE_MESSAGE_INFOS,
    _resolve_wmsvr_hook,
    decode_tlv_envelope,
    describe_envelope,
    encode_tlv,
    encode_tlv_envelope,
)

SEC_OS_TYPE_WINDOWS = 0
SEC_OS_TYPE_MACOS = 1
SEC_OS_TYPE_IOS = 2


# ---------------------------------------------------------------------------
# Payload models
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WmsvrLoginPayload:
    """Method-specific TLV payload used during the Wmsvr login chain."""

    method: str
    records: list[tuple[int, bytes]] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        return encode_tlv_envelope(self.records)

    def describe(self) -> list[dict[str, Any]]:
        return describe_envelope(self.to_bytes())


@dataclass(slots=True)
class WmsvrStartupPayload:
    """Observed TLV payload for the special startup-family d1 request path."""

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
        return len(pad_d1_slice(self.to_bytes()))

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
        return len(pad_d1_slice(self.to_bytes()))

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


# ---------------------------------------------------------------------------
# Startup / control TLV builders & parsers
# ---------------------------------------------------------------------------


def _as_login_value(value: bytes | str | None) -> bytes:
    return _as_bytes(value)


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


# ---------------------------------------------------------------------------
# Login TLV & JSON body builders
# ---------------------------------------------------------------------------


def build_loginone_payload(
    context: WmsvrLoginContext,
    *,
    tag_107: bytes | str | None = None,
    locale: str | None = None,
    method: str = LOGIN_METHOD_LOGINONE,
) -> WmsvrLoginPayload:
    """Build the current capture-confirmed `wzpa:loginone` TLV payload."""
    if method not in LOGIN_FAMILY_METHODS:
        raise ValueError(f"Unsupported login-family method: {method}")
    resolved_locale = locale or context.locale or DEFAULT_WMSVR_LOGIN_LOCALE
    records: list[tuple[int, bytes]] = [
        (LOGIN_TAG_METHOD, method.encode("utf-8")),
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
    return WmsvrLoginPayload(method=method, records=records)


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


def _build_ordered_login_body(items: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for key, value in items:
        if value is None or value == "":
            continue
        body[key] = value
    return body


def build_loginmail_body(
    context: WmsvrLoginContext,
    *,
    urs_code: str = DEFAULT_WMSVR_LOGINMAIL_URS_CODE,
    df: str = DEFAULT_WMSVR_LOGIN_DF,
    product: str = DEFAULT_WMSVR_LOGIN_PRODUCT,
    party: str = DEFAULT_WMSVR_LOGINMAIL_PARTY,
) -> dict[str, Any]:
    """Build the statically recovered `wzpa:loginmail` JSON slice1 body."""
    return _build_ordered_login_body(
        [
            ("username", context.user or context.account),
            ("ursCode", urs_code),
            ("funcid", DEFAULT_WMSVR_LOGIN_LOGINTOKEN_FUNCID),
            ("type", "1"),
            ("df", df),
            ("product", product),
            ("device-id", context.device_id),
            ("sdid", context.master_sdid),
            ("returnUrs", True),
            ("returnToken", True),
            ("party", party),
        ]
    )


def build_logincorp_body(
    context: WmsvrLoginContext,
    *,
    access_token: str,
    df: str = DEFAULT_WMSVR_LOGIN_DF,
    product: str = DEFAULT_WMSVR_LOGIN_PRODUCT,
) -> dict[str, Any]:
    """Build the statically recovered `wzpa:logincorp` JSON slice1 body."""
    if not access_token:
        raise ValueError("`access_token` is required for logincorp body construction.")
    return _build_ordered_login_body(
        [
            ("username", context.user or context.account),
            ("accessToken", access_token),
            ("funcid", DEFAULT_WMSVR_LOGIN_LOGINTOKEN_FUNCID),
            ("type", "1"),
            ("df", df),
            ("product", product),
            ("device-id", context.device_id),
            ("sdid", context.master_sdid),
            ("returnUrs", True),
            ("returnToken", True),
        ]
    )


def build_login_response_flags_body(
    *,
    return_urs: bool | int = True,
    return_token: bool | int = True,
) -> dict[str, Any]:
    """Build the minimal `returnUrs` / `returnToken` login-family body."""
    return _build_ordered_login_body(
        [
            ("returnUrs", return_urs),
            ("returnToken", return_token),
        ]
    )


def build_update_message_infos_body(
    ids: Iterable[str],
    *,
    read: bool | None = None,
) -> dict[str, Any]:
    """Build the capture-verified `mbox:updateMessageInfos` body."""
    resolved_ids = [str(mail_id) for mail_id in ids]
    if not resolved_ids:
        raise ValueError("`mbox:updateMessageInfos` needs at least one message id.")
    attrs: dict[str, Any] = {}
    if read is not None:
        attrs["flags"] = {"read": bool(read)}
    return {"attrs": attrs, "ids": resolved_ids}


def build_update_message_infos_frame(
    context: WmsvrD1RequestContext,
    session: WmsvrSession,
    ids: Iterable[str],
    *,
    read: bool | None = None,
    seq: int = 1,
) -> tuple[WmsvrD1Frame, str]:
    """Build one `mbox:updateMessageInfos` request frame plus its JSON body."""
    body = build_update_message_infos_body(ids, read=read)
    frame = build_wmsvr_d1_request_frame(
        context,
        session,
        WMSVR_METHOD_UPDATE_MESSAGE_INFOS,
        body=body,
        seq=seq,
    )
    return frame, json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def build_logintoken_body(
    context: WmsvrLoginContext,
    *,
    access_token: str,
    funcid: str = DEFAULT_WMSVR_LOGIN_LOGINTOKEN_FUNCID,
    type_value: str = "1",
    include_username: bool = False,
    include_df: bool = False,
    include_product: bool = False,
    include_device_id: bool = False,
    include_sdid: bool = False,
    df: str = DEFAULT_WMSVR_LOGIN_DF,
    product: str = DEFAULT_WMSVR_LOGIN_PRODUCT,
    return_urs: bool | int = 1,
    return_token: bool | int = 1,
) -> dict[str, Any]:
    """Build the recovered `accessToken` / `logintoken` slice1 candidate."""
    if not access_token:
        raise ValueError("`access_token` is required for logintoken body construction.")
    items: list[tuple[str, Any]] = [
        ("accessToken", access_token),
        ("funcid", funcid),
        ("type", type_value),
    ]
    if include_username:
        items.append(("username", context.user or context.account))
    if include_df:
        items.append(("df", df))
    if include_product:
        items.append(("product", product))
    if include_device_id:
        items.append(("device-id", context.device_id))
    if include_sdid:
        items.append(("sdid", context.master_sdid))
    items.extend(
        [
            ("returnUrs", return_urs),
            ("returnToken", return_token),
        ]
    )
    return _build_ordered_login_body(items)


def build_loginmail_password_body(
    context: WmsvrLoginContext,
    *,
    funcid: str | int = "123456",
    passtype: str | int = 6,
    switch_login: str | int | None = None,
    ignore: bool | int | str | None = None,
    smslogin_trust: bool | int | str | None = None,
    party: bool | int | str | None = None,
    qiye_use_md5: bool | int | str | None = None,
    include_app_version: bool = True,
    include_device_id: bool = True,
    return_urs: bool | int = 1,
    return_token: bool | int = 1,
) -> dict[str, Any]:
    """Build a legacy compatibility probe body from an older login hypothesis."""
    items: list[tuple[str, Any]] = []
    if switch_login is not None:
        items.append(("switchLogin", switch_login))
    items.extend(
        [
            ("ursCode", context.user or context.account),
            ("logintoken", context.password),
            ("funcid", funcid),
            ("passtype", passtype),
        ]
    )
    if include_app_version:
        items.append(("app-version", context.app_version))
    if include_device_id:
        items.append(("device-id", context.device_id))
    if ignore is not None:
        items.append(("ignore", ignore))
    if smslogin_trust is not None:
        items.append(("smslogin_trust", smslogin_trust))
    if party is not None:
        items.append(("party", party))
    if qiye_use_md5 is not None:
        items.append(("qiye_use_md5", qiye_use_md5))
    items.extend(
        [
            ("returnUrs", return_urs),
            ("returnToken", return_token),
        ]
    )
    return _build_ordered_login_body(items)


def build_masterdevice_auth_body(
    *,
    account: str,
    secret: str,
    account_key: str = "aid",
    secret_key: str = "pwd",
    auth_type: str = "",
) -> dict[str, Any]:
    """Build the short `masterdevice` auth-style slice1 candidate."""
    if account_key not in {"aid", "uid"}:
        raise ValueError(f"Unsupported masterdevice account key: {account_key!r}")
    if secret_key != "pwd":
        raise ValueError(f"Unsupported masterdevice secret key: {secret_key!r}")
    return _build_ordered_login_body(
        [
            (account_key, account),
            ("authType", auth_type),
            (secret_key, secret),
        ]
    )


def build_sec_fingerprint_items(
    sec_name: str | None = None,
    sec_os_type: int | None = None,
    sec_mdc: str | None = None,
) -> list[tuple[str, Any]]:
    """`sec` device-fingerprint body items, in the client's own order."""
    if sec_name is None and sec_os_type is None and sec_mdc is None:
        return []
    items: list[tuple[str, Any]] = [("sec", 1)]
    if sec_name is not None:
        items.append(("secName", sec_name))
    if sec_os_type is not None:
        items.append(("secOsType", sec_os_type))
    if sec_mdc is not None:
        items.append(("secMdc", sec_mdc))
    return items


def local_sec_os_type(platform_name: str | None = None) -> int:
    """Platform code the client puts in `secOsType`."""
    resolved = (platform_name or sys.platform or "").lower()
    if resolved.startswith(("darwin", "mac")):
        return SEC_OS_TYPE_MACOS
    if resolved.startswith("ios"):
        return SEC_OS_TYPE_IOS
    return SEC_OS_TYPE_WINDOWS


def _query_dns_fully_qualified_name() -> str | None:
    """`GetComputerNameExW(ComputerNameDnsFullyQualified)` on Windows, else None."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        buffer = ctypes.create_unicode_buffer(256)
        size = wintypes.DWORD(len(buffer))
        if not ctypes.windll.kernel32.GetComputerNameExW(3, buffer, ctypes.byref(size)):
            return None
        return buffer.value or None
    except (AttributeError, OSError, ValueError):
        return None


def local_sec_name() -> str:
    """Machine name the client puts in `secName`."""
    query_dns = _resolve_wmsvr_hook(
        "_query_dns_fully_qualified_name",
        _query_dns_fully_qualified_name,
        _ORIG_QUERY_DNS_FQDN,
    )
    name = query_dns()
    if name:
        return name
    try:
        name = socket.gethostname()
    except OSError:
        name = ""
    if name:
        return name
    try:
        return socket.getfqdn()
    except OSError:
        return ""


def build_loginone_body(
    context: WmsvrLoginContext,
    *,
    password: str | None = None,
    passtype: str | None = None,
    password_mode: str = WMSVR_LOGINONE_PASSWORD_MD5,
    funcid: str = DEFAULT_WMSVR_LOGINONE_FUNCID,
    df: str = DEFAULT_WMSVR_LOGIN_DF,
    product: str = DEFAULT_WMSVR_LOGIN_PRODUCT,
    ignore: bool = True,
    qiye: bool = False,
    qiye_token: str = "",
    area: str | None = None,
    system: str | None = None,
    smslogin_trust: str = "",
    sec_name: str | None = None,
    sec_os_type: int | None = None,
    sec_mdc: str | None = None,
) -> dict[str, Any]:
    """Build the statically recovered common `wzpa:loginone` JSON slice1 body."""
    resolved_password = context.password if password is None else password
    if password_mode == WMSVR_LOGINONE_PASSWORD_MD5:
        source = resolved_password
        if len(source) > WMSVR_LOGINONE_MD5_SOURCE_LIMIT:
            source = source[:WMSVR_LOGINONE_MD5_SOURCE_LIMIT]
        resolved_password = md5(source.encode("utf-8")).hexdigest()
    elif password_mode != WMSVR_LOGINONE_PASSWORD_RAW:
        raise ValueError(
            f"password_mode must be {WMSVR_LOGINONE_PASSWORD_MD5!r} or "
            f"{WMSVR_LOGINONE_PASSWORD_RAW!r}, got {password_mode!r}"
        )
    if passtype is None:
        passtype = (
            WMSVR_LOGINONE_PASSTYPE_MD5
            if password_mode == WMSVR_LOGINONE_PASSWORD_MD5
            else WMSVR_LOGINONE_PASSTYPE_PLAIN
        )
    resolved_area = context.area if area is None else area
    resolved_system = context.system if system is None else system

    items: list[tuple[str, Any]] = [
        ("funcid", funcid),
        ("df", df),
        ("product", product),
        ("username", context.user or context.account),
    ]
    if funcid == DEFAULT_WMSVR_LOGIN_SWITCH_FUNCID:
        items.append(("qiyeToken", qiye_token))
    else:
        items.append(("password", resolved_password))
        items.append(("passtype", passtype))
    items.extend(
        [
            ("app-version", context.app_version),
            ("type", "1"),
            ("returnToken", "true"),
            ("returnUrs", "true"),
            ("device-id", context.device_id),
            ("ignore", "true" if ignore else "false"),
        ]
    )
    if qiye:
        items.extend(
            [
                ("qiye", True),
                ("area", resolved_area),
                ("sys", resolved_system),
                ("smslogin_trust", smslogin_trust),
            ]
        )
    items.extend(build_sec_fingerprint_items(sec_name, sec_os_type, sec_mdc))
    body = _build_ordered_login_body(items)
    for key, value in build_sec_fingerprint_items(sec_name, sec_os_type, sec_mdc):
        if key not in body:
            body[key] = value
    return body


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
    """Build one capture-shaped login-family segment."""
    segment = build_wmsvr_login_tlv(
        payload,
        ticket=ticket,
        trace_id=trace_id,
        device_info_json=device_info_json,
        client_id=client_id,
    )
    if not include_d1_control:
        return segment
    control = build_wmsvr_d1_control_tlv(
        WmsvrD1RequestContext(
            key_version=key_version,
            key_digest16=key_digest,
        )
    )
    return control + segment


def build_wmsvr_login_frame(
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
    session_key: bytes | None = None,
    seq: int = 1,
    word2: int = 0x0003,
    word4: int = DEFAULT_D1_RPC_WORD4,
    padding: str = DEFAULT_D1_SLICE_PADDING,
) -> tuple[WmsvrD1Frame, bytes, str]:
    """Build one login-family d1 frame plus the resolved session key/client id."""
    if body is not None and body_bytes is not None:
        raise ValueError("Pass either `body` or `body_bytes`, not both.")

    if method == LOGIN_METHOD_MASTERDEVICE:
        payload = build_masterdevice_payload(context)
    elif method in LOGIN_FAMILY_METHODS:
        payload = build_loginone_payload(context, method=method)
    else:
        raise ValueError(f"Unknown login method: {method}")

    resolved_client_id = client_id or build_default_wmsvr_login_client_id(
        context,
        method=method,
    )
    login_tlv = build_wmsvr_login_tlv(
        payload,
        ticket=context.master_fp,
        trace_id=context.master_sdid,
        device_info_json=context.device_info_json,
        client_id=resolved_client_id,
    )
    should_prefix_control = bool(include_d1_control)
    slice0 = login_tlv
    if prefix_version:
        slice0 = encode_tlv(TAG_VERSION, b"\x00\x00\x00\x01") + slice0
    if should_prefix_control:
        slice0 = (
            build_wmsvr_d1_control_tlv(
                WmsvrD1RequestContext(
                    key_version=key_version,
                    key_digest16=key_digest16,
                )
            )
            + slice0
        )

    resolved_body_bytes = body_bytes
    if body is not None:
        resolved_body_bytes = json.dumps(
            dict(body),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    resolved_session_key = session_key if session_key is not None else generate_wmsvr_d1_session_key()
    frame = build_wmsvr_d1_encrypted_frame(
        slice0,
        slice1_bytes=resolved_body_bytes or b"",
        session_key=resolved_session_key,
        seq=seq,
        word2=word2,
        word4=word4,
        padding=padding,
    )
    return frame, resolved_session_key, resolved_client_id


_ORIG_QUERY_DNS_FQDN = _query_dns_fully_qualified_name
