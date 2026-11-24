"""Static `mastercore.dll` anchor scanning, Chromium runtime inspection, and legacy HTTP helpers."""

from __future__ import annotations

import json
import logging
import re as _re
import shutil
import sqlite3
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import sha1
from pathlib import Path
from typing import Any

from ..discovery import discover_paths
from .bootstrap import WmsvrSession, _coerce_wmsvr_text
from .d1_wire import WmsvrRequest, WmsvrTransportError, build_request
from .tlv import AIRSYNC_COMMAND_NAMES, decode_tlv_envelope, encode_leb128

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static & runtime search term tables
# ---------------------------------------------------------------------------

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
    "secName",
    "secOsType",
    "secMdc",
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
# Token and command classifiers
# ---------------------------------------------------------------------------


def classify_wmsvr_auth_token(value: bytes | str | None) -> str:
    """Classify an observed Wmsvr auth/session token family."""
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
    """Return the static AirSync-style command name for a numeric command flag."""
    return AIRSYNC_COMMAND_NAMES.get(command, "")


def infer_wmsvr_http_auth_type(value: bytes | str | None) -> str:
    """Infer the observed HTTP `X-AUTH-TYPE` value from a confirmed token family."""
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


# ---------------------------------------------------------------------------
# Static & Chromium web runtime inspection models
# ---------------------------------------------------------------------------


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

    host: str = ""
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


# ---------------------------------------------------------------------------
# Static & Chromium web runtime scanners
# ---------------------------------------------------------------------------


def _iter_wmsvr_mastercore_candidates(install_root: Path | None = None) -> list[Path]:
    resolved_install_root = Path(install_root) if install_root is not None else discover_paths().install_root
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
    cleaned = _re.sub(
        r"((?:mastersess|mixmailtokens|masterfp|masterdi|sdid)\s*[:=]\s*)([A-Za-z0-9%+/_=\-]{12,})",
        r"\1<redacted>",
        cleaned,
        flags=_re.IGNORECASE,
    )
    cleaned = _re.sub(
        r"((?:authToken|coremailToken|mixmailToken|refreshToken)\s*[:=]\s*)([A-Za-z0-9%+/_=-]{12,})",
        r"\1<redacted>",
        cleaned,
        flags=_re.IGNORECASE,
    )
    cleaned = _re.sub(
        r'((?:mastersess|mixmailtokens|masterfp|masterdi|sdid|authToken|coremailToken|mixmailToken|refreshToken)\"\s*:\s*\")([^\"]{8,})\"',
        r'\1<redacted>"',
        cleaned,
        flags=_re.IGNORECASE,
    )
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
                WHERE host_key LIKE '%163.com%' OR host_key LIKE '%127.net%' OR host_key LIKE '%netease%'
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
        and any(term in str(item.get("server") or "") for term in ("mail.163.com", "dashi.163.com", "127.net"))
    }
    return sorted(server for server in servers if server)


def discover_wmsvr_login_static_hints(install_root: Path | None = None) -> WmsvrLoginStaticHints:
    """Scan the installed `mastercore.dll` for confirmed login/auth string hints."""
    for dll_path in _iter_wmsvr_mastercore_candidates(install_root):
        try:
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
    runtime_state.relevant_servers = _load_relevant_network_servers(snapshot_root / "Network Persistent State")
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


# ---------------------------------------------------------------------------
# Legacy request builders & HTTP analysis scaffolding
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


def build_compose_request(
    session: WmsvrSession,
    *,
    to: list[str],
    subject: str = "",
    body_text: str = "",
    body_html: str = "",
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    action: str = "deliver",
) -> WmsvrRequest:
    """Build a mbox:compose request to send email."""
    body: dict[str, Any] = {
        "action": action,
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
    return build_request(session, "mbox:compose", body)


def build_http_url(session: WmsvrSession) -> str:
    """Build the Wmsvr HTTP endpoint URL from session fields."""
    return f"{session.proto}://{session.host}:{session.port}"


def build_http_headers(session: WmsvrSession) -> dict[str, str]:
    """Build HTTP headers for a Wmsvr request (legacy analysis helper)."""
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
    """Build the currently confirmed `mail.163.com`-style runtime HTTP headers."""
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


def build_wire_body(
    envelope: bytes,
    body_json: bytes,
    *,
    length_prefixed: bool = True,
) -> bytes:
    """Combine TLV envelope and JSON body into the legacy HTTP POST body."""
    if length_prefixed:
        return (
            encode_leb128(len(envelope))
            + envelope
            + encode_leb128(len(body_json))
            + body_json
        )
    return envelope + body_json


@dataclass(slots=True)
class WmsvrResponse:
    """Response from a legacy Wmsvr HTTP request."""

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
        """Try to extract JSON from the response."""
        try:
            return json.loads(self.raw_body)
        except (json.JSONDecodeError, ValueError):
            pass
        idx = self.raw_body.find(b"{")
        if idx > 0:
            try:
                return json.loads(self.raw_body[idx:])
            except (json.JSONDecodeError, ValueError):
                pass
        return None


def send_request(
    request: WmsvrRequest,
    *,
    timeout: float = 15.0,
    length_prefixed: bool = True,
    verify_ssl: bool = False,
) -> WmsvrResponse:
    """Send a Wmsvr request via legacy HTTP POST and return the response."""
    import ssl
    import urllib.error
    import urllib.request

    session = request.session
    url = build_http_url(session)
    headers = build_http_headers(session)
    envelope_bytes, body_bytes = request.to_wire()
    wire_body = build_wire_body(envelope_bytes, body_bytes, length_prefixed=length_prefixed)

    logger.debug(
        "wmsvr POST %s method=%s envelope=%d body=%d wire=%d",
        url,
        request.method,
        len(envelope_bytes),
        len(body_bytes),
        len(wire_body),
    )

    req = urllib.request.Request(url, data=wire_body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)

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


# ---------------------------------------------------------------------------
# Frida dump & session serialization helpers
# ---------------------------------------------------------------------------


def parse_session_from_frida_log(log_text: str) -> WmsvrSession:
    """Parse a WmsvrSession from the output of session_dump_readonly.js."""
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

    if not session.device_id and session.device_info:
        try:
            info = json.loads(session.device_info)
            session.device_id = info.get("deviceId", "")
        except (json.JSONDecodeError, ValueError):
            pass

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
