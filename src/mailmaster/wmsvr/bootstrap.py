"""Persisted `app.db` bootstrap loaders, route/ticket helpers, and session models."""

from __future__ import annotations

import base64
import json
import os
import re as _re
import sqlite3
import struct
from collections.abc import Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from hashlib import md5
from pathlib import Path
from typing import Any, cast

from ..protocol_config import decrypt_runtime_protected_blob
from ..store import copy_sqlite_snapshot
from .tlv import (
    DEFAULT_WMSVR_LOGIN_CLIENT_PHASE,
    DEFAULT_WMSVR_LOGIN_COUNTERS,
    DEFAULT_WMSVR_LOGIN_LOCALE,
    WMSVR_ROUTE_PREFIX,
    WMSVR_SERVICE_TYPE_D1,
    _WMSVR_ROUTE_RE,
)

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


# ---------------------------------------------------------------------------
# Route / ticket helpers
# ---------------------------------------------------------------------------


@dataclass
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


# ---------------------------------------------------------------------------
# Session & bootstrap data models
# ---------------------------------------------------------------------------


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
        return not _normalize_account(self.locate_id.user) and not _normalize_account(self.locate_id.locate_user)

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
            if key
            not in {
                "user",
                "password",
                "area",
                "sys",
                "refreshToken",
                "corpOAuth",
                "qiyeToken",
                "pass2fa",
            }
        }
        return cls(
            user=str(data.get("user") or ""),
            password=str(data.get("password") or ""),
            area=str(data.get("area") or ""),
            system=str(data.get("sys") or ""),
            corp_oauth=str(data.get("corpOAuth") or ""),
            qiye_token=str(data.get("qiyeToken") or ""),
            pass2fa=str(data.get("pass2fa") or ""),
            extras=extras,
        )


@dataclass(slots=True)
class WmsvrLoginContext:
    """Persisted + decrypted inputs that feed the Wmsvr login chain."""

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
        wanted_service_types = {int(value) for value in service_types} if service_types is not None else None
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


# ---------------------------------------------------------------------------
# SQLite snapshot & config loaders
# ---------------------------------------------------------------------------


def _copy_sqlite_for_read(path: Path) -> Path:
    return copy_sqlite_snapshot(path)


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
    with closing(_connect_sqlite(app_db, as_bytes=True)) as conn:
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


def parse_master_device_info(raw_value: str | bytes | Mapping[str, Any] | None) -> WmsvrMasterDeviceInfo:
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
        try:
            payload = json.loads(decrypt_runtime_protected_blob(raw_value, install_root).decode("utf-8"))
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
    """
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
        try:
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


def normalize_wmsvr_client_id_prefix(prefix: str) -> str:
    """Normalize one Wmsvr client-id prefix to the confirmed 8-hex shape."""
    normalized = "".join(char for char in str(prefix).upper() if char in "0123456789ABCDEF")
    if len(normalized) != 8:
        raise ValueError(f"Wmsvr client-id prefix must normalize to 8 hex chars, got {prefix!r}")
    return normalized


def generate_wmsvr_client_id_prefix(seed: bytes | str | None = None) -> str:
    """Return an 8-hex client-id prefix matching `mailwin|<8HEX>.<phase>.<counter>`."""
    if seed is None:
        return os.urandom(4).hex().upper()
    raw_seed = seed.encode("utf-8") if isinstance(seed, str) else seed
    return md5(raw_seed).hexdigest()[:8].upper()


def build_wmsvr_client_id(
    *,
    prefix: str,
    phase: int = DEFAULT_WMSVR_LOGIN_CLIENT_PHASE,
    counter: int = 1,
) -> str:
    """Build one capture-shaped Wmsvr client id."""
    if phase < 0:
        raise ValueError(f"Wmsvr client-id phase must be non-negative, got {phase}")
    if counter < 0:
        raise ValueError(f"Wmsvr client-id counter must be non-negative, got {counter}")
    normalized_prefix = normalize_wmsvr_client_id_prefix(prefix)
    return f"mailwin|{normalized_prefix}.{phase}.{counter}"


def build_default_wmsvr_login_client_id(
    context: WmsvrLoginContext,
    *,
    method: str,
    prefix: str | None = None,
) -> str:
    """Build a login-family client id that matches the confirmed wire shape."""
    seed = "|".join(
        value
        for value in (
            context.account,
            context.device_id,
            context.master_sdid,
            context.app_version,
        )
        if value
    )
    resolved_prefix = (
        normalize_wmsvr_client_id_prefix(prefix)
        if prefix is not None and prefix != ""
        else generate_wmsvr_client_id_prefix(seed or None)
    )
    counter = DEFAULT_WMSVR_LOGIN_COUNTERS.get(method, 1)
    return build_wmsvr_client_id(
        prefix=resolved_prefix,
        phase=DEFAULT_WMSVR_LOGIN_CLIENT_PHASE,
        counter=counter,
    )
