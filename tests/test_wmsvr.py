import base64
import json
from binascii import unhexlify

import pytest
import socket
import sqlite3
import sys
import threading
from hashlib import md5, pbkdf2_hmac
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mailmaster import wmsvr as wmsvr_module  # noqa: E402
from mailmaster.wmsvr import (
    WmsvrLoginContext,
    WmsvrLoginResponse,
    WmsvrSession,
    summarize_login_response,
    classify_captured_tlv_segment,
    decode_tlv_envelope,
    decode_captured_tlv_record,
    extract_captured_method_segments,
    extract_tlv_method_name,
    split_captured_tlv_records,
)
from mailmaster import (
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_GET_SETTINGS_SIGNATURE,
    DEFAULT_D1_KEY_VERSION,
    DEFAULT_D1_RPC_WORD2,
    DEFAULT_D1_RPC_WORD4,
    D1_SLICE_PADDING_NUL,
    LOGIN_METHOD_LOGINMAIL,
    LOGIN_METHOD_LOGINONE,
    MailMaster,
    MailMasterPaths,
    WmsvrControlPayload,
    WmsvrD1RequestContext,
    WmsvrPeerCandidate,
    WmsvrStartupPayload,
    WMSVR_METHOD_UPDATE_MESSAGE_INFOS,
    app_version_to_inner,
    build_d1_slice_layout,
    build_get_settings_frame,
    build_get_settings_tlv,
    build_init_session_headers,
    build_login_response_flags_body,
    build_loginmail_body,
    build_loginmail_password_body,
    build_loginone_body,
    build_loginone_payload,
    build_logincorp_body,
    build_logintoken_body,
    build_masterdevice_auth_body,
    build_masterdevice_payload,
    build_observed_runtime_headers,
    build_sec_fingerprint_items,
    build_update_message_infos_body,
    build_update_message_infos_frame,
    local_sec_name,
    local_sec_os_type,
    build_default_wmsvr_login_client_id,
    build_wmsvr_client_id,
    build_wmsvr_control_tlv,
    build_wmsvr_d1_control_tlv,
    build_wmsvr_d1_encrypted_frame,
    build_wmsvr_d1_request_context,
    build_wmsvr_d1_request_frame,
    build_wmsvr_key_exchange_frame,
    build_wmsvr_login_frame,
    build_wmsvr_login_segment,
    build_wmsvr_login_tlv,
    build_wmsvr_pre_auth_frame,
    classify_wmsvr_auth_token,
    build_wmsvr_login_context,
    build_wmsvr_startup_tlv,
    build_compose_request,
    compute_wmsvr_public_key_digest,
    discover_wmsvr_login_static_hints,
    discover_wmsvr_web_runtime_state,
    decode_get_settings_key_update,
    decrypt_wmsvr_d1_frame_slices,
    decrypt_wmsvr_d1_slice,
    der_bytes_to_public_key_pem,
    describe_d1_frame,
    encrypt_wmsvr_d1_slice,
    exchange_get_settings,
    get_wmsvr_hardcoded_public_key,
    infer_wmsvr_http_auth_type,
    inspect_wmsvr_auth_surface,
    generate_wmsvr_d1_session_key,
    load_server_configs,
    load_wmsvr_hardcoded_public_keys,
    load_wmsvr_bootstrap,
    lookup_airsync_command_name,
    normalize_d1_key_digest,
    normalize_wmsvr_client_id_prefix,
    pad_d1_slice,
    parse_d1_frame,
    parse_get_settings_response,
    parse_wmsvr_route,
    parse_wmsvr_control_tlv,
    parse_wmsvr_startup_tlv,
    recv_d1_frame,
    refresh_wmsvr_master_session,
    route_to_http_ticket,
    send_d1_frame,
    ticket_to_wmsvr_route,
    wrap_wmsvr_d1_session_key,
    unwrap_wmsvr_key_update_blob,
)


APP_CONFIG_IV = b"0123456789ABCDEF"
APP_CONFIG_SALT = "unit-test-salt"
APP_CONFIG_FIXED_PASSWORD = "unit-test-fixed-password"
APP_CONFIG_RUNTIME_PASSWORD = "unit-test-runtime-password"


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def _encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(_pkcs7_pad(data)) + encryptor.finalize()


def _encrypt_protected_blob(data: bytes, password: str) -> bytes:
    key = pbkdf2_hmac("sha1", password.encode("utf-8"), APP_CONFIG_SALT.encode("utf-8"), 256, dklen=32)
    return _encrypt_aes_cbc(data, key, APP_CONFIG_IV)


def _patch_app_config_crypto(monkeypatch) -> None:
    monkeypatch.setattr(
        "mailmaster.protocol_config.get_security_constants",
        lambda install_root=None: (APP_CONFIG_IV, APP_CONFIG_SALT, APP_CONFIG_FIXED_PASSWORD),
    )
    monkeypatch.setattr(
        "mailmaster.protocol_config.get_runtime_password",
        lambda install_root=None: APP_CONFIG_RUNTIME_PASSWORD,
    )


def _build_app_db(tmp_path: Path) -> Path:
    path = tmp_path / "app.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE AppConfig (Key TEXT PRIMARY KEY, Value TEXT)")
    conn.execute(
        "CREATE TABLE Account (ID INTEGER PRIMARY KEY, Type INTEGER, Valid INTEGER, Name TEXT, Email TEXT, DataPath TEXT)"
    )
    conn.execute(
        "INSERT INTO Account (ID, Type, Valid, Name, Email, DataPath) VALUES (?, ?, ?, ?, ?, ?)",
        (7, 1, 1, "tester@163.com", "tester@163.com", r"C:\MailMasterData\tester@163.com_7"),
    )
    locate_cache = [
        {
            "locate_id": {"locate_user": "tester@163.com", "service_type": 4, "user": "tester@163.com"},
            "service_cache": {
                "prefer_ipv6": True,
                "candidates": [
                    {"host": "2408:876a:1110:100:0:9:30:4", "is_ip_v6": True, "port": 443},
                    {"host": "220.197.30.4", "is_ip_v6": False, "port": 443},
                ],
            },
        },
        {
            "locate_id": {"locate_user": "", "service_type": 3, "user": ""},
            "service_cache": {
                "prefer_ipv6": False,
                "candidates": [
                    {"host": "220.197.30.5", "is_ip_v6": False, "port": 443},
                ],
            },
        },
    ]
    app_config_values: list[tuple[str, object]] = [
        (
            "CloudInfo",
            sqlite3.Binary(
                _encrypt_protected_blob(
                    json.dumps(
                        {
                            "CloudId": "cloud-id-123",
                            "CloudToken": "mastersess-token-456",
                            "RelateEmails": ["tester@163.com", "alias@example.com"],
                            "SyncTag": "sync-tag-789",
                            "weixin": {"uid": "wx-1"},
                        },
                        ensure_ascii=False,
                    ).encode("utf-8"),
                    APP_CONFIG_RUNTIME_PASSWORD,
                )
            ),
        ),
        (
            "MasterDI",
            json.dumps(
                {
                    "appVersion": "5.5.2.1006",
                    "configId": "10",
                    "devType": "pc",
                    "deviceId": "WINTESTDEVICEID",
                    "md5Sign": "abc123",
                },
                ensure_ascii=False,
            ),
        ),
        ("MasterFP", "MASTERFPVALUE"),
        ("MasterSdid", "1027626894865072128"),
        ("FakeDeviceId", "WINTESTDEVICEID"),
        ("WebuiPubKey", "PUBKEY"),
        ("LocateCache", json.dumps(locate_cache, ensure_ascii=False)),
        (
            "WzpLocateAddresses",
            sqlite3.Binary(
                _encrypt_protected_blob(
                    json.dumps(
                        {
                            "addresses": [
                                "https://config1.mail.163.com",
                                "https://config2.mail.163.com",
                            ]
                        },
                        ensure_ascii=False,
                    ).encode("utf-8"),
                    APP_CONFIG_FIXED_PASSWORD,
                )
            ),
        ),
    ]
    conn.executemany("INSERT INTO AppConfig (Key, Value) VALUES (?, ?)", app_config_values)
    conn.commit()
    conn.close()
    return path


def _build_mail_db(tmp_path: Path) -> Path:
    path = tmp_path / "mail.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE AccountConfig (Key TEXT PRIMARY KEY, Value BLOB)")
    config = {
        "user": "tester@163.com",
        "pass": "",
        "area": "",
        "sys": "",
        "refreshToken": "REFRESH",
    }
    conn.execute(
        "INSERT INTO AccountConfig (Key, Value) VALUES (?, ?)",
        ("WmsvrServerConfig", json.dumps(config, ensure_ascii=False).encode("utf-8")),
    )
    conn.commit()
    conn.close()
    return path


def _build_fake_install_root(tmp_path: Path) -> Path:
    install_root = tmp_path / "Application" / "5.5.2.1006"
    install_root.mkdir(parents=True, exist_ok=True)
    (install_root / "mastercore.dll").write_bytes(
        b"\x00".join(
            [
                b"user:validateSession",
                b"wzpa:loginone",
                b"wzpmmc:masterdevice",
                b"switchLogin",
                b"funcid",
                b"returnToken",
                b"authToken",
                b"mixmailToken",
                b"LOGIN_ACCOUNT",
                b"VALIDATE_MASTER_SESSION",
                b"masterToken",
                b"/ud_proxy/info",
                b"mail.163.com",
            ]
        )
    )
    return install_root.parent.parent


def _build_web_cache_root(tmp_path: Path) -> Path:
    local_root = tmp_path / "LocalMailMaster"
    cache_root = local_root / "web" / "cache"
    (cache_root / "Cache").mkdir(parents=True, exist_ok=True)
    (cache_root / "Local Storage" / "leveldb").mkdir(parents=True, exist_ok=True)
    (cache_root / "Session Storage").mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(cache_root / "Cookies")
    conn.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)")
    conn.execute(
        "INSERT INTO cookies (host_key, name, value, encrypted_value) VALUES (?, ?, ?, ?)",
        (".mail.163.com", "SESSION", "", b"encrypted-cookie"),
    )
    conn.commit()
    conn.close()

    (cache_root / "Network Persistent State").write_text(
        json.dumps(
            {
                "net": {
                    "http_server_properties": {
                        "servers": [
                            {"server": "https://mail.163.com", "supports_spdy": True},
                            {"server": "https://dashi.163.com", "supports_spdy": True},
                            {"server": "https://example.com", "supports_spdy": True},
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (cache_root / "Cache" / "data_3").write_bytes(
        (
            b"HTTP/1.1 200\x00"
            b"access-control-allow-headers: Content-Type,mastersess,masterfp,masterdi,sdid,browserfp,mixmailTokens\x00"
            b"/ud_proxy/info\x00mail.163.com\x00"
        )
    )
    (cache_root / "Local Storage" / "leveldb" / "000003.log").write_bytes(
        b"META:mailmaster://static.dashi.163.com\x00masterdi\x00mixmailToken\x00"
    )
    (cache_root / "Session Storage" / "000003.log").write_bytes(
        b"namespace-123-mailmaster://static.dashi.163.com/\x00mastersess\x00"
    )
    return local_root


def _build_signed_key_update_blob(
    sibling_private_key: rsa.RSAPrivateKey,
    inner_public_key_der: bytes,
) -> bytes:
    block_size = sibling_private_key.key_size // 8
    padding_len = block_size - len(inner_public_key_der) - 3
    assert padding_len >= 8
    encoded_message = b"\x00\x01" + (b"\xFF" * padding_len) + b"\x00" + inner_public_key_der
    private_numbers = sibling_private_key.private_numbers()
    signed_int = pow(
        int.from_bytes(encoded_message, "big"),
        private_numbers.d,
        private_numbers.public_numbers.n,
    )
    return signed_int.to_bytes(block_size, "big")


def test_load_wmsvr_bootstrap_reads_app_config(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    _patch_app_config_crypto(monkeypatch)

    bootstrap = load_wmsvr_bootstrap(app_db)

    assert bootstrap.cloud_info.cloud_id == "cloud-id-123"
    assert bootstrap.cloud_info.cloud_token == "mastersess-token-456"
    assert bootstrap.cloud_info.relate_emails == ["tester@163.com", "alias@example.com"]
    assert bootstrap.cloud_info.sync_tag == "sync-tag-789"
    assert bootstrap.master_device_info.app_version == "5.5.2.1006"
    assert bootstrap.master_device_info.device_id == "WINTESTDEVICEID"
    assert bootstrap.master_fp == "MASTERFPVALUE"
    assert bootstrap.master_sdid == "1027626894865072128"
    assert bootstrap.fake_device_id == "WINTESTDEVICEID"
    assert bootstrap.webui_pub_key == "PUBKEY"
    assert bootstrap.cloud_info_ciphertext_b64
    assert bootstrap.wzp_locate_addresses_b64 == base64.b64encode(
        _encrypt_protected_blob(
            json.dumps(
                {"addresses": ["https://config1.mail.163.com", "https://config2.mail.163.com"]},
                ensure_ascii=False,
            ).encode("utf-8"),
            APP_CONFIG_FIXED_PASSWORD,
        )
    ).decode("ascii")
    assert len(bootstrap.locate_entries) == 2


def test_discover_wmsvr_login_static_hints_scans_mastercore(tmp_path: Path) -> None:
    install_root = _build_fake_install_root(tmp_path)

    hints = discover_wmsvr_login_static_hints(install_root)

    assert hints.source_dll.endswith("mastercore.dll")
    assert "wzpa:loginone" in hints.login_methods
    assert "wzpmmc:masterdevice" in hints.login_methods
    assert "switchLogin" in hints.login_request_fields
    assert "returnToken" in hints.login_request_fields
    assert "authToken" in hints.auth_response_fields
    assert "LOGIN_ACCOUNT" in hints.jsbridge_methods
    assert "masterToken" in hints.http_auth_types
    assert "/ud_proxy/info" in hints.endpoint_hints


def test_discover_wmsvr_web_runtime_state_scans_cache_snapshot(tmp_path: Path) -> None:
    local_root = _build_web_cache_root(tmp_path)

    runtime_state = discover_wmsvr_web_runtime_state(local_root)

    assert runtime_state.source_root.endswith(r"web\cache")
    assert any(item.host == ".mail.163.com" for item in runtime_state.cookie_hints)
    assert "https://mail.163.com" in runtime_state.relevant_servers
    assert any(hit.term == "mastersess" for hit in runtime_state.hits)
    assert any(hit.term == "/ud_proxy/info" for hit in runtime_state.hits)
    assert any(hit.term == "mixmailToken" for hit in runtime_state.hits)


def test_inspect_wmsvr_auth_surface_combines_static_and_runtime(tmp_path: Path) -> None:
    install_root = _build_fake_install_root(tmp_path)
    local_root = _build_web_cache_root(tmp_path)

    surface = inspect_wmsvr_auth_surface(install_root=install_root, local_root=local_root)

    assert "wzpa:loginone" in surface.static_hints.login_methods
    assert any(hit.term == "mastersess" for hit in surface.web_runtime_state.hits)


def test_wmsvr_bootstrap_filters_candidates_by_account_and_service(tmp_path: Path) -> None:
    app_db = _build_app_db(tmp_path)
    bootstrap = load_wmsvr_bootstrap(app_db)

    service_entries = bootstrap.get_locate_entries(account="tester@163.com", service_types=[4])
    peers = bootstrap.get_candidate_peers(account="tester@163.com", service_types=[4])

    assert len(service_entries) == 1
    assert service_entries[0].service_type == 4
    assert service_entries[0].prefer_ipv6 is True
    assert [peer.host for peer in peers] == [
        "2408:876a:1110:100:0:9:30:4",
        "220.197.30.4",
    ]


def test_refresh_wmsvr_master_session_uses_persisted_cloud_token(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    _patch_app_config_crypto(monkeypatch)
    bootstrap = load_wmsvr_bootstrap(app_db)

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://config.dashi.163.com/init/session"
        assert request.headers["masterfp"] == "MASTERFPVALUE"
        assert request.headers["token"] == "mastersess-token-456"
        assert request.headers["content-type"] == "text/plain"
        assert request.headers["user-agent"] == "MailMasterPC/5.5.2.1006"
        assert request.headers["x-ntsm-ftid"] == "mailwin|test.http_1"
        assert request.content == b""
        return httpx.Response(
            200,
            json={
                "code": 200,
                "desc": "DONE",
                "success": "true",
                "result": {
                    "token": "refreshed-mastersess-token",
                    "tokenRefreshInterval": 3600,
                },
            },
        )

    result = refresh_wmsvr_master_session(
        bootstrap,
        ftid="mailwin|test.http_1",
        transport=httpx.MockTransport(handler),
    )

    assert result.ok is True
    assert result.code == 200
    assert result.desc == "DONE"
    assert result.token == "refreshed-mastersess-token"
    assert result.token_refresh_interval == 3600


def test_mailmaster_exposes_wmsvr_bootstrap(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    _patch_app_config_crypto(monkeypatch)
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=tmp_path,
        app_db=app_db,
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mailmaster = MailMaster(paths=paths)

    bootstrap = mailmaster.get_wmsvr_bootstrap("tester@163.com")
    account_bootstrap = mailmaster.open_account("tester@163.com").get_wmsvr_bootstrap()

    assert bootstrap.master_fp == "MASTERFPVALUE"
    assert bootstrap.cloud_info.master_id == "cloud-id-123"
    assert account_bootstrap.master_device_info.device_id == "WINTESTDEVICEID"


def test_app_version_to_inner_matches_confirmed_singleton_mapping() -> None:
    assert app_version_to_inner("5.5.2.1006") == 50050021006


def test_wmsvr_login_context_combines_bootstrap_and_server_config(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    mail_db = _build_mail_db(tmp_path)
    _patch_app_config_crypto(monkeypatch)
    bootstrap = load_wmsvr_bootstrap(app_db)

    monkeypatch.setattr("mailmaster.protocol_config.decrypt_account_config_blob", lambda blob, install_root=None: json.loads(blob))
    monkeypatch.setattr("mailmaster.protocol_config.decrypt_config_password", lambda password_b64, install_root=None: "")
    server_configs = load_server_configs(mail_db)

    context = build_wmsvr_login_context("tester@163.com", server_configs, bootstrap)

    assert context.user == "tester@163.com"
    assert context.config_id == "10"
    assert context.app_version == "5.5.2.1006"
    assert context.appver_inner == 50050021006
    assert context.device_id == "WINTESTDEVICEID"
    assert context.cloud_id == "cloud-id-123"
    assert context.cloud_token == "mastersess-token-456"
    assert context.master_fp == "MASTERFPVALUE"
    assert [peer.host for peer in context.peer_candidates] == ["220.197.30.5"]


def test_login_payload_builders_follow_confirmed_tag_map(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    mail_db = _build_mail_db(tmp_path)
    bootstrap = load_wmsvr_bootstrap(app_db)

    monkeypatch.setattr("mailmaster.protocol_config.decrypt_account_config_blob", lambda blob, install_root=None: json.loads(blob))
    monkeypatch.setattr("mailmaster.protocol_config.decrypt_config_password", lambda password_b64, install_root=None: "")
    context = build_wmsvr_login_context("tester@163.com", load_server_configs(mail_db), bootstrap)

    loginone = build_loginone_payload(context)
    masterdevice = build_masterdevice_payload(context)

    loginone_records = {tag: value for tag, value in loginone.records}
    masterdevice_records = {tag: value for tag, value in masterdevice.records}

    assert loginone_records[0x0100] == b"wzpa:loginone"
    assert loginone_records[0x010F] == b"WINTESTDEVICEID"
    assert loginone_records[0x0110] == b"10"
    assert loginone_records[0x0112] == b"5.5.2.1006"
    assert loginone_records[0x0204] == b"zh_CN"

    assert masterdevice_records[0x0100] == b"wzpmmc:masterdevice"
    assert masterdevice_records[0x010F] == b"WINTESTDEVICEID"
    assert masterdevice_records[0x0112] == bytes.fromhex("0000000ba736b68e")
    assert masterdevice_records[0x0110] == b"10"


def test_login_json_body_builders_follow_recovered_field_order_and_types() -> None:
    context = WmsvrLoginContext(
        account="tester@163.com",
        user="tester@163.com",
        password="secret-pass",
        area="86",
        system="sys",
        app_version="5.5.2.1006",
        device_id="WINTESTDEVICEID",
        master_sdid="1027626894865072128",
    )

    assert list(build_loginmail_body(context).items()) == [
        ("username", "tester@163.com"),
        ("ursCode", "200"),
        ("funcid", "logintoken"),
        ("type", "1"),
        ("df", "mailmaster_pc"),
        ("product", "mailmaster_win"),
        ("device-id", "WINTESTDEVICEID"),
        ("sdid", "1027626894865072128"),
        ("returnUrs", True),
        ("returnToken", True),
        ("party", "mail"),
    ]
    assert list(build_logincorp_body(context, access_token="corp-token").items()) == [
        ("username", "tester@163.com"),
        ("accessToken", "corp-token"),
        ("funcid", "logintoken"),
        ("type", "1"),
        ("df", "mailmaster_pc"),
        ("product", "mailmaster_win"),
        ("device-id", "WINTESTDEVICEID"),
        ("sdid", "1027626894865072128"),
        ("returnUrs", True),
        ("returnToken", True),
    ]
    # The client's normal path sends `passtype="0"` with the *MD5 hex* of the
    # password (`0x10a25322` -> `0x1005a370`), not the password as typed.
    assert list(build_loginone_body(context).items()) == [
        ("funcid", "loginone"),
        ("df", "mailmaster_pc"),
        ("product", "mailmaster_win"),
        ("username", "tester@163.com"),
        ("password", md5(b"secret-pass").hexdigest()),
        ("passtype", "0"),
        ("app-version", "5.5.2.1006"),
        ("type", "1"),
        ("returnToken", "true"),
        ("returnUrs", "true"),
        ("device-id", "WINTESTDEVICEID"),
        ("ignore", "true"),
    ]


def _captured_length_session() -> WmsvrSession:
    """Session placeholders whose *lengths* mirror the mark-read capture.

    Only lengths matter for the envelope-size claim, so every value is a
    same-length placeholder instead of the captured session material.
    """
    return WmsvrSession(
        token="T" * 32,
        route="Coremail:" + "0" * 13 + "%" + "T" * 32 + "%" + "p" * 30,
        host="203.0.113.7",
        port=443,
        account_desc="10|placeholder@ex.com",
        ticket="F" * 218,
        trace_id="1" * 19,
        device_info="D" * 149,
        client_id="mailwin|00TEST00.1.109",  # captured tag 0x0014 is 22 bytes
    )


def test_update_message_infos_body_matches_the_captured_request() -> None:
    """The mark-read body is copied from a real capture, not invented.

    `artifacts/logs/captures_controlled_20260315_105258.json` captures #43/#44/#45
    are three real `mbox:updateMessageInfos` requests; this pins capture #43's
    plaintext body byte for byte (70 bytes, `attrs` before `ids`).
    """
    captured = '{"attrs":{"flags":{"read":true}},"ids":["755:xtbC8wM3tWm2HKMfrwAA3i"]}'

    body = build_update_message_infos_body(["755:xtbC8wM3tWm2HKMfrwAA3i"], read=True)
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False)

    assert encoded == captured
    assert len(encoded.encode("utf-8")) == 70
    assert WMSVR_METHOD_UPDATE_MESSAGE_INFOS == "mbox:updateMessageInfos"


def test_update_message_infos_body_mirrors_read_for_unread() -> None:
    # Mark-unread is the same key with the mirrored value; only `true` is captured,
    # so this test documents the shape rather than claiming capture evidence.
    body = build_update_message_infos_body(["756:xtbC9B-JSGrM8v83VAAA3i"], read=False)

    assert json.dumps(body, separators=(",", ":")) == (
        '{"attrs":{"flags":{"read":false}},"ids":["756:xtbC9B-JSGrM8v83VAAA3i"]}'
    )


def test_update_message_infos_body_requires_at_least_one_id() -> None:
    with pytest.raises(ValueError):
        build_update_message_infos_body([], read=True)


def test_update_message_infos_envelope_matches_the_captured_length() -> None:
    """The write request's slice0 is the same 11-record runtime envelope.

    The capture's record lengths are 4/23/32/86/11/2/21/218/19/149/22 (`updateMessageInfos`
    is 23 bytes, as its method record shows), which is 587 payload bytes + 35 header
    bytes = 622 — the length the capture analysis reports — padding to the 624 the
    wire carried as `section_len`. Values are same-length placeholders.
    """
    session = _captured_length_session()

    envelope = wmsvr_module.build_envelope(session, WMSVR_METHOD_UPDATE_MESSAGE_INFOS)

    assert len(envelope) == 622
    assert (len(envelope) + 15) // 16 * 16 == 624


def test_update_message_infos_frame_pads_both_slices() -> None:
    session = _captured_length_session()
    frame, body_json = build_update_message_infos_frame(
        WmsvrD1RequestContext(),
        session,
        ["755:xtbC8wM3tWm2HKMfrwAA3i"],
        read=True,
    )

    assert frame.header.len0 == 624
    assert frame.header.len1 == 80  # pad16 of the 70-byte body
    assert json.dumps(json.loads(body_json), separators=(",", ":")) == body_json


def test_loginone_body_binds_passtype_to_the_password_encoding() -> None:
    """`passtype` and `password` cannot be chosen independently.

    Read off the client's `0x10a24970`: the normal path (`0x10a25322` for a password
    of at most 16 chars, `0x10a2504c` above that) sends `passtype="0"` with
    `md5hex(password)`, and only the `[+0x1d1]`-set branch (`0x10a2523a`) sends
    `passtype="1"` with the password as typed. Sending a plaintext password under
    `passtype="0"` is a pairing no branch produces, so the default must hash.
    """
    context = _full_login_context()

    default = build_loginone_body(context)

    assert default["passtype"] == "0"
    assert default["password"] == md5(context.password.encode("utf-8")).hexdigest()
    assert context.password not in json.dumps(default)

    raw = build_loginone_body(context, password_mode="raw")

    assert raw["passtype"] == "1"
    assert raw["password"] == context.password


def test_loginone_body_truncates_a_long_password_before_hashing() -> None:
    """The client hashes `password[:16]` when the password is longer than 16 chars."""
    context = _full_login_context()
    long_password = "p" * 40

    body = build_loginone_body(context, password=long_password)

    assert body["password"] == md5(b"p" * 16).hexdigest()
    assert body["password"] != md5(long_password.encode("utf-8")).hexdigest()


def test_loginone_body_rejects_an_unknown_password_mode() -> None:
    context = _full_login_context()

    with pytest.raises(ValueError, match="password_mode"):
        build_loginone_body(context, password_mode="whatever")


def test_login_probe_body_builders_cover_new_static_candidates() -> None:
    context = WmsvrLoginContext(
        account="tester@163.com",
        user="tester@163.com",
        password="secret-pass",
        app_version="5.5.2.1006",
        device_id="WINTESTDEVICEID",
        master_sdid="1027626894865072128",
        cloud_id="cloud-id-123",
    )

    assert list(build_login_response_flags_body().items()) == [
        ("returnUrs", True),
        ("returnToken", True),
    ]
    assert list(build_login_response_flags_body(return_urs=1, return_token=1).items()) == [
        ("returnUrs", 1),
        ("returnToken", 1),
    ]
    assert list(
        build_logintoken_body(
            context,
            access_token="cloud-id-123",
            return_urs=1,
            return_token=1,
        ).items()
    ) == [
        ("accessToken", "cloud-id-123"),
        ("funcid", "logintoken"),
        ("type", "1"),
        ("returnUrs", 1),
        ("returnToken", 1),
    ]
    assert list(
        build_loginmail_password_body(
            context,
            switch_login=1,
            ignore=5,
            smslogin_trust=True,
            qiye_use_md5=1,
        ).items()
    ) == [
        ("switchLogin", 1),
        ("ursCode", "tester@163.com"),
        ("logintoken", "secret-pass"),
        ("funcid", "123456"),
        ("passtype", 6),
        ("app-version", "5.5.2.1006"),
        ("device-id", "WINTESTDEVICEID"),
        ("ignore", 5),
        ("smslogin_trust", True),
        ("qiye_use_md5", 1),
        ("returnUrs", 1),
        ("returnToken", 1),
    ]
    assert list(
        build_masterdevice_auth_body(account="tester@163.com", secret="secret-pass").items()
    ) == [
        ("aid", "tester@163.com"),
        ("pwd", "secret-pass"),
    ]


def test_capture_record_helpers_split_concatenated_segments() -> None:
    records = [
        {"tag": 0x0107, "len": 4, "hex": "00000001"},
        {"tag": 0x0100, "len": 16, "hex": "777a703a6c6973744d65737361676573"},
        {"tag": 0x0014, "len": 16, "hex": "6d61696c77696e7c544553542e312e31"},
        {"tag": 0x0100, "len": 13, "hex": "777a70613a6c6f67696e6f6e65"},
        {"tag": 0x010F, "len": 15, "hex": "57494e544553544445564943454944"},
        {"tag": 0x0110, "len": 2, "hex": "3130"},
        {"tag": 0x0112, "len": 10, "hex": "352e352e322e31303036"},
        {"tag": 0x0204, "len": 5, "hex": "7a685f434e"},
        {"tag": 0x0014, "len": 16, "hex": "6d61696c77696e7c544553542e312e32"},
        {"tag": 0x0001, "len": 4, "hex": "00000191"},
        {"tag": 0x0002, "len": 32, "hex": "b1f9fc8e92f8018795d29582fc9940c000000000000000000000000000000000"},
    ]

    assert decode_captured_tlv_record(records[0]) == (0x0107, bytes.fromhex("00000001"))

    segments = split_captured_tlv_records(records)

    assert len(segments) == 3
    assert extract_tlv_method_name(segments[0]) == "wzp:listMessages"
    assert classify_captured_tlv_segment(segments[0]) == "unknown"
    assert extract_tlv_method_name(segments[1]) == "wzpa:loginone"
    assert classify_captured_tlv_segment(segments[1]) == "login"
    assert extract_tlv_method_name(segments[2]) == ""
    assert classify_captured_tlv_segment(segments[2]) == "d1_control"


def test_extract_captured_method_segments_pulls_prefix_tags_into_method_segment() -> None:
    records = [
        {"tag": 0x0001, "len": 4, "hex": "00000191"},
        {"tag": 0x0002, "len": 32, "hex": "b1f9fc8e92f8018795d29582fc9940c000000000000000000000000000000000"},
        {"tag": 0x010B, "len": 1, "hex": "31"},
        {"tag": 0x010C, "len": 10, "hex": "31373733353432333434"},
        {"tag": 0x010A, "len": 16, "hex": "39663130326535663038316664376133"},
        {"tag": 0x0100, "len": 10, "hex": "4745545f47524f555053"},
        {"tag": 0x010E, "len": 15, "hex": "57494e544553544445564943454944"},
        {"tag": 0x010F, "len": 11, "hex": "3530303530303231303036"},
        {"tag": 0x0110, "len": 2, "hex": "3130"},
        {"tag": 0x0014, "len": 16, "hex": "6d61696c77696e7c544553542e312e33"},
        {"tag": 0x0001, "len": 4, "hex": "00000191"},
    ]

    segments = extract_captured_method_segments(records)

    assert len(segments) == 1
    assert [tag for tag, _ in segments[0][:6]] == [0x0001, 0x0002, 0x010B, 0x010C, 0x010A, 0x0100]
    assert extract_tlv_method_name(segments[0]) == "GET_GROUPS"


def test_build_wmsvr_login_tlv_appends_runtime_tail_in_capture_order() -> None:
    payload = build_loginone_payload(
        WmsvrLoginContext(
            config_id="10",
            app_version="5.5.2.1006",
            device_id="WINTESTDEVICEID",
        )
    )

    tlv = build_wmsvr_login_tlv(
        payload,
        ticket="MASTERFPVALUE",
        trace_id="1027626894865072128",
        device_info_json='{"appVersion":"5.5.2.1006"}',
        client_id="mailwin|TEST.1.1",
    )

    assert [tag for tag, _ in decode_tlv_envelope(tlv)] == [
        0x0100,
        0x010F,
        0x0110,
        0x0112,
        0x0204,
        0x0113,
        0x0115,
        0x0114,
        0x0014,
    ]


def test_build_wmsvr_login_segment_can_prefix_d1_control_tags() -> None:
    payload = build_loginone_payload(
        WmsvrLoginContext(
            config_id="10",
            app_version="5.5.2.1006",
            device_id="WINTESTDEVICEID",
        )
    )

    segment = build_wmsvr_login_segment(
        payload,
        ticket="MASTERFPVALUE",
        trace_id="1027626894865072128",
        device_info_json='{"appVersion":"5.5.2.1006"}',
        client_id="mailwin|TEST.1.2",
        include_d1_control=True,
    )

    tags = [tag for tag, _ in decode_tlv_envelope(segment)]

    assert tags[:2] == [0x0001, 0x0002]
    assert tags[2:] == [
        0x0100,
        0x010F,
        0x0110,
        0x0112,
        0x0204,
        0x0113,
        0x0115,
        0x0114,
        0x0014,
    ]


def test_build_default_wmsvr_login_client_id_matches_confirmed_wire_shape() -> None:
    context = WmsvrLoginContext(
        account="tester@example.com",
        device_id="WINTESTDEVICEID",
        master_sdid="1027626894865072128",
        app_version="5.5.2.1006",
    )

    loginone_client_id = build_default_wmsvr_login_client_id(context, method="wzpa:loginone")
    masterdevice_client_id = build_default_wmsvr_login_client_id(context, method="wzpmmc:masterdevice")

    assert loginone_client_id.startswith("mailwin|")
    assert masterdevice_client_id.startswith("mailwin|")
    assert normalize_wmsvr_client_id_prefix(loginone_client_id.split("|", 1)[1].split(".", 1)[0])
    assert loginone_client_id.endswith(".0.13")
    assert masterdevice_client_id.endswith(".0.33")


def test_build_wmsvr_client_id_normalizes_hex_prefix() -> None:
    assert build_wmsvr_client_id(prefix="ab-cd ef12", phase=1, counter=41) == "mailwin|ABCDEF12.1.41"


def test_build_wmsvr_login_frame_matches_capture_shaped_lengths() -> None:
    context = WmsvrLoginContext(
        account="tester@example.com",
        config_id="10",
        app_version="5.5.2.1006",
        appver_inner=50050021006,
        device_id="WINM1B4C7EDE3A2E4D9783941D1F61DE",
        master_fp=(
            "11IOMlZdb7Pfy6URv0gDPTzscI/eM3o85EsxozvEl0lWNpcA+4cdkK9wacF2d96Uk24B1PmHauaCYbVee1zWu/"
            "A7+r3Z6OqM/yDBzf2EgfXJ5528BOtY3DJ1qwSDlzvVtMQsbFd+JI5IWnx71slcQCFJXl3M78AKwt5uZFISGLZ"
            "rkArFT4Y9UMXN4K6VvbmTYe+677YA6l45zpmdYlg9kipQ=="
        ),
        master_sdid="1027626894865072128",
        device_info_json=(
            '{"appVersion":"5.5.2.1006","configId":"10","devType":"pc","deviceId":"WINM1B4C7EDE3A2E4D9783941D1F61DE",'
            '"md5Sign":"788118d68f7fa789a1ae6467cce15a99"}'
        ),
    )

    loginone_frame, _, loginone_client_id = build_wmsvr_login_frame(
        context,
        method="wzpa:loginone",
        client_id="mailwin|8E255B31.0.13",
    )
    masterdevice_frame, _, masterdevice_client_id = build_wmsvr_login_frame(
        context,
        method="wzpmmc:masterdevice",
        client_id="mailwin|8E255B31.0.33",
    )

    assert loginone_client_id == "mailwin|8E255B31.0.13"
    assert loginone_frame.header.word0 == 0xA000
    # 512 is not a fitted number: the `word2=0x0003` connections in the pcap set
    # carried len0=512 on every request, and this envelope is 499 bytes -> 512.
    assert loginone_frame.header.len0 == 512
    assert len(loginone_frame.to_bytes()) == 523
    assert masterdevice_client_id == "mailwin|8E255B31.0.33"
    assert masterdevice_frame.header.word0 == 0xA000
    assert masterdevice_frame.header.len0 == 496
    assert len(masterdevice_frame.to_bytes()) == 507


def test_build_wmsvr_login_frame_supports_slice1_login_body() -> None:
    context = WmsvrLoginContext(
        account="tester@example.com",
        user="tester@example.com",
        password="secret-pass",
        config_id="10",
        app_version="5.5.2.1006",
        device_id="WINTESTDEVICEID",
        master_fp="MASTERFPVALUE",
        master_sdid="1027626894865072128",
        device_info_json='{"appVersion":"5.5.2.1006"}',
    )

    frame, _, _ = build_wmsvr_login_frame(
        context,
        method=LOGIN_METHOD_LOGINMAIL,
        client_id="mailwin|8E255B31.0.13",
        body=build_login_response_flags_body(return_urs=1, return_token=1),
    )

    assert frame.header.len0 is not None
    assert frame.header.word0 == 0xB000
    assert frame.header.word2 == 0x0003
    assert frame.header.len0 % 16 == 0
    assert frame.header.len0 > 0
    assert frame.header.len1 == 32


def test_build_wmsvr_login_frame_supports_login_slice1_body() -> None:
    context = WmsvrLoginContext(
        account="tester@163.com",
        user="tester@163.com",
        config_id="10",
        app_version="5.5.2.1006",
        device_id="WINTESTDEVICEID",
        master_fp="MASTERFPVALUE",
        master_sdid="1027626894865072128",
        device_info_json='{"appVersion":"5.5.2.1006"}',
    )
    body = build_loginmail_body(context)

    frame, session_key, client_id = build_wmsvr_login_frame(
        context,
        method=LOGIN_METHOD_LOGINMAIL,
        body=body,
        client_id="mailwin|TEST1234.0.21",
    )
    _, decrypted_slice1 = decrypt_wmsvr_d1_frame_slices(frame, session_key)
    expected_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    assert client_id == "mailwin|TEST1234.0.21"
    assert frame.header.word0 == 0xB000
    assert frame.header.len1 is not None
    assert frame.header.len1 > 0
    assert decrypted_slice1[: len(expected_body)] == expected_body
    tail = decrypted_slice1[len(expected_body) :]
    assert 1 <= len(tail) <= 16
    assert set(tail) == {len(tail)}  # client rule: PKCS#7, byte value == count


def test_build_wmsvr_pre_auth_frame_attaches_wrapped_session_key() -> None:
    context = WmsvrD1RequestContext(
        key_version=DEFAULT_D1_KEY_VERSION,
        key_digest16=DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")

    frame, resolved_session_key, wrapped_session_key = build_wmsvr_pre_auth_frame(
        context,
        public_key=private_key.public_key(),
        session_key=session_key,
    )
    decrypted_slice0, decrypted_slice1 = decrypt_wmsvr_d1_frame_slices(
        frame,
        resolved_session_key,
    )
    control_tlv = build_wmsvr_d1_control_tlv(context)

    assert resolved_session_key == session_key
    assert frame.header.word0 == 0xB000
    assert frame.header.word2 == 0x0003
    assert frame.header.word4 == 0x0003
    assert frame.header.len0 == 48
    # The wrapped key is 128 bytes, i.e. exactly 16-aligned, so the client's PKCS#7
    # rule adds a whole 0x10 block here; that is the one case where an aligned
    # plaintext changes the frame length instead of only the pad bytes.
    assert frame.header.len1 == 144
    assert decrypted_slice0[: len(control_tlv)] == control_tlv
    assert decrypted_slice0[len(control_tlv) :] == b"\x06" * 6
    assert decrypted_slice1[: len(wrapped_session_key)] == wrapped_session_key
    assert decrypted_slice1[len(wrapped_session_key) :] == b"\x10" * 16


def test_startup_payload_get_settings_reencodes_to_observed_slice0_length() -> None:
    payload = WmsvrStartupPayload(
        method="GET_SETTINGS",
        opaque_token=(
            b"2A2E48M6-QMIDvwBWkIU8DX3fbqVg44P2doc2-Tp9ytVA3hMHomhvUwYjPzl4xCX_lp-"
            b"QEf6QvSR7IhPrCq4d9l-MHY5dBu--Q0eHWWQ01UMMtk1UemS9wfHwz7ITxdtiq-obPPSgvE70ILxidhCU2LaA"
        ),
        nonce_hex="2e43c73be28251ae",
        timestamp="1773398854",
        device_id="WINM1B4C7EDE3A2E4D9783941D1F61DE",
        appver_inner="50050021006",
        config_id="10",
        mode=b"5",
        ticket=(
            "11IOMlZdb7Pfy6URv0gDPTzscI/eM3o85EsxozvEl0lWNpcA+4cdkK9wacF2d96Uk24B1PmHauaCYbVee1zWu/"
            "A7+r3Z6OqM/yDBzf2EgfXJ5528BOtY3DJ1qwSDlzvVtMQsbFd+JI5IWnx71slcQCFJXl3M78AKwt5uZFISGLZ"
            "rkArFT4Y9UMXN4K6VvbmTYe+677YA6l45zpmdYlg9kipQ=="
        ),
        trace_id="1027626894865072128",
        device_info_json=(
            '{"appVersion":"5.5.2.1006","configId":"10","devType":"pc","deviceId":"WINM1B4C7EDE3A2E4D9783941D1F61DE",'
            '"md5Sign":"788118d68f7fa789a1ae6467cce15a99"}'
        ),
        client_id="mailwin|E6A38DB7.8.5720",
    )

    tlv = build_wmsvr_startup_tlv(payload)
    parsed = parse_wmsvr_startup_tlv(tlv)
    layout = build_d1_slice_layout(tlv)

    assert payload.encoded_len == 689
    assert payload.aligned_len == 704
    assert layout.slice0_len == 704
    assert layout.slice1_len == 0
    assert parsed.method == "GET_SETTINGS"
    assert parsed.opaque_token == payload.opaque_token
    assert parsed.nonce_hex == "2e43c73be28251ae"
    assert parsed.timestamp == "1773398854"
    assert parsed.device_id == "WINM1B4C7EDE3A2E4D9783941D1F61DE"
    assert parsed.appver_inner == "50050021006"
    assert parsed.config_id == "10"
    assert parsed.mode == b"5"
    assert parsed.ticket == payload.ticket
    assert parsed.trace_id == payload.trace_id
    assert parsed.device_info_json == payload.device_info_json
    assert parsed.client_id == payload.client_id


def test_startup_payload_supports_response_format_variant() -> None:
    payload = WmsvrStartupPayload(
        method="LIST_WRITEMAIL_TEMP_IDS",
        opaque_token=b"COMMON_TOKEN_3a2f7115-974e-4ad2-aa20-7b2d9228283b",
        nonce_hex="62d6f4d4a891c865",
        timestamp="1773458896",
        device_id="WINM1B4C7EDE3A2E4D9783941D1F61DE",
        appver_inner="50050021006",
        config_id="10",
        mode=b"2",
        response_format=b"json,byte",
        ticket=(
            "11IOMlZdb7Pfy6URv0gDPTzscI/eM3o85EsxozvEl0lWNpcA+4cdkK9wacF2d96Uk24B1PmHauaCYbVee1zWu/"
            "A7+r3Z6OqM/yDBzf2EgfXJ5528BOtY3DJ1qwSDlzvVtMQsbFd+JI5IWnx71slcQCFJXl3M78AKwt5uZFISGLZ"
            "rkArFT4Y9UMXN4K6VvbmTYe+677YA6l45zpmdYlg9kipQ=="
        ),
        trace_id="1027626894865072128",
        device_info_json=(
            '{"appVersion":"5.5.2.1006","configId":"10","devType":"pc","deviceId":"WINM1B4C7EDE3A2E4D9783941D1F61DE",'
            '"md5Sign":"788118d68f7fa789a1ae6467cce15a99"}'
        ),
        client_id="mailwin|C54DEE8F.1.57",
    )

    parsed = parse_wmsvr_startup_tlv(payload.to_bytes())

    assert parsed.method == "LIST_WRITEMAIL_TEMP_IDS"
    assert parsed.opaque_token == b"COMMON_TOKEN_3a2f7115-974e-4ad2-aa20-7b2d9228283b"
    assert parsed.mode == b"2"
    assert parsed.response_format == b"json,byte"
    assert payload.aligned_len == 608


def test_control_payload_reencodes_to_observed_short_frame_length() -> None:
    payload = WmsvrControlPayload(
        mode=b"0",
        control_id_hex="154e2f63e9148748ff694ee836ad352e",
        timestamp="1773420981",
        ticket=(
            "11IOMlZdb7Pfy6URv0gDPTzscI/eM3o85EsxozvEl0lWNpcA+4cdkK9wacF2d96Uk24B1PmHauaCYbVee1zWu/"
            "A7+r3Z6OqM/yDBzf2EgfXJ5528BOtY3DJ1qwSDlzvVtMQsbFd+JI5IWnx71slcQCFJXl3M78AKwt5uZFISGLZ"
            "rkArFT4Y9UMXN4K6VvbmTYe+677YA6l45zpmdYlg9kipQ=="
        ),
        trace_id="1027626894865072128",
        device_info_json=(
            '{"appVersion":"5.5.2.1006","configId":"10","devType":"pc","deviceId":"WINM1B4C7EDE3A2E4D9783941D1F61DE",'
            '"md5Sign":"788118d68f7fa789a1ae6467cce15a99"}'
        ),
        client_id="mailwin|1169E2CE.1.112",
    )

    tlv = build_wmsvr_control_tlv(payload)
    parsed = parse_wmsvr_control_tlv(tlv)
    layout = build_d1_slice_layout(tlv)

    assert payload.encoded_len == 474
    assert payload.aligned_len == 480
    assert layout.slice0_len == 480
    assert parsed.mode == b"0"
    assert parsed.control_id_hex == "154e2f63e9148748ff694ee836ad352e"
    assert parsed.timestamp == "1773420981"
    assert parsed.ticket == payload.ticket
    assert parsed.trace_id == payload.trace_id
    assert parsed.device_info_json == payload.device_info_json
    assert parsed.client_id == payload.client_id


def test_classify_wmsvr_auth_token_recognizes_current_families() -> None:
    assert classify_wmsvr_auth_token(
        "2A2E48M6-QMIDvwBWkIU8DX3fbqVg44P2doc2-Tp9ytVA3hMHomhvUwYjPzl4xCX_lp-QEf6QvSR7IhPrCq4d9l-MHY5dBu--Q0eHWWQ01UMM"
    ) == "mastersess"
    assert classify_wmsvr_auth_token("COMMON_TOKEN_3a2f7115-974e-4ad2-aa20-7b2d9228283b") == "common_token"
    assert (
        classify_wmsvr_auth_token(
            "1D1XfuSlR3DoFwzEx3uUVVedaLz2ze2vrGpJgVKWRVN1x5850VPBk8yF9FSRFoDDpoXKd97De2xhoA38nr19gw81FJQFr6968PlN1xXreeBUb8RoQUW1azx5zeVurAamgBv"
        )
        == "mixmailtokens"
    )
    assert classify_wmsvr_auth_token(bytes.fromhex("00000001")) == "flag"


def test_infer_wmsvr_http_auth_type_from_confirmed_token_families() -> None:
    assert (
        infer_wmsvr_http_auth_type(
            "2A2E48M6-QMIDvwBWkIU8DX3fbqVg44P2doc2-Tp9ytVA3hMHomhvUwYjPzl4xCX_lp-QEf6QvSR7IhPrCq4d9l-MHY5dBu--Q0eHWWQ01UMM"
        )
        == "masterToken"
    )
    assert (
        infer_wmsvr_http_auth_type(
            "1D1XfuSlR3DoFwzEx3uUVVedaLz2ze2vrGpJgVKWRVN1x5850VPBk8yF9FSRFoDDpoXKd97De2xhoA38nr19gw81FJQFr6968PlN1xXreeBUb8RoQUW1azx5zeVurAamgBv"
        )
        == "mixmailToken"
    )
    assert infer_wmsvr_http_auth_type("COMMON_TOKEN_3a2f7115-974e-4ad2-aa20-7b2d9228283b") == ""


def test_lookup_airsync_command_name_returns_confirmed_switch_names() -> None:
    assert lookup_airsync_command_name(0x0200) == "FolderSync"
    assert lookup_airsync_command_name(0x2000) == "MoveItems"
    assert lookup_airsync_command_name(0x40000) == "Ping"
    assert lookup_airsync_command_name(0x1234) == ""


def test_route_and_http_ticket_round_trip() -> None:
    route = "Coremail:b65ca1fcc7aaa%mKFjcZlIiNXSzpFWHzHHfsUvdNbygJQm%wzp-session-40-5.mail.163.com"

    parts = parse_wmsvr_route(route)

    assert parts is not None
    assert parts.seed == "b65ca1fcc7aaa"
    assert parts.token == "mKFjcZlIiNXSzpFWHzHHfsUvdNbygJQm"
    assert parts.session_host == "wzp-session-40-5.mail.163.com"
    assert parts.http_ticket == "b65ca1fcc7aaa%mKFjcZlIiNXSzpFWHzHHfsUvdNbygJQm%wzp-session-40-5.mail.163.com"
    assert route_to_http_ticket(route) == parts.http_ticket
    assert ticket_to_wmsvr_route(parts.http_ticket) == route


def test_session_alias_properties_match_confirmed_master_fields() -> None:
    session = WmsvrSession(
        route="Coremail:b65ca1fcc7aaa%mKFjcZlIiNXSzpFWHzHHfsUvdNbygJQm%wzp-session-40-5.mail.163.com",
        ticket="MASTERFPVALUE",
        trace_id="1027626894865072128",
        device_info='{"appVersion":"5.5.2.1006"}',
        mastersess="2A2E48M6-QMIDvwBWkIU8DX3fbqVg44P2doc2-Tp9ytVA3hMHomhvUwYjPzl4xCX_lp-QEf6QvSR7IhPrCq4d9l-MHY5dBu--Q0eHWWQ01UMM",
        mixmailtokens="1D1XfuSlR3DoFwzEx3uUVVedaLz2ze2vrGpJgVKWRVN1x5850VPBk8yF9FSRFoDDpoXKd97De2xhoA38nr19gw81FJQFr6968PlN1xXreeBUb8RoQUW1azx5zeVurAamgBv",
    )

    assert session.master_fp == "MASTERFPVALUE"
    assert session.master_sdid == "1027626894865072128"
    assert session.master_device_info_json == '{"appVersion":"5.5.2.1006"}'
    assert session.http_ticket == "b65ca1fcc7aaa%mKFjcZlIiNXSzpFWHzHHfsUvdNbygJQm%wzp-session-40-5.mail.163.com"
    assert session.mastersess.startswith("2A2E48M6-")
    assert session.mixmailtokens.startswith("1D1")


def test_build_observed_runtime_headers_matches_confirmed_mail163_shape() -> None:
    session = WmsvrSession(
        ticket="MASTERFPVALUE",
        trace_id="1027626894865072128",
        device_info='{"appVersion":"5.5.2.1006"}',
        mastersess="2A2E48M6-example",
        mixmailtokens="1D1-example",
    )

    assert build_observed_runtime_headers(session) == {
        "masterfp": "MASTERFPVALUE",
        "masterdi": '{"appVersion":"5.5.2.1006"}',
        "sdid": "1027626894865072128",
        "mastersess": "2A2E48M6-example",
        "mixmailtokens": "1D1-example",
    }


def test_build_init_session_headers_uses_masterfp_and_mastersess() -> None:
    session = WmsvrSession(ticket="MASTERFPVALUE", mastersess="2A2E48M6-example")

    assert build_init_session_headers(session) == {
        "masterfp": "MASTERFPVALUE",
        "token": "2A2E48M6-example",
    }


def test_build_wmsvr_d1_request_context_uses_login_material(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    mail_db = _build_mail_db(tmp_path)
    bootstrap = load_wmsvr_bootstrap(app_db)

    monkeypatch.setattr("mailmaster.protocol_config.decrypt_account_config_blob", lambda blob, install_root=None: json.loads(blob))
    monkeypatch.setattr("mailmaster.protocol_config.decrypt_config_password", lambda password_b64, install_root=None: "")
    context = build_wmsvr_login_context("tester@163.com", load_server_configs(mail_db), bootstrap)

    request_context = build_wmsvr_d1_request_context(context)

    assert request_context.key_version == DEFAULT_D1_KEY_VERSION
    assert request_context.key_digest16 == DEFAULT_D1_FALLBACK_KEY_DIGEST16
    assert request_context.master_fp == "MASTERFPVALUE"
    assert request_context.master_sdid == "1027626894865072128"
    assert request_context.device_info_json == bootstrap.master_device_info.to_json()


def test_build_wmsvr_d1_request_context_preserves_explicit_key_material(tmp_path: Path, monkeypatch) -> None:
    app_db = _build_app_db(tmp_path)
    mail_db = _build_mail_db(tmp_path)
    bootstrap = load_wmsvr_bootstrap(app_db)

    monkeypatch.setattr("mailmaster.protocol_config.decrypt_account_config_blob", lambda blob, install_root=None: json.loads(blob))
    monkeypatch.setattr("mailmaster.protocol_config.decrypt_config_password", lambda password_b64, install_root=None: "")
    context = build_wmsvr_login_context("tester@163.com", load_server_configs(mail_db), bootstrap)

    request_context = build_wmsvr_d1_request_context(
        context,
        key_version=0x222,
        key_digest16=b"\x11" * 16,
        session_key=b"\x22" * 16,
        word2=0x0001,
        word4=0x0009,
    )

    assert request_context.key_version == 0x222
    assert request_context.key_digest16 == b"\x11" * 16
    assert request_context.session_key == b"\x22" * 16
    assert request_context.word2 == 0x0001
    assert request_context.word4 == 0x0009


def test_build_wmsvr_d1_control_tlv_matches_confirmed_prefix_shape() -> None:
    tlv = build_wmsvr_d1_control_tlv(
        build_wmsvr_d1_request_context(
            WmsvrLoginContext(
                master_fp="MASTERFPVALUE",
                master_sdid="1027626894865072128",
                device_info_json='{"appVersion":"5.5.2.1006"}',
            ),
        )
    )

    assert tlv == (
        bytes.fromhex("00010400000191")
        + bytes.fromhex("000220")
        + DEFAULT_D1_FALLBACK_KEY_DIGEST16
        + (b"\x00" * 16)
    )


def test_normalize_d1_key_digest_expands_to_wire_size() -> None:
    assert normalize_d1_key_digest(DEFAULT_D1_FALLBACK_KEY_DIGEST16) == (
        DEFAULT_D1_FALLBACK_KEY_DIGEST16 + b"\x00" * 16
    )


def test_compute_wmsvr_public_key_digest_accepts_pem_and_der() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    assert compute_wmsvr_public_key_digest(pem) == compute_wmsvr_public_key_digest(der)


def test_generate_wmsvr_d1_session_key_returns_16_bytes() -> None:
    key = generate_wmsvr_d1_session_key()
    assert isinstance(key, bytes)
    assert len(key) == 16


def test_wrap_wmsvr_d1_session_key_uses_pkcs1_v15() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")

    wrapped = wrap_wmsvr_d1_session_key(session_key, private_key.public_key())

    assert len(wrapped) == 256
    assert private_key.decrypt(
        wrapped,
        padding.PKCS1v15(),
    ) == session_key


def test_encrypt_and_decrypt_wmsvr_d1_slice_round_trip() -> None:
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    plaintext = b"0123456789abcdef" * 2

    encrypted = encrypt_wmsvr_d1_slice(plaintext, session_key)

    assert encrypted != plaintext
    assert decrypt_wmsvr_d1_slice(encrypted, session_key) == plaintext


def test_build_wmsvr_d1_encrypted_frame_without_json_uses_a000() -> None:
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    envelope = b"\x01\x02\x03"

    frame = build_wmsvr_d1_encrypted_frame(
        envelope,
        session_key=session_key,
        seq=7,
    )
    plain0, plain1 = decrypt_wmsvr_d1_frame_slices(frame, session_key)

    assert frame.header.word0 == 0xA000
    assert frame.header.word2 == DEFAULT_D1_RPC_WORD2
    assert frame.header.word4 == DEFAULT_D1_RPC_WORD4
    assert frame.header.seq == 7
    assert frame.header.len0 == 16
    assert frame.header.len1 is None
    assert plain0 == b"\x01\x02\x03" + (b"\x0d" * 13)
    assert plain1 == b""


def test_build_wmsvr_d1_encrypted_frame_with_json_uses_b000() -> None:
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    envelope = b"\x01\x02\x03"
    body = b'{"ok":true}'

    frame = build_wmsvr_d1_encrypted_frame(
        envelope,
        session_key=session_key,
        body_bytes=body,
        seq=8,
    )
    plain0, plain1 = decrypt_wmsvr_d1_frame_slices(frame, session_key)

    assert frame.header.word0 == 0xB000
    assert frame.header.len0 == 16
    assert frame.header.len1 == 16
    assert plain0 == b"\x01\x02\x03" + (b"\x0d" * 13)
    assert plain1 == body + (b"\x05" * 5)


def test_build_wmsvr_d1_encrypted_frame_supports_opaque_slice1() -> None:
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    slice0 = bytes.fromhex("00010400000191")
    slice1 = b"\x10\x20\x30"

    frame = build_wmsvr_d1_encrypted_frame(
        slice0,
        session_key=session_key,
        slice1_bytes=slice1,
        seq=9,
    )
    plain0, plain1 = decrypt_wmsvr_d1_frame_slices(frame, session_key)

    assert frame.header.word0 == 0xB000
    assert frame.header.len0 == 16
    assert frame.header.len1 == 16
    assert frame.header.seq == 9
    assert plain0 == slice0 + (b"\x09" * 9)
    assert plain1 == slice1 + (b"\x0d" * 13)


def test_build_d1_slice_layout_aliases_slice_fields() -> None:
    layout = build_d1_slice_layout(b"\x01\x02\x03", b"\x04\x05")

    assert layout.slice0_len == 16
    assert layout.slice1_len == 16
    assert layout.padded_slice0 == b"\x01\x02\x03" + (b"\x0d" * 13)
    assert layout.padded_slice1 == b"\x04\x05" + (b"\x0e" * 14)


def test_pad_d1_slice_follows_the_clients_pkcs7_rule() -> None:
    """The client's only outbound slice cipher is BoringSSL EVP, i.e. PKCS#7.

    No captured frame can decide this: every shape the client has ever sent us is
    non-aligned, where both rules agree on the length and differ only in the pad
    bytes. The aligned case is the one that changes the length, so it is pinned here.
    """
    assert pad_d1_slice(b"") == b""
    assert pad_d1_slice(b"a" * 15) == b"a" * 15 + b"\x01"
    assert pad_d1_slice(b"a" * 16) == b"a" * 16 + (b"\x10" * 16)
    assert pad_d1_slice(b"a" * 17) == b"a" * 17 + (b"\x0f" * 15)
    # Negative control: the rule this module used before the client's was pinned.
    assert pad_d1_slice(b"a" * 16, D1_SLICE_PADDING_NUL) == b"a" * 16
    assert pad_d1_slice(b"a" * 3, D1_SLICE_PADDING_NUL) == b"a" * 3 + (b"\x00" * 13)
    with pytest.raises(ValueError):
        pad_d1_slice(b"a", "rot13")


def test_load_wmsvr_hardcoded_public_keys_scans_embedded_pems(tmp_path: Path) -> None:
    pems: list[bytes] = []
    for key_size in (2048, 1024, 1024):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pems.append(
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    dll_path = tmp_path / "Application" / "5.5.2.1006" / "mastercore.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(
        b"noise\x00"
        + pems[0]
        + b"\x00-----BEGIN PUBLIC KEY-----%bad-----END PUBLIC KEY-----\x00"
        + pems[1]
        + b"\x00"
        + pems[2]
        + b"\x00",
    )

    keys = load_wmsvr_hardcoded_public_keys(tmp_path)

    assert len(keys) == 3
    assert {item.digest16 for item in keys.values()} == {
        compute_wmsvr_public_key_digest(pem)
        for pem in pems
    }
    assert all(item.source_path.endswith("mastercore.dll") for item in keys.values())


def test_get_wmsvr_hardcoded_public_key_returns_known_label(tmp_path: Path) -> None:
    sibling_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sibling_pem = sibling_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    dll_path = tmp_path / "Application" / "5.5.2.1006" / "mastercore.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(sibling_pem)

    keys = load_wmsvr_hardcoded_public_keys(tmp_path)
    only_key = next(iter(keys.values()))

    assert get_wmsvr_hardcoded_public_key(only_key.label, install_root=tmp_path).digest16 == only_key.digest16


def test_build_get_settings_tlv_matches_confirmed_layout() -> None:
    tlv = build_get_settings_tlv()
    assert tlv.hex() == (
        "00010400000191"
        "000220b1f9fc8e92f8018795d29582fc9940c0"
        "00000000000000000000000000000000"
    )


def test_build_get_settings_frame_matches_known_capture() -> None:
    frame = build_get_settings_frame()
    assert frame.to_bytes().hex() == (
        "d13000000a000000002a800100010400000191000220b1f9fc8e92f8018795d29582fc9940c0"
        "0000000000000000000000000000000044063d68ff633d2bd9ee5768cdb7260af6204aacb6f6d47c"
        "cc05a64124e935faa0843d4e9ea4b5d0493f981ceee25d26f1317e28fc1dd298a032291313c8d3f6"
        "360f8cf900f3700b397b2f6e5854982bc830391815287c3f20fd40a53aeab1c2d63429d72175cc26"
        "cb6dd1a62759b7191aa1bc33f6462d7144a6bd67a5bfc680"
    )


def test_parse_d1_frame_parses_known_settings_frame() -> None:
    frame = parse_d1_frame(build_get_settings_frame().to_bytes())

    assert frame.header.word0 == 0x3000
    assert frame.header.frame_type == 0x30
    assert frame.header.word4 == 0x000A
    assert frame.header.word2 == 0x0000
    assert frame.header.seq == 0
    assert frame.header.extra16 is None
    assert frame.header.len0 == 42
    assert frame.header.len1 == 128
    assert frame.slice0 == build_get_settings_tlv()
    assert frame.slice1 == DEFAULT_D1_GET_SETTINGS_SIGNATURE
    assert frame.remainder == b""


def test_parse_d1_frame_parses_extra16_only_ack() -> None:
    frame = parse_d1_frame(bytes.fromhex("d14080000a0000000001f7"))

    assert frame.header.word0 == 0x4080
    assert frame.header.frame_type == 0x40
    assert frame.header.word4 == 0x000A
    assert frame.header.word2 == 0x0000
    assert frame.header.seq == 0
    assert frame.header.extra16 == 0x01F7
    assert frame.header.len0 is None
    assert frame.header.len1 is None


def test_describe_d1_frame_reports_compact_header_summary() -> None:
    desc = describe_d1_frame(build_get_settings_frame(version=DEFAULT_D1_KEY_VERSION).to_bytes())

    assert desc["word0"] == "0x3000"
    assert desc["frame_type"] == "0x30"
    assert desc["len0"] == 42
    assert desc["len1"] == 128


def test_parse_get_settings_response_reads_ack_code_only() -> None:
    response = parse_get_settings_response(bytes.fromhex("d14080000a0000000001f7"))

    assert response.business_code == 0x01F7
    assert response.key_version is None
    assert response.key_blob == b""


def test_parse_get_settings_response_reads_key_update_metadata() -> None:
    key_update = bytes.fromhex(
        "d17080000a0000000001f007800200010400000191"
    ) + (b"\x11" * 0x100)

    response = parse_get_settings_response(key_update)

    assert response.business_code == 0x01F0
    assert response.key_version == 0x00000191
    assert response.key_blob == b"\x11" * 0x100


def test_unwrap_wmsvr_key_update_blob_recovers_der_payload() -> None:
    sibling_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sibling_pem = sibling_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    runtime_private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    runtime_der = runtime_private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    blob = _build_signed_key_update_blob(sibling_private_key, runtime_der)

    assert unwrap_wmsvr_key_update_blob(blob, sibling_pem) == runtime_der


def test_decode_get_settings_key_update_recovers_runtime_pem_and_match(tmp_path: Path) -> None:
    sibling_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sibling_pem = sibling_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    runtime_private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    runtime_public_key = runtime_private_key.public_key()
    runtime_der = runtime_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    runtime_pem = runtime_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    blob = _build_signed_key_update_blob(sibling_private_key, runtime_der)
    dll_path = tmp_path / "Application" / "5.5.2.1006" / "mastercore.dll"
    dll_path.parent.mkdir(parents=True, exist_ok=True)
    dll_path.write_bytes(sibling_pem + b"\x00" + runtime_pem)
    response = parse_get_settings_response(
        bytes.fromhex("d17080000a0000000001f007800200010400000191") + blob
    )

    decoded = decode_get_settings_key_update(
        response,
        install_root=tmp_path,
        sibling_public_key=sibling_pem,
    )

    assert decoded.version == DEFAULT_D1_KEY_VERSION
    assert decoded.der_bytes == runtime_der
    assert compute_wmsvr_public_key_digest(decoded.pem) == compute_wmsvr_public_key_digest(runtime_pem)
    assert der_bytes_to_public_key_pem(runtime_der) == decoded.pem
    assert decoded.matched_hardcoded_key.startswith("embedded_")


def test_build_wmsvr_d1_request_frame_starts_at_the_envelope() -> None:
    request_context = WmsvrD1RequestContext(
        key_version=DEFAULT_D1_KEY_VERSION,
        key_digest16=DEFAULT_D1_FALLBACK_KEY_DIGEST16,
        master_fp="MASTERFPVALUE",
        master_sdid="1027626894865072128",
        device_info_json='{"appVersion":"5.5.2.1006"}',
        session_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
        word2=DEFAULT_D1_RPC_WORD2,
        word4=DEFAULT_D1_RPC_WORD4,
    )
    session = WmsvrSession(client_id="mailwin|test")

    frame = build_wmsvr_d1_request_frame(
        request_context,
        session,
        "user:validateSession",
        body=None,
        seq=1,
    )
    plain0, plain1 = decrypt_wmsvr_d1_frame_slices(frame, request_context.session_key)

    assert frame.header.word0 == 0xA000
    assert frame.header.seq == 1
    assert plain1 == b""
    # Captured request envelopes carry no 0x0001/0x0002 prefix, so neither does the
    # default: the envelope is the whole slice and the control pair is the slice0 of
    # the separate GET_SETTINGS key-exchange frame.
    assert plain0.startswith(b"\x01\x07")
    assert not plain0.startswith(build_wmsvr_d1_control_tlv(request_context))
    assert b"user:validateSession" in plain0
    assert b"mailwin|test" in plain0


def test_build_wmsvr_d1_request_frame_can_prefix_control_tlv() -> None:
    request_context = WmsvrD1RequestContext(
        key_version=DEFAULT_D1_KEY_VERSION,
        key_digest16=DEFAULT_D1_FALLBACK_KEY_DIGEST16,
        session_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
    )

    frame = build_wmsvr_d1_request_frame(
        request_context,
        WmsvrSession(client_id="mailwin|test"),
        "user:validateSession",
        body=None,
        seq=1,
        include_d1_control=True,
    )
    plain0, _plain1 = decrypt_wmsvr_d1_frame_slices(frame, request_context.session_key)

    assert plain0.startswith(build_wmsvr_d1_control_tlv(request_context))


def test_send_and_recv_d1_frame_over_socketpair() -> None:
    left, right = socket.socketpair()
    try:
        frame = build_get_settings_frame()
        send_d1_frame(left, frame)
        received = recv_d1_frame(right, timeout=1.0)
    finally:
        left.close()
        right.close()

    assert received.to_bytes() == frame.to_bytes()


def test_exchange_get_settings_round_trip_over_socketpair() -> None:
    client, server = socket.socketpair()
    seen: dict[str, bytes] = {}

    def _server() -> None:
        try:
            inbound = recv_d1_frame(server, timeout=1.0)
            seen["request"] = inbound.to_bytes()
            send_d1_frame(server, bytes.fromhex("d14080000a0000000001f7"))
        finally:
            server.close()

    worker = threading.Thread(target=_server, daemon=True)
    worker.start()
    try:
        response = exchange_get_settings(client, timeout=1.0)
    finally:
        client.close()
        worker.join(timeout=2.0)

    assert seen["request"] == build_get_settings_frame().to_bytes()
    assert response.business_code == 0x01F7


def test_build_compose_request_creates_valid_structure() -> None:
    session = WmsvrSession(
        host="test.example.com",
        port=443,
        ticket="test_ticket",
        trace_id="test_trace",
        device_info="{}",
    )

    request = build_compose_request(
        session,
        to=["recipient@example.com"],
        subject="Test Subject",
        body_text="Test body",
    )

    assert request.method == "mbox:compose"
    assert request.session == session
    body = json.loads(request.body_json)
    assert body["action"] == "deliver"
    assert body["to"] == ["recipient@example.com"]
    assert body["subject"] == "Test Subject"
    assert body["bodyText"] == "Test body"


def test_build_compose_request_includes_optional_fields() -> None:
    session = WmsvrSession(
        host="test.example.com",
        port=443,
        ticket="test_ticket",
        trace_id="test_trace",
        device_info="{}",
    )

    request = build_compose_request(
        session,
        to=["recipient@example.com"],
        subject="Test",
        body_html="<p>HTML body</p>",
        cc=["cc@example.com"],
        bcc=["bcc@example.com"],
    )

    body = json.loads(request.body_json)
    assert body["bodyHtml"] == "<p>HTML body</p>"
    assert body["cc"] == ["cc@example.com"]
    assert body["bcc"] == ["bcc@example.com"]


def _login_context() -> WmsvrLoginContext:
    return WmsvrLoginContext(
        account="account@example.invalid",
        user="account@example.invalid",
        password="dummy-password",
        app_version="0.0.0.0000",
        device_id="device-dummy",
    )


def test_sec_fingerprint_items_include_flag_when_any_value_present() -> None:
    # The client always writes `sec` alongside the three values, in this order
    # (docs/reverse-engineering.md 4.10.2). The flag is what tells the server a
    # fingerprint is present, so it must appear for any partial fingerprint.
    assert build_sec_fingerprint_items() == []
    assert build_sec_fingerprint_items(sec_name="host.example") == [
        ("sec", 1),
        ("secName", "host.example"),
    ]
    assert build_sec_fingerprint_items("host.example", 0, "abc") == [
        ("sec", 1),
        ("secName", "host.example"),
        ("secOsType", 0),
        ("secMdc", "abc"),
    ]


def test_loginone_body_omits_sec_block_by_default() -> None:
    body = build_loginone_body(_login_context(), password="dummy-password")
    assert not {"sec", "secName", "secOsType", "secMdc"} & set(body)


def test_loginone_body_appends_sec_block_when_requested() -> None:
    body = build_loginone_body(
        _login_context(),
        password="dummy-password",
        sec_name="host.example",
        sec_os_type=local_sec_os_type("win32"),
    )
    assert body["sec"] == 1
    assert body["secName"] == "host.example"
    assert body["secOsType"] == 0
    assert "secMdc" not in body

    keys = list(body)
    assert keys[-3:] == ["sec", "secName", "secOsType"]


def test_local_sec_os_type_matches_recovered_platform_mapper() -> None:
    # Recovered from the mapper at 0x10a7b560: win -> 0, mac -> 1, ios -> 2,
    # everything else falls through to the Windows code.
    assert local_sec_os_type("win32") == 0
    assert local_sec_os_type("darwin") == 1
    assert local_sec_os_type("ios") == 2
    assert local_sec_os_type("freebsd") == 0


def test_local_sec_name_uses_the_clients_own_api() -> None:
    # The client asks Win32 for ComputerNameDnsFullyQualified (format 3), so on
    # Windows the value must be exactly that — not a reverse-DNS guess.
    # Measured on this host: getfqdn() answered "host.docker.internal" while the
    # machine name was "DESKTOP-HQV0QUQ", and the client would send the latter.
    value = local_sec_name()
    assert value
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        buffer = ctypes.create_unicode_buffer(256)
        size = wintypes.DWORD(len(buffer))
        assert ctypes.windll.kernel32.GetComputerNameExW(3, buffer, ctypes.byref(size))
        assert value == buffer.value


def test_local_sec_name_falls_back_to_the_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    # The gethostname() path is what runs off-Windows or when the Win32 query
    # fails; it must still prefer the machine's own name over reverse DNS.
    monkeypatch.setattr(wmsvr_module, "_query_dns_fully_qualified_name", lambda: None)
    assert local_sec_name() == socket.gethostname()


def test_loginone_body_keeps_an_explicitly_empty_sec_mdc() -> None:
    # The client sends secMdc as an empty string (the table it joins is empty in
    # this build), so the shared "drop empty values" filter must not remove it.
    body = build_loginone_body(
        _login_context(),
        sec_name="HOST",
        sec_os_type=0,
        sec_mdc="",
    )
    assert body["secMdc"] == ""


# The captured first frame of a real d1 connection, byte for byte. The header and
# slice0 are what our builder must reproduce; slice1 is the *other* session's
# wrapped key and therefore only pins the length.
CAPTURED_GET_SETTINGS_HEADER_HEX = "d13000000a000000002a8001"
CAPTURED_GET_SETTINGS_SLICE0_HEX = (
    "00010400000191000220b1f9fc8e92f8018795d29582fc9940c0"
    "00000000000000000000000000000000"
)


def test_get_settings_frame_matches_captured_header_and_slice0() -> None:
    frame = build_get_settings_frame()
    assert frame.header.to_bytes().hex() == CAPTURED_GET_SETTINGS_HEADER_HEX
    assert frame.slice0.hex() == CAPTURED_GET_SETTINGS_SLICE0_HEX
    assert frame.header.len0 == 42
    assert frame.header.len1 == 128


def test_key_exchange_frame_wraps_our_own_key_not_the_captured_blob() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    frame, session_key = build_wmsvr_key_exchange_frame(public_key=private_key.public_key())

    assert len(session_key) == 16
    assert frame.header.to_bytes().hex() == CAPTURED_GET_SETTINGS_HEADER_HEX
    assert frame.slice0.hex() == CAPTURED_GET_SETTINGS_SLICE0_HEX
    assert frame.header.len1 == 128
    # The whole point: the tail is a fresh encryption of *our* key. Replaying the
    # captured blob is what made every earlier request undecryptable.
    assert frame.slice1 != DEFAULT_D1_GET_SETTINGS_SIGNATURE


def test_key_exchange_frame_is_decryptable_by_the_matching_private_key() -> None:
    # Stands in for the server: it can only recover the session key because slice1
    # is a PKCS#1 v1.5 type-2 block under the key named by slice0's digest.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    session_key = bytes.fromhex("00112233445566778899aabbccddeeff")

    frame, resolved = build_wmsvr_key_exchange_frame(
        session_key=session_key,
        public_key=private_key.public_key(),
    )

    recovered = private_key.decrypt(frame.slice1, padding.PKCS1v15())
    assert recovered == session_key
    assert resolved == session_key


def test_key_exchange_frame_requires_a_key_matching_the_digest() -> None:
    with pytest.raises(ValueError, match="No hardcoded Wmsvr public key"):
        build_wmsvr_key_exchange_frame(
            key_digest16=bytes.fromhex("00" * 16),
        )


def test_get_settings_frame_rejects_a_non_rsa1024_tail() -> None:
    with pytest.raises(ValueError, match="slice1 must be 128 bytes"):
        build_get_settings_frame(wrapped_session_key=b"\x01" * 64)


class _RecordingSocket:
    """Minimal socket stand-in: records what was sent and replays canned bytes.

    `recv` is a stream, not a packet queue, because `recv_d1_frame` reads a frame in
    several exact-length steps.
    """

    def __init__(self, inbound: bytes) -> None:
        self.sent = bytearray()
        self._inbound = bytearray(inbound)

    def settimeout(self, _value: float) -> None:
        pass

    def gettimeout(self) -> None:
        return None

    def connect(self, _address: tuple[str, int]) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        chunk = bytes(self._inbound[:size])
        del self._inbound[:size]
        return chunk

    def close(self) -> None:
        pass


def _probe_context() -> WmsvrLoginContext:
    context = _login_context()
    context.peer_candidates = [
        WmsvrPeerCandidate(host="127.0.0.1", port=1)
    ]
    return context


def test_login_probe_exchanges_our_key_and_uses_it_for_the_login_frame(
    monkeypatch,
) -> None:
    """The two frames must share one key: exchange it, then encrypt the login with it."""
    settings_ack = bytes.fromhex("d14080000a000000000064")
    login_response = build_wmsvr_d1_encrypted_frame(
        b"\x00" * 16,
        session_key=bytes.fromhex("ab" * 16),
        seq=1,
        word2=0x0003,
        word4=0x0003,
    ).to_bytes()
    fake = _RecordingSocket(settings_ack + login_response)

    wrapped_with: list[bytes] = []
    real_wrap = wmsvr_module.wrap_wmsvr_d1_session_key

    def _record_wrap(key: bytes, public_key) -> bytes:
        wrapped_with.append(key)
        return real_wrap(key, public_key)

    monkeypatch.setattr(wmsvr_module.socket, "socket", lambda *a, **k: fake)
    monkeypatch.setattr(wmsvr_module, "wrap_wmsvr_d1_session_key", _record_wrap)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    monkeypatch.setattr(
        wmsvr_module,
        "find_wmsvr_hardcoded_public_key_by_digest",
        lambda digest, install_root=None: server_key.public_key(),
    )

    probe = wmsvr_module.execute_wmsvr_login_probe(
        _probe_context(),
        method=LOGIN_METHOD_LOGINONE,
        word2=0x0003,
        word4=0x0003,
    )

    assert probe.error == ""
    assert probe.key_exchange is True
    assert probe.key_exchange_frame is not None
    assert wrapped_with == [probe.session_key]

    # What the server can do with frame 1 must yield exactly the key that protects
    # frame 2, otherwise the login request is undecryptable and earns a 400.
    assert (
        server_key.decrypt(probe.key_exchange_frame.slice1, padding.PKCS1v15())
        == probe.session_key
    )

    # Frame 1 on the wire is the key exchange, frame 2 the login request. Parsing
    # them back out is the cheapest way to show both went out in that order.
    stream = bytes(fake.sent)
    exchange_raw = probe.key_exchange_frame.to_bytes()
    assert stream.startswith(exchange_raw)
    login_raw = stream[len(exchange_raw) :]
    login_frame = parse_d1_frame(login_raw)
    decrypted = decrypt_wmsvr_d1_slice(login_frame.slice0, probe.session_key)
    records = decode_tlv_envelope(decrypted[: _tlv_records_end(decrypted)])
    methods = [value for tag, value in records if tag == 0x0100]
    assert methods == [b"wzpa:loginone"]


def _tlv_records_end(data: bytes) -> int:
    """Length of the leading run of complete TLV records (slice0 is zero padded)."""
    offset = 0
    while offset + 3 <= len(data):
        tag = int.from_bytes(data[offset : offset + 2], "big")
        length, cursor = _decode_leb(data, offset + 2)
        if tag == 0 and length == 0:
            return cursor
        if cursor + length > len(data):
            return offset
        offset = cursor + length
    return offset


def _decode_leb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("truncated leb128")


def test_login_probe_replay_mode_sends_the_captured_blob(monkeypatch) -> None:
    """`key_exchange=False` is the negative control: it must replay the captured tail."""
    settings_ack = bytes.fromhex("d14080000a000000000064")
    fake = _RecordingSocket(settings_ack)

    monkeypatch.setattr(wmsvr_module.socket, "socket", lambda *a, **k: fake)

    probe = wmsvr_module.execute_wmsvr_login_probe(
        _probe_context(),
        method=LOGIN_METHOD_LOGINONE,
        word2=0x0003,
        word4=0x0003,
        key_exchange=False,
    )

    assert probe.key_exchange is False
    assert probe.key_exchange_frame is None
    stream = bytes(fake.sent)
    assert stream.startswith(build_get_settings_frame().to_bytes())
    assert DEFAULT_D1_GET_SETTINGS_SIGNATURE in stream


# A real request slice0, captured off the wire (see artifacts/logs/tlv_captures.json).
# It is `wzp:listMessages` from a live session, and it is the whole reason the control
# TLV is not prepended anywhere: this envelope is 614 bytes and pads to 624, which is
# exactly the `len0` the wire carried for that connection.
CAPTURED_LISTMESSAGES_SLICE0_HEX = (
    "01070400000001010010777a703a6c6973744d657373616765730101206c4c6177424e516d4665775650664c46526e50"
    "635a645761484e4d5263464955010256436f72656d61696c3a64306133646561313636333339256c4c6177424e516d46"
    "65775650664c46526e50635a645761484e4d526346495525777a702d73657373696f6e2d34302d32342e6d61696c2e31"
    "36332e636f6d02000b31302e34372e37332e3533020102003c00161531307c616e646572736f6e6279403136332e636f"
    "6d0113da013131494f4d6c5a6462375066793655527630674450547a7363492f654d336f38354573786f7a76456c306c"
    "574e7063412b3463646b4b397761634632643936556b32344231506d48617561435962566565317a57752f41372b7233"
    "5a364f714d2f7944427a6632456766584a35353238424f745933444a31717753446c7a7656744d51736246642b4a4935"
    "49576e783731736c635143464a586c334d3738414b777435755a464953474c5a726b41724654345939554d584e344b36"
    "5676626d5459652b3637375941366c34357a706d64596c67396b6970513d3d0115133130323736323638393438363530"
    "3732313238011495017b2261707056657273696f6e223a22352e352e322e31303036222c22636f6e6669674964223a22"
    "3130222c2264657654797065223a227063222c226465766963654964223a2257494e4d31423443374544453341324534"
    "443937383339343144314636314445222c226d64355369676e223a223738383131386436386637666137383961316165"
    "363436376363653135613939227d0014156d61696c77696e7c43353444454538462e312e3638"
)


def _captured_listmessages_session() -> WmsvrSession:
    """Runtime material taken verbatim from the captured envelope above."""
    import binascii

    raw = binascii.unhexlify(CAPTURED_LISTMESSAGES_SLICE0_HEX)
    # Parsed by hand: the capture is a plain TLV stream with no framing.
    import struct as _struct

    parsed: dict[int, bytes] = {}
    offset = 0
    while offset < len(raw):
        tag = _struct.unpack_from(">H", raw, offset)[0]
        offset += 2
        length, offset = _decode_leb(raw, offset)
        parsed[tag] = raw[offset : offset + length]
        offset += length
    return WmsvrSession(
        token=parsed[0x0101].decode(),
        route=parsed[0x0102].decode(),
        host=parsed[0x0200].decode(),
        port=_struct.unpack(">H", parsed[0x0201])[0],
        account_desc=parsed[0x0016].decode(),
        ticket=parsed[0x0113].decode(),
        trace_id=parsed[0x0115].decode(),
        device_info=parsed[0x0114].decode(),
        client_id=parsed[0x0014].decode(),
    )


def test_envelope_reproduces_the_captured_request_slice0_byte_for_byte() -> None:
    envelope = wmsvr_module.build_envelope(_captured_listmessages_session(), "wzp:listMessages")

    assert envelope == unhexlify(CAPTURED_LISTMESSAGES_SLICE0_HEX)
    assert len(envelope) == 614
    # The padded length is what the wire reports as len0, so this is the check that
    # ties our builder to the captured header rather than just to itself. The
    # envelope is not 16-aligned, which is also why the captured frame cannot tell
    # the client's PKCS#7 rule apart from the legacy NUL one.
    assert len(pad_d1_slice(envelope)) == 624
    assert pad_d1_slice(envelope)[len(envelope) :] == b"\x0a" * 10


def test_request_frame_default_slice0_is_the_envelope_alone() -> None:
    session = _captured_listmessages_session()
    frame = build_wmsvr_d1_request_frame(
        WmsvrD1RequestContext(),
        session,
        "wzp:listMessages",
        body={"a": 1},
    )

    assert frame.header.len0 == 624
    assert frame.header.len1 == 16
    # The capture says 624; 614 plus the 42-byte control prefix is 656, which is
    # 16-aligned and so grows to 672 under the client's rule.
    assert frame.header.len0 != 672


def test_business_request_frame_can_still_prefix_control_for_negative_control() -> None:
    session = _captured_listmessages_session()
    frame = build_wmsvr_d1_request_frame(
        WmsvrD1RequestContext(),
        session,
        "wzp:listMessages",
        body={"a": 1},
        include_d1_control=True,
    )

    assert frame.header.len0 == 672  # 656 aligned, +one 0x10 block under the client rule


def test_login_frame_slice0_carries_no_control_pair_by_default() -> None:
    frame, session_key, _client_id = build_wmsvr_login_frame(_login_context())

    plaintext = decrypt_wmsvr_d1_slice(frame.slice0, session_key)
    records = decode_tlv_envelope(plaintext[: _tlv_records_end(plaintext)])
    tags = [tag for tag, _value in records]

    assert 0x0100 in tags
    assert 0x0001 not in tags and 0x0002 not in tags
    assert tags[0] == 0x0100


def test_login_frame_can_still_prefix_control_for_negative_control() -> None:
    plain_len0 = build_wmsvr_login_frame(_login_context())[0].header.len0
    frame, session_key, _client_id = build_wmsvr_login_frame(
        _login_context(),
        include_d1_control=True,
    )

    plaintext = decrypt_wmsvr_d1_slice(frame.slice0, session_key)
    records = decode_tlv_envelope(plaintext[: _tlv_records_end(plaintext)])
    tags = [tag for tag, _value in records]

    assert tags[:2] == [0x0001, 0x0002]
    # The control pair is what the old default sent; it only ever made slice0 longer.
    assert frame.header.len0 is not None and plain_len0 is not None
    assert frame.header.len0 > plain_len0


def _full_login_context() -> WmsvrLoginContext:
    """A context with the runtime tail sizes a real install has (218/19/149)."""
    context = _login_context()
    context.config_id = "10"
    # A real install's device id is 32 chars; the dummy one is 12, and the 20-byte
    # difference is what moves the padded envelope between 480 and 512.
    context.device_id = "W" * 32
    context.master_fp = "F" * 218
    context.master_sdid = "1" * 19
    context.device_info_json = '{"appVersion":"5.7.2.1006"}'.ljust(149, " ")
    return context


def test_full_size_login_frame_matches_the_captured_login_channel_len0() -> None:
    # The `word2=0x0003` connections carried len0=512 on every request, and a
    # full-size login envelope is 499 bytes, which pads to exactly 512.
    context = _full_login_context()
    body = wmsvr_module.build_loginone_body(context)
    without, _key, _cid = build_wmsvr_login_frame(context, body=body)
    with_control, _key2, _cid2 = build_wmsvr_login_frame(
        context,
        body=body,
        include_d1_control=True,
    )

    assert without.header.len0 == 512
    assert without.header.word0 == 0xB000
    assert without.header.len1 is not None and without.header.len1 > 0
    assert with_control.header.len0 == 544


def test_login_frame_version_record_is_optional_and_length_neutral() -> None:
    """Both shapes pad to 512, which is exactly why the flag exists."""
    context = _full_login_context()
    body = wmsvr_module.build_loginone_body(context)

    without, _k1, _c1 = build_wmsvr_login_frame(context, body=body)
    with_version, _k2, _c2 = build_wmsvr_login_frame(
        context,
        body=body,
        prefix_version=True,
    )

    assert without.header.len0 == 512
    assert with_version.header.len0 == 512
    # Same padded length, different first record: the length cannot tell them apart.
    plain = decrypt_wmsvr_d1_slice(with_version.slice0, _k2)
    records = decode_tlv_envelope(plain[: _tlv_records_end(plain)])
    assert [tag for tag, _value in records][0] == 0x0107
    assert dict(records)[0x0107] == b"\x00\x00\x00\x01"


def test_summarize_login_response_reports_names_without_values() -> None:
    """The probe's acceptance evidence is *which* fields came back, not their values."""
    response = WmsvrLoginResponse(
        code="200",
        status="ok",
        success=True,
        mixmail_token="m" * 24,
        ntessess_token="n" * 12,
        sid="SIDVALUE",
        uid="12345",
        raw_json={"code": "200", "mixmailToken": "m" * 24, "sid": "SIDVALUE"},
    )

    summary = summarize_login_response(response)
    rendered = json.dumps(summary)

    assert summary["code"] == "200"
    assert summary["success"] is True
    assert summary["json_keys"] == ["code", "mixmailToken", "sid"]
    assert summary["token_fields_present"] == ["mixmailToken", "ntessessToken"]
    assert summary["identifier_fields_present"] == ["sid", "uid"]
    assert summary["value_lengths"]["mixmailToken"] == 24
    # Nothing sensitive may reach the default report, in any shape.
    assert "m" * 24 not in rendered
    assert "SIDVALUE" not in rendered
    assert "values" not in summary
    assert "raw_json" not in summary


def test_describe_login_response_slice_reports_shape_not_values() -> None:
    """One probe must answer "what encoding came back" as well as "what code".

    The response container is not settled (the request slices are TLV; JSON for the
    response is only the working hypothesis), so the shape report deliberately says
    what the bytes look like instead of assuming a parser. Values never appear.
    """
    json_body = b'{"code":"200","mixmailToken":"TOPSECRETTOKENVALUE"}'

    described = wmsvr_module.describe_login_response_slice(json_body)

    assert described["looks_like_json"] is True
    assert described["json_decoded"] is True
    assert described["printable_ratio"] == 1.0
    assert described["field_name_offsets"]["mixmailToken"] == [15]
    assert "TOPSECRETTOKENVALUE" not in json.dumps(described)

    noise = wmsvr_module.describe_login_response_slice(bytes(range(32)))
    assert noise["looks_like_json"] is False
    assert noise["printable_ratio"] < 0.5
    assert noise["field_name_offsets"] == {}


def test_describe_login_response_slice_requires_key_like_delimiters() -> None:
    """Short names must not match inside unrelated words.

    A false "the server returned uid" is worse than no evidence: it would look like
    acceptance. So a name only counts when a non-identifier byte bounds both sides.
    """
    assert wmsvr_module.describe_login_response_slice(b"encodeuiduidwide")["field_name_offsets"] == {}
    assert wmsvr_module.describe_login_response_slice(b"uid=42&sid=7")["field_name_offsets"] == {
        "sid": [7],
        "uid": [0],
    }


def test_login_response_body_survives_pkcs7_padding() -> None:
    """The live 2026-10-13 answer: `{"code":1}` arrives padded with 6x 0x06.

    Servers pad a slice to the 16-byte boundary with PKCS#7, so a naive `json.loads` on the
    padded bytes fails and the server's own error code is lost (the summary then reports the
    TLV method name in `code` instead). This pins the captured 16 bytes as a vector.
    """
    slice1 = unhexlify("7b22636f6465223a317d060606060606")
    response = wmsvr_module.parse_login_response(b"", slice1)

    assert response.raw_json == {"code": 1}
    assert response.code == "1"
    assert response.success is False


def test_strip_wmsvr_slice_padding_handles_pkcs7_and_nuls() -> None:
    assert wmsvr_module.strip_wmsvr_slice_padding(b'{"code":1}' + b"\x06" * 6) == b'{"code":1}'
    assert wmsvr_module.strip_wmsvr_slice_padding(b"payload" + b"\x00" * 4) == b"payload"
    # Nothing that is not padding may be removed: a real trailing 0x02 is payload.
    assert wmsvr_module.strip_wmsvr_slice_padding(b"ab\x03") == b"ab\x03"
    assert wmsvr_module.strip_wmsvr_slice_padding(b"") == b""


def test_summarize_login_response_describes_both_slices() -> None:
    """The summary carries the per-slice shape, including slice0's decoded TLV tags."""
    plain = wmsvr_module.encode_tlv(0x0100, b"200") + wmsvr_module.encode_tlv(0x0101, b"tok")
    response = WmsvrLoginResponse(
        code="200",
        raw_slice0=plain,
        raw_slice1=b'{"loginState":"ok"}',
    )

    summary = summarize_login_response(response)

    assert summary["slice0_shape"]["tlv_tags"] == ["0x100", "0x101"]
    assert summary["slice0_shape"]["field_name_offsets"] == {}
    assert summary["slice1_shape"]["looks_like_json"] is True
    assert summary["slice1_shape"]["field_name_offsets"] == {"loginState": [2]}


def test_summarize_login_response_can_include_secrets() -> None:
    response = WmsvrLoginResponse(
        mixmail_token="m" * 8,
        raw_json={"mixmailToken": "m" * 8},
    )

    summary = summarize_login_response(response, include_secrets=True)

    assert summary["values"]["mixmailToken"] == "m" * 8
    assert summary["raw_json"] == {"mixmailToken": "m" * 8}


def test_login_envelope_record_table_matches_the_client_writer() -> None:
    """Pin the login envelope's record table to the client's own writer (`0x10a23720`).

    That function calls the TLV writer `0x10c14ee0` exactly six times: `0x100` (the
    method), a `0x107` string on the loginmail branch only, `0x10f`/`0x110`/`0x112`, and
    the hardcoded `zh_CN` locale. So a login envelope provably carries no `0x0107` version
    record, and no `0x103` (that tag is written by the OAuth family instead).

    The `0x113`/`0x115`/`0x114`/`0x14` tail is deliberately pinned too, but it is *not*
    written by that function: it comes from another member of the login path and is
    currently justified only by length (it pads to 512, the captured `word2=0x0003`
    channel's `len0`), not by a writer identity.
    """
    context = _full_login_context()
    body = wmsvr_module.build_loginone_body(context)
    frame, key, _client_id = build_wmsvr_login_frame(context, body=body)

    plain = decrypt_wmsvr_d1_slice(frame.slice0, key)
    records = decode_tlv_envelope(plain[: _tlv_records_end(plain)])
    tags = [tag for tag, _value in records if tag != 0x0000]

    assert tags == [
        0x0100,  # method: wzpa:loginone
        0x010F,
        0x0110,
        0x0112,  # the envelope records the login writer emits itself
        0x0204,  # hardcoded zh_CN
        0x0113,
        0x0115,
        0x0114,
        0x0014,  # tail: MasterFP / MasterSdid / device info / client id
    ]
    assert 0x0107 not in tags
    assert 0x0103 not in tags
    assert frame.header.len0 == 512


def test_execute_login_probe_forwards_the_version_record_choice(monkeypatch) -> None:
    settings_ack = bytes.fromhex("d14080000a000000000064")
    fake = _RecordingSocket(settings_ack)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    monkeypatch.setattr(wmsvr_module.socket, "socket", lambda *a, **k: fake)
    monkeypatch.setattr(
        wmsvr_module,
        "find_wmsvr_hardcoded_public_key_by_digest",
        lambda digest, install_root=None: server_key.public_key(),
    )

    probe = wmsvr_module.execute_wmsvr_login_probe(
        _probe_context(),
        method=LOGIN_METHOD_LOGINONE,
        prefix_version=True,
    )

    assert probe.request_frame is not None
    plain = decrypt_wmsvr_d1_slice(probe.request_frame.slice0, probe.session_key)
    assert plain.startswith(b"\x01\x07")


def test_d1_socket_family_follows_the_peer_address_literal() -> None:
    """The login service's locate entry carries IPv6 candidates; a v4 default cannot dial them."""
    assert wmsvr_module.d1_socket_family("111.124.203.43") == socket.AF_INET
    assert wmsvr_module.d1_socket_family("2408:876a:1110:100::9:30:6") == socket.AF_INET6
    assert wmsvr_module.d1_socket_family("220.197.30.4") == socket.AF_INET


def test_login_probe_prefers_an_explicit_peer_over_peer_index(monkeypatch) -> None:
    """`peer=` exists so a probe can address the login service's own locate entry."""
    settings_ack = bytes.fromhex("d14080000a000000000064")
    login_response = build_wmsvr_d1_encrypted_frame(
        b"\x00" * 16,
        session_key=bytes.fromhex("ab" * 16),
        seq=1,
        word2=0x0004,
        word4=0x0003,
    ).to_bytes()
    fake = _RecordingSocket(settings_ack + login_response)
    connected: list[tuple[str, int]] = []
    real_connect = fake.connect

    def _record_connect(address: tuple[str, int]) -> None:
        connected.append(address)
        real_connect(address)

    monkeypatch.setattr(fake, "connect", _record_connect)
    monkeypatch.setattr(wmsvr_module.socket, "socket", lambda *a, **k: fake)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    monkeypatch.setattr(
        wmsvr_module,
        "find_wmsvr_hardcoded_public_key_by_digest",
        lambda digest, install_root=None: server_key.public_key(),
    )

    context = _probe_context()
    explicit = WmsvrPeerCandidate(host="2408:876a:1110:100::9:30:6", port=443, is_ip_v6=True)
    probe = wmsvr_module.execute_wmsvr_login_probe(context, peer=explicit)

    # `peer_index=0` would have dialled 127.0.0.1:1 from the context's own list.
    assert connected == [("2408:876a:1110:100::9:30:6", 443)]
    assert probe.error == ""
