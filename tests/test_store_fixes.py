from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import zlib
from contextlib import AbstractContextManager
from hashlib import pbkdf2_hmac
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import mailmaster.protocol_config as protocol_config_module
import mailmaster.store as store_module
from mailmaster.models import Account, AccountCapabilities, MailContent
from mailmaster.protocol_config import load_server_configs
from mailmaster.store import AccountStore, LocalLookupError, MailMasterStore, _copy_to_temp, copy_sqlite_snapshot


def _create_app_db(app_db: Path, account_data_path: Path) -> None:
    conn = sqlite3.connect(app_db)
    try:
        conn.execute(
            """
            CREATE TABLE Account (
                ID INTEGER PRIMARY KEY,
                Type INTEGER,
                Valid INTEGER,
                Name TEXT,
                Email TEXT,
                DataPath TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO Account (ID, Type, Valid, Name, Email, DataPath) VALUES (?, ?, ?, ?, ?, ?)",
            (1, 0, 1, "Personal", "user@example.com", str(account_data_path)),
        )
        conn.execute(
            "INSERT INTO Account (ID, Type, Valid, Name, Email, DataPath) VALUES (?, ?, ?, ?, ?, ?)",
            (42, 0, 1, "Work", "work@example.com", str(account_data_path)),
        )
        conn.commit()
    finally:
        conn.close()


def _create_mail_and_content_dbs(data_dir: Path, *, create_content_db: bool = True) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    mail_db = data_dir / "mail.db"
    conn = sqlite3.connect(mail_db)
    try:
        conn.execute(
            """
            CREATE TABLE Mailbox (
                Id TEXT PRIMARY KEY,
                Parent TEXT,
                DisplayName TEXT,
                Type INTEGER,
                SyncState INTEGER,
                Remind INTEGER,
                UIFlags INTEGER
            )
            """
        )
        conn.execute(
            "INSERT INTO Mailbox (Id, Parent, DisplayName, Type, SyncState, Remind, UIFlags) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("1", "", "INBOX", 1, 1, 0, 0),
        )
        conn.execute(
            """
            CREATE TABLE MailMeta (
                LocalId INTEGER PRIMARY KEY,
                RemoteId TEXT,
                Mailbox TEXT,
                Subject TEXT,
                Summary TEXT,
                Froms TEXT,
                Tos TEXT,
                Ccs TEXT,
                ReplyTos TEXT,
                Unread INTEGER,
                Starred INTEGER,
                HasAttachments INTEGER,
                Replied INTEGER,
                Forwarded INTEGER,
                ReceivedDate INTEGER,
                OrigDate INTEGER,
                MessageId TEXT,
                ReferenceIds TEXT,
                Deleted INTEGER
            )
            """
        )
        rows = [
            (
                101,
                "r-101",
                "1",
                "Weekly update",
                "Short summary",
                json.dumps({"name": "Alice", "mail": "alpha-sender@example.com"}),
                json.dumps([{"name": "Bob", "mail": "bob@example.com"}]),
                "[]",
                "[]",
                1,
                0,
                0,
                0,
                0,
                3000,
                3000,
                "<101@example.com>",
                "",
                0,
            ),
            (
                102,
                "r-102",
                "1",
                "Monthly report",
                "Another summary",
                json.dumps({"name": "Alpha Team", "mail": "team@example.com"}),
                json.dumps([{"name": "Bob", "mail": "bob@example.com"}]),
                "[]",
                "[]",
                0,
                0,
                0,
                0,
                0,
                2000,
                2000,
                "<102@example.com>",
                "",
                0,
            ),
            (
                103,
                "r-103",
                "1",
                "Alpha digest",
                "Contains keyword in subject",
                json.dumps({"name": "Carol", "mail": "carol@example.com"}),
                json.dumps([{"name": "Bob", "mail": "bob@example.com"}]),
                "[]",
                "[]",
                0,
                0,
                0,
                0,
                0,
                1000,
                1000,
                "<103@example.com>",
                "",
                0,
            ),
        ]
        conn.executemany(
            """
            INSERT INTO MailMeta VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
    finally:
        conn.close()

    if create_content_db:
        content_db = data_dir / "content.db"
        conn = sqlite3.connect(content_db)
        try:
            conn.execute(
                """
                CREATE TABLE MailContent (
                    MailId INTEGER,
                    ContentType INTEGER,
                    OrigBody BLOB,
                    CompressType INTEGER
                )
                """
            )
            html_101 = b"<html><body><p>Detailed alpha milestone achieved in body text.</p></body></html>"
            conn.execute(
                "INSERT INTO MailContent VALUES (?, ?, ?, ?)",
                (101, 1, zlib.compress(html_101), 1),
            )
            conn.execute(
                "INSERT INTO MailContent VALUES (?, ?, ?, ?)",
                (101, 0, b"This is an HTML email", 0),
            )
            conn.execute(
                "INSERT INTO MailContent VALUES (?, ?, ?, ?)",
                (102, 0, b"Completely unrelated body without the search term at all, long enough to keep as text body." * 2, 0),
            )
            # Note: 103 intentionally has no row in MailContent to test missing-ID fallback
            conn.commit()
        finally:
            conn.close()


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def _encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(_pkcs7_pad(data)) + encryptor.finalize()


def _make_capabilities(
    *,
    supports_smtp_send: bool = False,
    supports_wmsvr_private_send: bool = False,
    supports_imap_mutations: bool = False,
    supports_wmsvr_private_mutations: bool = False,
) -> AccountCapabilities:
    return AccountCapabilities(
        account_id=1,
        email="user@163.com",
        name="Test 163",
        has_local_store=True,
        has_content_store=True,
        has_imap_config=supports_imap_mutations,
        has_smtp_config=supports_smtp_send,
        has_wmsvr_config=supports_wmsvr_private_send or supports_wmsvr_private_mutations,
        supports_local_read=True,
        supports_smtp_send=supports_smtp_send,
        supports_imap_mutations=supports_imap_mutations,
        supports_wmsvr_bootstrap=True,
        recommended_read_method="local_sqlite",
        recommended_send_method="wmsvr_private" if supports_wmsvr_private_send else "unsupported",
        recommended_mutation_method="wmsvr_private" if supports_wmsvr_private_mutations else "unsupported",
        supports_wmsvr_private_mutations=supports_wmsvr_private_mutations,
        supports_wmsvr_private_send=supports_wmsvr_private_send,
    )


def test_get_account_accepts_int_and_str(tmp_path: Path) -> None:
    app_db = tmp_path / "app.db"
    data_dir = tmp_path / "acc1"
    _create_app_db(app_db, data_dir)

    store = MailMasterStore(app_db)

    acc_by_int = store.get_account(1)
    acc_by_str = store.get_account("1")
    acc_by_email = store.get_account("user@example.com")
    acc_by_name = store.get_account("Personal")
    acc_42 = store.get_account(42)

    assert acc_by_int == acc_by_str == acc_by_email == acc_by_name
    assert acc_by_int.id == 1
    assert acc_42.id == 42
    assert acc_42.email == "work@example.com"

    with pytest.raises(LocalLookupError) as exc_info:
        store.get_account(999)
    assert exc_info.value.code == "account_not_found"
    assert str(exc_info.value) == "Account not found: 999"


def test_account_capabilities_matches_require_send_for_wmsvr_only() -> None:
    wmsvr_only = _make_capabilities(supports_smtp_send=False, supports_wmsvr_private_send=True)
    smtp_only = _make_capabilities(supports_smtp_send=True, supports_wmsvr_private_send=False)
    neither = _make_capabilities(supports_smtp_send=False, supports_wmsvr_private_send=False)

    assert wmsvr_only.matches(require_send=True) is True
    assert smtp_only.matches(require_send=True) is True
    assert neither.matches(require_send=True) is False


def test_copy_sqlite_snapshot_caches_and_invalidates_on_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _copy_to_temp is copy_sqlite_snapshot
    store_module._SNAPSHOT_CACHE.clear()

    db_path = tmp_path / "sample.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE t (v TEXT)")
        conn.execute("INSERT INTO t VALUES ('v1')")
        conn.commit()
    finally:
        conn.close()

    copy_calls: list[tuple[Path, Path]] = []
    real_copy2 = shutil.copy2

    def tracked_copy2(src: Path | str, dst: Path | str, *args: Any, **kwargs: Any) -> Any:
        copy_calls.append((Path(src), Path(dst)))
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(store_module.shutil, "copy2", tracked_copy2)

    snap1 = copy_sqlite_snapshot(db_path)
    assert len(copy_calls) == 1
    assert snap1.exists()

    # Second call with unchanged file reuses cached snapshot without copying
    snap2 = copy_sqlite_snapshot(db_path)
    assert snap2 == snap1
    assert len(copy_calls) == 1

    # Modify the DB and ensure mtime advances so metadata signature changes
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("INSERT INTO t VALUES ('v2-extra-payload')")
        conn.commit()
    finally:
        conn.close()
    stat = db_path.stat()
    os.utime(db_path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))

    snap3 = copy_sqlite_snapshot(db_path)
    assert snap3 == snap1
    assert len(copy_calls) == 2

    check_conn = sqlite3.connect(snap3)
    try:
        values = [row[0] for row in check_conn.execute("SELECT v FROM t ORDER BY rowid").fetchall()]
    finally:
        check_conn.close()
    assert values == ["v1", "v2-extra-payload"]

    # Deleting the target forces re-copy even if source metadata did not change
    snap3.unlink()
    snap4 = copy_sqlite_snapshot(db_path)
    assert snap4 == snap3
    assert snap4.exists()
    assert len(copy_calls) == 3


def test_copy_sqlite_snapshot_wal_sidecar_invalidation_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store_module._SNAPSHOT_CACHE.clear()

    db_path = tmp_path / "wal_sample.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE items (name TEXT)")
        conn.execute("INSERT INTO items VALUES ('one')")
        conn.commit()
    finally:
        conn.close()

    wal_src = Path(f"{db_path}-wal")
    shm_src = Path(f"{db_path}-shm")
    wal_src.write_bytes(b"wal-v1")
    shm_src.write_bytes(b"shm-v1")

    copy_count = 0
    real_copy2 = shutil.copy2

    def counting_copy2(src: Path | str, dst: Path | str, *args: Any, **kwargs: Any) -> Any:
        nonlocal copy_count
        copy_count += 1
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(store_module.shutil, "copy2", counting_copy2)

    snap = copy_sqlite_snapshot(db_path)
    assert copy_count == 3  # db + wal + shm
    assert Path(f"{snap}-wal").read_bytes() == b"wal-v1"
    assert Path(f"{snap}-shm").read_bytes() == b"shm-v1"

    # Unchanged db + wal -> 0 copies
    copy_sqlite_snapshot(db_path)
    assert copy_count == 3

    # Update only the -wal sidecar -> invalidates cache and re-copies
    wal_src.write_bytes(b"wal-v2-updated")
    wal_stat = wal_src.stat()
    os.utime(wal_src, ns=(wal_stat.st_atime_ns, wal_stat.st_mtime_ns + 1_000_000_000))
    copy_sqlite_snapshot(db_path)
    assert copy_count == 6
    assert Path(f"{snap}-wal").read_bytes() == b"wal-v2-updated"

    # Remove source sidecars -> invalidates cache and removes stale sidecars on target
    wal_src.unlink()
    shm_src.unlink()
    copy_sqlite_snapshot(db_path)
    assert copy_count == 7
    assert not Path(f"{snap}-wal").exists()
    assert not Path(f"{snap}-shm").exists()


def test_get_contents_bulk_and_search_mail_single_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "account_data"
    _create_mail_and_content_dbs(data_dir, create_content_db=True)

    account = Account(
        id=1,
        type=0,
        valid=True,
        name="Personal",
        email="user@example.com",
        data_path=data_dir,
    )
    store = AccountStore(account)

    connect_paths: list[Path] = []
    real_connect = store_module._connect_sqlite

    def tracking_connect(path: Path, *, as_bytes: bool = False) -> AbstractContextManager[sqlite3.Connection]:
        connect_paths.append(path)
        return real_connect(path, as_bytes=as_bytes)

    monkeypatch.setattr(store_module, "_connect_sqlite", tracking_connect)

    # Bulk read opens content.db exactly once and matches get_content semantics
    bulk = store.get_contents_bulk([101, 102, 103, 101])
    assert connect_paths == [store.content_db]
    assert set(bulk.keys()) == {101, 102, 103}
    assert bulk[101].html_body is not None and "alpha milestone" in bulk[101].html_body
    # Short placeholder plain text ("This is an HTML email") falls back to html_to_text
    assert bulk[101].text_body == "Detailed alpha milestone achieved in body text."
    assert bulk[102].html_body is None
    assert bulk[102].text_body is not None and "Completely unrelated body" in bulk[102].text_body
    assert bulk[103] == MailContent(mail_id=103)

    # search_mail(include_body=True) opens mail.db once and content.db at most once
    connect_paths.clear()
    matched = store.search_mail("alpha", include_body=True, limit=10)
    assert connect_paths.count(store.mail_db) == 1
    assert connect_paths.count(store.content_db) == 1
    assert [record.local_id for record in matched] == [101, 103]


def test_get_contents_bulk_handles_missing_content_db(tmp_path: Path) -> None:
    data_dir = tmp_path / "no_content_db"
    _create_mail_and_content_dbs(data_dir, create_content_db=False)
    account = Account(
        id=1,
        type=0,
        valid=True,
        name="Personal",
        email="user@example.com",
        data_path=data_dir,
    )
    store = AccountStore(account)

    assert store.get_contents_bulk([]) == {}
    bulk = store.get_contents_bulk([101, 103])
    assert bulk == {101: MailContent(mail_id=101), 103: MailContent(mail_id=103)}

    # search_mail(include_body=True) still succeeds when content.db is absent
    matched = store.search_mail("alpha", include_body=True, limit=10)
    assert [record.local_id for record in matched] == [103]


def test_load_server_configs_uses_sqlite_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    iv = b"0123456789ABCDEF"
    salt = "unit-test-salt"
    fixed_password = "unit-test-fixed-password"
    runtime_password = "unit-test-runtime-password"

    monkeypatch.setattr(
        protocol_config_module,
        "get_security_constants",
        lambda install_root=None: (iv, salt, fixed_password),
    )
    monkeypatch.setattr(
        protocol_config_module,
        "get_runtime_password",
        lambda install_root=None: runtime_password,
    )

    outer_key = pbkdf2_hmac("sha1", fixed_password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)
    inner_key = pbkdf2_hmac("sha1", runtime_password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)
    inner_cipher = _encrypt_aes_cbc(b"secret-pass", inner_key, iv)
    outer_cipher = _encrypt_aes_cbc(
        json.dumps(
            {
                "host": "smtp.example.com",
                "port": 465,
                "user": "sender@example.com",
                "pass": base64.b64encode(inner_cipher).decode("ascii"),
            }
        ).encode("utf-8"),
        outer_key,
        iv,
    )

    mail_db = tmp_path / "mail.db"
    conn = sqlite3.connect(mail_db)
    try:
        conn.execute("CREATE TABLE AccountConfig (Key TEXT PRIMARY KEY, Value BLOB)")
        conn.execute(
            "INSERT INTO AccountConfig (Key, Value) VALUES (?, ?)",
            ("SMTPServerConfig", outer_cipher),
        )
        conn.commit()
    finally:
        conn.close()

    snapshot_calls: list[Path] = []
    connected_paths: list[Path] = []
    real_snapshot = store_module.copy_sqlite_snapshot
    real_connect = sqlite3.connect

    def tracked_snapshot(path: Path) -> Path:
        snapshot_calls.append(path)
        return real_snapshot(path)

    def tracked_connect(database: Path | str, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        connected_paths.append(Path(database))
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(store_module, "copy_sqlite_snapshot", tracked_snapshot)
    monkeypatch.setattr(protocol_config_module.sqlite3, "connect", tracked_connect)

    configs = load_server_configs(mail_db)

    assert snapshot_calls == [mail_db]
    assert len(connected_paths) == 1
    assert connected_paths[0].resolve() != mail_db.resolve()
    assert configs["SMTPServerConfig"]["host"] == "smtp.example.com"
    assert configs["SMTPServerConfig"]["password"] == "secret-pass"
