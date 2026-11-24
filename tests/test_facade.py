from pathlib import Path

from mailmaster import Account, MailMaster, MailMasterPaths
from mailmaster.wmsvr import WmsvrLoginContext, WmsvrPeerCandidate


class _FakeStore:
    def __init__(self, account: Account):
        self._account = account

    def get_accounts(self) -> list[Account]:
        return [self._account]

    def get_account(self, identifier: str) -> Account:
        return self._account


class _FakeAccountStore:
    def __init__(self, account: Account, *, install_root: Path | None = None):
        self.account = account
        self.install_root = install_root
        self.mail_db = account.data_path / "mail.db"
        self.content_db = account.data_path / "content.db"

    def list_mail(self, *, mailbox: str | None = None, unread_only: bool = False, limit: int = 20):
        return ["ok", mailbox, unread_only, limit]

    def get_server_configs(self):
        return {
            "SMTPServerConfig": {"host": "smtp.example.com", "port": 465, "user": self.account.email, "password": "secret123", "sslType": 1},
            "IMAPServerConfig": {"host": "imap.example.com", "port": 993, "user": self.account.email, "password": "secret123", "sslType": 1},
        }

    def get_mail(self, mail_id: str):
        from mailmaster.models import MailRecord

        return MailRecord(
            local_id=1,
            remote_id="1734",
            mailbox="INBOX",
            subject="Hi",
            summary="",
            sender_name="",
            sender_email=self.account.email,
            to_list=[],
            cc_list=[],
            reply_to_list=[],
            unread=True,
            starred=False,
            has_attachments=False,
            replied=False,
            forwarded=False,
            received_ts_ms=0,
            orig_ts_ms=0,
            message_id="mid",
            reference_ids="",
        )


def test_mailmaster_open_account(monkeypatch) -> None:
    account = Account(id=1, type=2, valid=True, name="tester@example.com", email="tester@example.com", data_path=Path(r"C:\MailMasterData\tester@example.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    access = mm.open_account("tester@example.com")

    assert access.account.email == "tester@example.com"
    assert access.list_mail(limit=5) == ["ok", None, False, 5]
    assert mm.account("tester@example.com").account.email == "tester@example.com"
    assert mm.list_mail("tester@example.com", limit=3) == ["ok", None, False, 3]


def test_account_access_send_markdown_email(monkeypatch) -> None:
    account = Account(id=1, type=2, valid=True, name="tester@example.com", email="tester@example.com", data_path=Path(r"C:\MailMasterData\tester@example.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    sent: dict[str, object] = {}

    def fake_send_email(profile, **kwargs):
        sent["profile"] = profile
        sent.update(kwargs)

    monkeypatch.setattr("mailmaster._facade.send_email", fake_send_email)

    access = mm.open_account("tester@example.com")
    access.send_markdown_email(to=["user@example.com"], subject="Hi", markdown_text="# Title\n\nHello")

    assert sent["subject"] == "Hi"
    assert sent["to"] == ["user@example.com"]
    assert "Title" in str(sent["body"])
    assert "<h1" in str(sent["html_body"])


def test_account_access_send_email_uses_wmsvr_fallback(monkeypatch) -> None:
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=Path(r"C:\MailMasterData\tester@163.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    sent: dict[str, object] = {}

    def fake_send_email(profile, **kwargs):
        sent["profile"] = profile
        sent.update(kwargs)

    monkeypatch.setattr("mailmaster._facade.send_email", fake_send_email)

    access = mm.open_account("tester@163.com")
    access.send_email(to=["user@example.com"], subject="Hi", body="Hello")

    profile = sent["profile"]
    assert getattr(profile, "smtp_host") == "smtp.163.com"
    assert getattr(profile, "effective_username") == "tester@163.com"
    assert getattr(profile, "password") == "secret123"


def test_account_access_exposes_wmsvr_login_context(monkeypatch) -> None:
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=Path(r"C:\MailMasterData\tester@163.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    fake_bootstrap = type(
        "_Bootstrap",
        (),
        {
            "master_device_info": type(
                "_DeviceInfo",
                (),
                {
                    "config_id": "10",
                    "app_version": "5.5.2.1006",
                    "device_id": "WINTEST",
                    "to_json": staticmethod(lambda: '{"appVersion":"5.5.2.1006"}'),
                },
            )(),
            "fake_device_id": "WINTEST",
            "cloud_info": type(
                "_CloudInfo",
                (),
                {
                    "cloud_id": "cloud-id-123",
                    "cloud_token": "mastersess-token-456",
                },
            )(),
            "master_fp": "MASTERFPVALUE",
            "master_sdid": "1027626894865072128",
            "webui_pub_key": "PUBKEY",
            "get_d1_candidate_peers": staticmethod(lambda account=None: []),
        },
    )()
    monkeypatch.setattr("mailmaster._facade.load_wmsvr_bootstrap", lambda app_db: fake_bootstrap)

    context = mm.get_wmsvr_login_context("tester@163.com")

    assert context.user == "tester@163.com"
    assert context.config_id == "10"
    assert context.appver_inner == 50050021006
    assert context.cloud_id == "cloud-id-123"
    assert context.cloud_token == "mastersess-token-456"


def test_account_access_refreshes_wmsvr_master_session(monkeypatch) -> None:
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=Path(r"C:\MailMasterData\tester@163.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)
    monkeypatch.setattr("mailmaster._facade.load_wmsvr_bootstrap", lambda app_db: object())

    called: dict[str, object] = {}

    class _Result:
        status_code = 200
        success = True
        token = "refreshed"

    def fake_refresh(bootstrap, *, timeout, verify_ssl):
        called["bootstrap"] = bootstrap
        called["timeout"] = timeout
        called["verify_ssl"] = verify_ssl
        return _Result()

    monkeypatch.setattr("mailmaster._facade.refresh_wmsvr_master_session", fake_refresh)

    result = mm.refresh_wmsvr_master_session("tester@163.com", timeout=9.5, verify_ssl=False)

    assert called["timeout"] == 9.5
    assert called["verify_ssl"] is False
    assert result.token == "refreshed"


def test_account_access_probes_wmsvr_get_settings(monkeypatch) -> None:
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=Path(r"C:\MailMasterData\tester@163.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    peer = type("_Peer", (), {"host": "220.197.30.5", "port": 443, "is_ip_v6": False})()
    fake_bootstrap = type(
        "_Bootstrap",
        (),
        {
            "get_d1_candidate_peers": staticmethod(lambda account=None: [peer]),
        },
    )()
    monkeypatch.setattr("mailmaster._facade.load_wmsvr_bootstrap", lambda app_db: fake_bootstrap)

    called: dict[str, object] = {}

    def fake_query(peer_obj, *, request, timeout):
        called["peer"] = peer_obj
        called["request"] = request
        called["timeout"] = timeout
        return {"ok": True}

    monkeypatch.setattr("mailmaster._facade.query_get_settings_peer", fake_query)

    result = mm.probe_wmsvr_get_settings("tester@163.com", use_primary_digest=True, timeout=3.0)

    assert result == {"ok": True}
    assert called["peer"] is peer
    assert called["timeout"] == 3.0


def test_account_access_probes_wmsvr_runtime_public_key(monkeypatch) -> None:
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=Path(r"C:\MailMasterData\tester@163.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    peer = type("_Peer", (), {"host": "220.197.30.5", "port": 443, "is_ip_v6": False})()
    fake_bootstrap = type(
        "_Bootstrap",
        (),
        {
            "get_d1_candidate_peers": staticmethod(lambda account=None: [peer]),
        },
    )()
    monkeypatch.setattr("mailmaster._facade.load_wmsvr_bootstrap", lambda app_db: fake_bootstrap)

    fake_response = object()
    seen: dict[str, object] = {}

    def fake_query(peer_obj, *, request, timeout):
        seen["peer"] = peer_obj
        seen["request"] = request
        seen["timeout"] = timeout
        return fake_response

    def fake_decode(response, *, install_root=None, sibling_public_key=None):
        seen["response"] = response
        seen["install_root"] = install_root
        seen["sibling_public_key"] = sibling_public_key
        return {"version": 401, "digest": "b1f9"}

    monkeypatch.setattr("mailmaster._facade.query_get_settings_peer", fake_query)
    monkeypatch.setattr("mailmaster._facade.decode_get_settings_key_update", fake_decode)

    result = mm.probe_wmsvr_runtime_public_key("tester@163.com", timeout=3.0)

    assert result == {"version": 401, "digest": "b1f9"}
    assert seen["peer"] is peer
    assert seen["timeout"] == 3.0
    assert seen["response"] is fake_response
    assert seen["install_root"] == paths.install_root
    assert seen["sibling_public_key"] is None


def test_mailmaster_inspect_wmsvr_auth_surface_uses_configured_paths(monkeypatch) -> None:
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=Path(r"C:\MailMasterData\tester@163.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    called: dict[str, object] = {}

    def fake_inspect(*, install_root=None, local_root=None, include_values=False):
        called["install_root"] = install_root
        called["local_root"] = local_root
        called["include_values"] = include_values
        return {"ok": True}

    monkeypatch.setattr("mailmaster._facade.inspect_wmsvr_auth_surface", fake_inspect)

    result = mm.inspect_wmsvr_auth_surface(include_values=True)

    assert result == {"ok": True}
    assert called["install_root"] == paths.install_root
    assert called["local_root"] == paths.local_root
    assert called["include_values"] is True


def test_account_access_mark_read(monkeypatch) -> None:
    account = Account(id=1, type=2, valid=True, name="tester@example.com", email="tester@example.com", data_path=Path(r"C:\MailMasterData\tester@example.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    class DummyContext:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return False

    called: dict[str, object] = {}

    monkeypatch.setattr("mailmaster._facade.open_imap_connection", lambda profile: DummyContext())
    monkeypatch.setattr("mailmaster._facade.mark_seen", lambda client, record, seen: called.update({"record": record, "seen": seen}))

    record = mm.mark_read("tester@example.com", "1")

    assert record.remote_id == "1734"
    assert called["seen"] is True


def test_account_access_mark_read_many(monkeypatch) -> None:
    account = Account(id=1, type=2, valid=True, name="tester@example.com", email="tester@example.com", data_path=Path(r"C:\MailMasterData\tester@example.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    class DummyContext:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return False

    called: list[tuple[str, str, bool]] = []

    monkeypatch.setattr("mailmaster._facade.open_imap_connection", lambda profile: DummyContext())
    monkeypatch.setattr(
        "mailmaster._facade.mark_seen",
        lambda client, record, seen: called.append((record.remote_id, record.mailbox, seen)),
    )

    records = mm.mark_read_many("tester@example.com", ["1", "2"])

    assert len(records) == 2
    assert called == [("1734", "INBOX", True), ("1734", "INBOX", True)]


def test_account_access_move_mail_many(monkeypatch) -> None:
    account = Account(id=1, type=2, valid=True, name="tester@example.com", email="tester@example.com", data_path=Path(r"C:\MailMasterData\tester@example.com_1"))
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _MailboxStore(_FakeAccountStore):
        def resolve_mailbox(self, identifier: str) -> str | None:
            return {"Archive": "Archive-ID"}.get(identifier)

    monkeypatch.setattr("mailmaster._facade.AccountStore", _MailboxStore)

    class DummyContext:
        def __enter__(self):
            return object()

        def __exit__(self, exc_type, exc, tb):
            return False

    called: list[tuple[str, str]] = []

    monkeypatch.setattr("mailmaster._facade.open_imap_connection", lambda profile: DummyContext())
    monkeypatch.setattr(
        "mailmaster._facade.imap_move_mail",
        lambda client, record, target_mailbox: called.append((record.remote_id, target_mailbox)),
    )

    records = mm.move_mail_many("tester@example.com", ["1", "2"], target_mailbox="Archive")

    assert len(records) == 2
    assert called == [("1734", "Archive-ID"), ("1734", "Archive-ID")]


def test_account_access_get_capabilities_imap_and_smtp(monkeypatch, tmp_path: Path) -> None:
    data_path = tmp_path / "tester@example.com_1"
    data_path.mkdir()
    (data_path / "mail.db").write_bytes(b"")
    (data_path / "content.db").write_bytes(b"")
    account = Account(id=1, type=2, valid=True, name="tester@example.com", email="tester@example.com", data_path=data_path)
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    capabilities = mm.get_capabilities("tester@example.com")

    assert capabilities.has_imap_config is True
    assert capabilities.has_smtp_config is True
    assert capabilities.has_wmsvr_config is False
    assert capabilities.supports_local_read is True
    assert capabilities.supports_smtp_send is True
    assert capabilities.supports_imap_mutations is True
    assert capabilities.recommended_send_method == "smtp"
    assert capabilities.recommended_mutation_method == "imap"
    assert "smtp-send" in capabilities.product_paths
    assert "imap-mutations" in capabilities.product_paths


def test_account_access_get_capabilities_wmsvr_fallback(monkeypatch, tmp_path: Path) -> None:
    data_path = tmp_path / "tester@163.com_1"
    data_path.mkdir()
    (data_path / "mail.db").write_bytes(b"")
    account = Account(id=1, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=data_path)
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    capabilities = mm.get_capabilities("tester@163.com")

    assert capabilities.has_wmsvr_config is True
    assert capabilities.has_imap_config is False
    assert capabilities.supports_smtp_send is True
    assert capabilities.supports_imap_mutations is False
    assert capabilities.supports_wmsvr_bootstrap is True
    assert capabilities.smtp_settings_source == "guess_smtp_settings"
    assert capabilities.recommended_send_method == "smtp"
    # Round 113: the guessed profile is still the only send path here, so it stays the
    # recommendation - but the guess is named instead of being presented as verified.
    assert "smtp_profile_guessed" in capabilities.warnings
    # This fixture's app.db is a stub, so the login context cannot be built: the
    # capability record must name that exact reason instead of a vague refusal.
    assert capabilities.supports_wmsvr_private_mutations is False
    assert capabilities.wmsvr_private_mutation_reason is not None
    assert capabilities.wmsvr_private_mutation_reason.startswith("wmsvr_login_context_failed:")
    assert capabilities.recommended_mutation_method == "none"
    assert any(
        warning.startswith("wmsvr_private_mutations_unavailable:")
        for warning in capabilities.warnings
    )


def test_capabilities_report_wmsvr_private_mutations_with_real_bootstrap(monkeypatch, tmp_path: Path) -> None:
    """With working bootstrap material the private mark path is a reported capability."""
    data_path = tmp_path / "tester@163.com_7"
    data_path.mkdir()
    (data_path / "mail.db").write_bytes(b"")
    account = Account(id=7, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=data_path)
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    context = WmsvrLoginContext(
        account=account.email,
        user=account.email,
        password="secret123",
        device_id="device-id",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    monkeypatch.setattr("mailmaster._facade.AccountAccess.get_wmsvr_login_context", lambda self: context)

    capabilities = mm.get_capabilities("tester@163.com")

    assert capabilities.supports_wmsvr_private_mutations is True
    assert capabilities.wmsvr_private_mutation_reason is None
    assert capabilities.recommended_mutation_method == "wmsvr-private"
    assert "wmsvr-private-mutations" in capabilities.product_paths
    # The private send rides the same material (round 62), so it is reported next to it.
    assert capabilities.supports_wmsvr_private_send is True
    assert capabilities.wmsvr_private_send_reason is None
    assert "wmsvr-private-send" in capabilities.product_paths
    # Round 113: a guessed SMTP profile plus a working private send recommends the private
    # path (the live 535 turned the guess into a known-fragile transport).
    assert capabilities.recommended_send_method == "wmsvr-private"
    assert "smtp_profile_guessed" in capabilities.warnings
    assert capabilities.matches(query="163.com", require_mutation=True) is True


def test_capabilities_name_the_empty_password_as_the_wmsvr_gap(monkeypatch, tmp_path: Path) -> None:
    """An empty stored password is reported as exactly that, not as a missing session."""
    data_path = tmp_path / "tester@163.com_5"
    data_path.mkdir()
    (data_path / "mail.db").write_bytes(b"")
    account = Account(id=5, type=1, valid=True, name="tester@163.com", email="tester@163.com", data_path=data_path)
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {"WmsvrServerConfig": {"user": self.account.email, "password": ""}}

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    context = WmsvrLoginContext(
        account=account.email,
        user=account.email,
        password="",
        device_id="device-id",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    monkeypatch.setattr("mailmaster._facade.AccountAccess.get_wmsvr_login_context", lambda self: context)

    capabilities = mm.get_capabilities("tester@163.com")

    assert capabilities.supports_wmsvr_private_mutations is False
    assert capabilities.wmsvr_private_mutation_reason == "stored_password_is_empty"
    assert capabilities.supports_wmsvr_private_send is False
    assert capabilities.wmsvr_private_send_reason == "stored_password_is_empty"
    assert "wmsvr-private-send" not in capabilities.product_paths
    assert "wmsvr_private_mutations_unavailable:stored_password_is_empty" in capabilities.warnings


def test_mailmaster_list_capabilities_filters(monkeypatch, tmp_path: Path) -> None:
    data_a = tmp_path / "a"
    data_a.mkdir()
    (data_a / "mail.db").write_bytes(b"")
    (data_a / "content.db").write_bytes(b"")
    data_b = tmp_path / "b"
    data_b.mkdir()
    (data_b / "mail.db").write_bytes(b"")
    account_a = Account(id=1, type=2, valid=True, name="sender@example.com", email="sender@example.com", data_path=data_a)
    account_b = Account(id=2, type=1, valid=True, name="user@163.com", email="user@163.com", data_path=data_b)
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=tmp_path,
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)

    class _StoreMany:
        def get_accounts(self) -> list[Account]:
            return [account_a, account_b]

        def get_account(self, identifier: str) -> Account:
            for account in [account_a, account_b]:
                if identifier in {str(account.id), account.email, account.name}:
                    return account
            raise ValueError(identifier)

    class _AccountStoreFiltered(_FakeAccountStore):
        def get_server_configs(self):
            if self.account.email == "sender@example.com":
                return {
                    "SMTPServerConfig": {"host": "smtp.example.com", "port": 465, "user": self.account.email, "password": "secret123", "sslType": 1},
                    "IMAPServerConfig": {"host": "imap.example.com", "port": 993, "user": self.account.email, "password": "secret123", "sslType": 1},
                }
            return {
                "WmsvrServerConfig": {"user": self.account.email, "password": "secret123"},
            }

    monkeypatch.setattr(mm, "store", _StoreMany())
    monkeypatch.setattr("mailmaster._facade.AccountStore", _AccountStoreFiltered)

    sendable = mm.list_capabilities(require_send=True)
    mutable = mm.list_capabilities(require_mutation=True)
    bootstrap = mm.list_capabilities(require_wmsvr_bootstrap=True)
    queried = mm.list_capabilities(query="163", require_paths=["smtp-send", "wmsvr-bootstrap"])

    assert [item.email for item in sendable] == ["sender@example.com", "user@163.com"]
    assert [item.email for item in mutable] == ["sender@example.com"]
    assert [item.email for item in bootstrap] == ["user@163.com"]
    assert [item.email for item in queried] == ["user@163.com"]


def test_mailmaster_save_mail_draft_forwards_the_compose_id(monkeypatch) -> None:
    """The top-level wrapper must forward `compose_id`, or `--compose-id` dies with a TypeError.

    Round 73's live acceptance hit exactly that: `AccountAccess.save_mail_draft` accepted the new
    kwarg while `MailMaster.save_mail_draft` did not, and `tests/test_cli_json.py` could not see it
    because its fake MailMaster takes `**kwargs`.
    """
    seen: list[dict] = []

    class _FakeAccess:
        def save_mail_draft(self, **kwargs):
            seen.append(kwargs)
            return {"mode": "update" if kwargs.get("compose_id") else "create"}

    mm = MailMaster()
    monkeypatch.setattr(mm, "open_account", lambda account: _FakeAccess())

    created = mm.save_mail_draft("7", to=["<to>"], subject="s", body="b")
    updated = mm.save_mail_draft("7", to=["<to>"], subject="s", body="b", compose_id="compose-1")

    assert created["mode"] == "create"
    assert updated["mode"] == "update"
    assert [call.get("compose_id") for call in seen] == [None, "compose-1"]
    assert seen[1]["subject"] == "s"


def test_mailmaster_accepts_int_account_identifier(monkeypatch) -> None:
    account = Account(
        id=7,
        type=2,
        valid=True,
        name="tester@example.com",
        email="tester@example.com",
        data_path=Path(r"C:\MailMasterData\tester@example.com_7"),
    )
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files\MailMaster"),
        launcher_exe=None,
        local_root=Path(r"C:\Users\Example\AppData\Local\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    seen_identifiers: list[str] = []

    class _RecordingStore(_FakeStore):
        def get_account(self, identifier: str) -> Account:
            seen_identifiers.append(identifier)
            return super().get_account(identifier)

    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _RecordingStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    assert mm.get_account(7).id == 7
    assert mm.open_account(7).account.id == 7
    assert mm.account(7).account.id == 7
    assert mm.list_mail(7, limit=2) == ["ok", None, False, 2]
    assert seen_identifiers == ["7", "7", "7", "7"]


def test_account_access_resolve_send_transport(monkeypatch, tmp_path: Path) -> None:
    import pytest
    from mailmaster.models import AccountCapabilities

    account = Account(
        id=7,
        type=1,
        valid=True,
        name="tester@163.com",
        email="tester@163.com",
        data_path=tmp_path,
    )
    paths = MailMasterPaths(
        install_root=tmp_path,
        launcher_exe=None,
        local_root=tmp_path,
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)
    access = mm.open_account(7)

    cap_stored_smtp = AccountCapabilities(
        account_id=7,
        email=account.email,
        name=account.name,
        has_local_store=True,
        has_content_store=True,
        has_imap_config=False,
        has_smtp_config=True,
        has_wmsvr_config=True,
        supports_local_read=True,
        supports_smtp_send=True,
        supports_imap_mutations=False,
        supports_wmsvr_bootstrap=True,
        supports_wmsvr_private_send=True,
        smtp_settings_source="SMTPServerConfig",
        recommended_read_method="local-store",
        recommended_send_method="smtp",
        recommended_mutation_method="wmsvr-private",
    )
    cap_guessed_smtp_with_private = AccountCapabilities(
        account_id=7,
        email=account.email,
        name=account.name,
        has_local_store=True,
        has_content_store=True,
        has_imap_config=False,
        has_smtp_config=False,
        has_wmsvr_config=True,
        supports_local_read=True,
        supports_smtp_send=True,
        supports_imap_mutations=False,
        supports_wmsvr_bootstrap=True,
        supports_wmsvr_private_send=True,
        smtp_settings_source="guess_smtp_settings",
        recommended_read_method="local-store",
        recommended_send_method="wmsvr-private",
        recommended_mutation_method="wmsvr-private",
    )
    cap_guessed_smtp_only = AccountCapabilities(
        account_id=7,
        email=account.email,
        name=account.name,
        has_local_store=True,
        has_content_store=True,
        has_imap_config=False,
        has_smtp_config=False,
        has_wmsvr_config=True,
        supports_local_read=True,
        supports_smtp_send=True,
        supports_imap_mutations=False,
        supports_wmsvr_bootstrap=True,
        supports_wmsvr_private_send=False,
        smtp_settings_source="guess_smtp_settings",
        recommended_read_method="local-store",
        recommended_send_method="smtp",
        recommended_mutation_method="none",
    )
    cap_none = AccountCapabilities(
        account_id=7,
        email=account.email,
        name=account.name,
        has_local_store=True,
        has_content_store=True,
        has_imap_config=False,
        has_smtp_config=False,
        has_wmsvr_config=False,
        supports_local_read=True,
        supports_smtp_send=False,
        supports_imap_mutations=False,
        supports_wmsvr_bootstrap=False,
        supports_wmsvr_private_send=False,
        recommended_read_method="local-store",
        recommended_send_method="none",
        recommended_mutation_method="none",
    )

    assert access.resolve_send_transport("auto", capability=cap_stored_smtp) == "smtp"
    assert access.resolve_send_transport("auto", capability=cap_guessed_smtp_with_private) == "wmsvr-private"
    assert access.resolve_send_transport("smtp", capability=cap_guessed_smtp_with_private) == "smtp"
    assert access.resolve_send_transport("auto", capability=cap_guessed_smtp_only) == "smtp"
    assert access.resolve_send_transport("wmsvr-private", capability=cap_guessed_smtp_only) == "none"
    assert access.resolve_send_transport("auto", capability=cap_none) == "none"
    with pytest.raises(ValueError, match="Unknown send transport"):
        access.resolve_send_transport("bogus", capability=cap_stored_smtp)


def test_mailmaster_send_mail_auto_and_markdown_smtp(monkeypatch, tmp_path: Path) -> None:
    data_path = tmp_path / "tester@example.com_1"
    data_path.mkdir()
    (data_path / "mail.db").write_bytes(b"")
    account = Account(
        id=1,
        type=2,
        valid=True,
        name="tester@example.com",
        email="tester@example.com",
        data_path=data_path,
    )
    paths = MailMasterPaths(
        install_root=tmp_path,
        launcher_exe=None,
        local_root=tmp_path,
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    sent: dict[str, object] = {}

    def fake_send_email(profile, **kwargs):
        sent["profile"] = profile
        sent.update(kwargs)

    monkeypatch.setattr("mailmaster._facade.send_email", fake_send_email)

    result = mm.send_mail(
        1,
        to=["dest@example.com"],
        subject="Markdown SMTP",
        markdown_text="# Heading\n\nFormula $E=mc^2$",
        latex_mode="raw",
        in_reply_to="<orig@example.com>",
    )

    assert result["transport"] == "smtp"
    assert result["status"] == "sent"
    assert result["content_mode"] == "markdown"
    assert result["latex_mode"] == "raw"
    assert sent["subject"] == "Markdown SMTP"
    assert sent["in_reply_to"] == "<orig@example.com>"
    assert "Heading" in str(sent["body"])
    assert "<h1" in str(sent["html_body"])
    assert "E=mc^2" in str(sent["html_body"])


def test_mailmaster_send_mail_auto_and_markdown_wmsvr_private(monkeypatch, tmp_path: Path) -> None:
    data_path = tmp_path / "tester@163.com_7"
    data_path.mkdir()
    (data_path / "mail.db").write_bytes(b"")
    account = Account(
        id=7,
        type=1,
        valid=True,
        name="tester@163.com",
        email="tester@163.com",
        data_path=data_path,
    )
    paths = MailMasterPaths(
        install_root=tmp_path,
        launcher_exe=None,
        local_root=tmp_path,
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    paths.app_db.write_bytes(b"")
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))

    class _WmsvrOnlyAccountStore(_FakeAccountStore):
        def get_server_configs(self):
            return {"WmsvrServerConfig": {"user": self.account.email, "password": "secret123"}}

    monkeypatch.setattr("mailmaster._facade.AccountStore", _WmsvrOnlyAccountStore)

    context = WmsvrLoginContext(
        account=account.email,
        user=account.email,
        password="secret123",
        device_id="device-id",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    monkeypatch.setattr("mailmaster._facade.AccountAccess.get_wmsvr_login_context", lambda self: context)

    captured: dict[str, object] = {}

    def fake_send_private(self, **kwargs):
        captured.update(kwargs)
        return {
            "transport": "wmsvr-private",
            "method": "mbox:compose",
            "code": "S_OK",
            "sent_id": "721:sent1",
            "state_change_verified": True,
        }

    monkeypatch.setattr("mailmaster._facade.AccountAccess.send_mail_private", fake_send_private)

    result = mm.send_mail(
        7,
        to=["dest@example.com"],
        subject="Markdown Private",
        markdown_text="# Private\n\nInline $a^2+b^2=c^2$",
        latex_mode="auto",
    )

    assert result["transport"] == "wmsvr-private"
    assert result["status"] == "sent"
    assert result["sent_id"] == "721:sent1"
    assert result["content_mode"] == "markdown"
    assert result["latex_mode"] == "mathml"
    assert "Private" in str(captured["body"])
    assert "<h1" in str(captured["html_body"])
    assert "mathml-formula" in str(captured["html_body"])
    assert "cid:" not in str(captured["html_body"])


def test_open_private_session_helper_preserves_monkeypatch_seam(monkeypatch, tmp_path: Path) -> None:
    account = Account(
        id=7,
        type=1,
        valid=True,
        name="tester@163.com",
        email="tester@163.com",
        data_path=tmp_path,
    )
    paths = MailMasterPaths(
        install_root=tmp_path,
        launcher_exe=None,
        local_root=tmp_path,
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )
    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _FakeAccountStore)

    context = WmsvrLoginContext(
        account=account.email,
        user=account.email,
        password="secret123",
        device_id="device-id",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    monkeypatch.setattr("mailmaster._facade.AccountAccess.get_wmsvr_login_context", lambda self: context)
    monkeypatch.setattr(
        "mailmaster._facade.AccountAccess.refresh_wmsvr_master_session",
        lambda self, timeout=20.0: type("_Init", (), {"ok": True, "token": "tok-123", "status_code": 200, "desc": "ok"})(),
    )

    opened: list[dict[str, object]] = []

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def list_folders(self) -> list[dict]:
            return [{"fid": 1, "name": "INBOX"}]

        def set_message_read_verified(self, remote_ids: list[str], *, read: bool) -> dict:
            return {"code": "S_OK", "ids": remote_ids, "read": read, "state_change_verified": True}

    def fake_open_session(ctx, **kwargs):
        opened.append({"context": ctx, **kwargs})
        return _FakeSession()

    monkeypatch.setattr("mailmaster._facade.open_wmsvr_mail_session", fake_open_session)

    folders = mm.list_wmsvr_folders(7)
    marked = mm.mark_read_verified(7, ["1"])

    assert folders == [{"fid": 1, "name": "INBOX"}]
    assert marked["result"]["ids"] == ["1734"]
    assert marked["result"]["read"] is True
    assert len(opened) == 2
    assert all(call["master_session_token"] == "tok-123" and call["account_id"] == "7" for call in opened)


def test_fetch_mail_source_auto_resolves_local_numeric_mail_id(monkeypatch, tmp_path: Path) -> None:
    from mailmaster.models import MailRecord

    account = Account(
        id=7,
        type=1,
        valid=True,
        name="tester@163.com",
        email="tester@163.com",
        data_path=tmp_path,
    )
    paths = MailMasterPaths(
        install_root=tmp_path,
        launcher_exe=None,
        local_root=tmp_path,
        app_db=tmp_path / "app.db",
        accounts_root=tmp_path,
    )

    lookup_calls: list[str] = []

    class _LocalLookupStore(_FakeAccountStore):
        def get_mail(self, mail_id: str) -> MailRecord:
            lookup_calls.append(mail_id)
            if mail_id == "52300":
                return MailRecord(
                    local_id=52300,
                    remote_id="755:xtbC9B-RemoteMid",
                    mailbox="INBOX",
                    subject="Hi",
                    summary="",
                    sender_name="",
                    sender_email="sender@example.com",
                    to_list=[],
                    cc_list=[],
                    reply_to_list=[],
                    unread=False,
                    starred=False,
                    has_attachments=False,
                    replied=False,
                    forwarded=False,
                    received_ts_ms=0,
                    orig_ts_ms=0,
                    message_id="mid",
                    reference_ids="",
                )
            raise ValueError(f"Mail not found: {mail_id}")

    mm = MailMaster(paths=paths)
    monkeypatch.setattr(mm, "store", _FakeStore(account))
    monkeypatch.setattr("mailmaster._facade.AccountStore", _LocalLookupStore)

    context = WmsvrLoginContext(
        account=account.email,
        user=account.email,
        password="secret123",
        device_id="device-id",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    monkeypatch.setattr("mailmaster._facade.AccountAccess.get_wmsvr_login_context", lambda self: context)
    monkeypatch.setattr(
        "mailmaster._facade.AccountAccess.refresh_wmsvr_master_session",
        lambda self, timeout=20.0: type("_Init", (), {"ok": True, "token": "tok-123", "status_code": 200, "desc": "ok"})(),
    )

    fetched_ids: list[str] = []

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def fetch_message_source(self, mid: str, *, max_part: int = 8) -> dict:
            fetched_ids.append(mid)
            return {
                "method": "wzpm:getMessageData",
                "mid": mid,
                "part_slot": 0,
                "offset": 0,
                "source": b"Received: from test\r\n\r\nbody",
                "length": 27,
                "sha256": "0" * 64,
                "candidates": [],
                "source_slots": [0],
                "misses": [],
            }

        def read_message_slice(self, mid: str, *, part: int, offset: int = 0) -> dict:
            fetched_ids.append(mid)
            return {
                "method": "wzpm:getMessageData",
                "mid": mid,
                "served": True,
                "payload": b"Received: slice",
                "length": 15,
                "sha256": "1" * 64,
                "code": "S_OK",
                "extra16": 0,
                "empty": False,
            }

    monkeypatch.setattr("mailmaster._facade.open_wmsvr_mail_session", lambda ctx, **kwargs: _FakeSession())

    # Local numeric ID resolves to RemoteId automatically (both scan and explicit part modes).
    res_scan = mm.fetch_mail_source(7, "52300")
    res_part = mm.fetch_mail_source(7, "52300", part=2)
    # Already-qualified RemoteId skips local lookup.
    res_remote = mm.fetch_mail_source(7, "755:direct-remote")
    # Unknown synthetic ID without ":" falls back to passing through unchanged.
    res_fallback = mm.fetch_mail_source(7, "synthetic-999")

    assert res_scan["mid"] == "755:xtbC9B-RemoteMid"
    assert res_part["mid"] == "755:xtbC9B-RemoteMid"
    assert res_remote["mid"] == "755:direct-remote"
    assert res_fallback["mid"] == "synthetic-999"
    assert fetched_ids == [
        "755:xtbC9B-RemoteMid",
        "755:xtbC9B-RemoteMid",
        "755:direct-remote",
        "synthetic-999",
    ]
    assert lookup_calls == ["52300", "52300", "synthetic-999"]
