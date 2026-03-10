from pathlib import Path

from mailmaster import Account, MailMaster, MailMasterPaths


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
