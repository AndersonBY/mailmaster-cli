from pathlib import Path
import json

import pytest
from typer.testing import CliRunner

from mailmaster.cli import app
from mailmaster.models import Account, MailMasterPaths
from mailmaster.store import LocalLookupError


runner = CliRunner()


class _FakeStore:
    def __init__(self, account: Account):
        self._account = account

    def get_accounts(self) -> list[Account]:
        return [self._account]

    def get_account(self, identifier: str) -> Account:
        return self._account


def _fake_paths_and_store() -> tuple[MailMasterPaths, _FakeStore]:
    account = Account(
        id=1,
        type=2,
        valid=True,
        name="tester@example.com",
        email="tester@example.com",
        data_path=Path(r"C:\MailMasterData\tester@example.com_1"),
    )
    paths = MailMasterPaths(
        install_root=Path(r"C:\Program Files (x86)\NetEase\MailMaster\Application"),
        launcher_exe=Path(r"C:\Program Files (x86)\NetEase\MailMaster\Application\mailmaster.exe"),
        local_root=Path(r"C:\Users\Example\AppData\Local\NetEase\MailMaster"),
        app_db=Path(r"C:\Users\Example\AppData\Local\NetEase\MailMaster\data\app.db"),
        accounts_root=Path(r"C:\MailMasterData"),
    )
    return paths, _FakeStore(account)


def test_accounts_supports_json_output(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)

    result = runner.invoke(app, ["--format", "json", "accounts"])

    assert result.exit_code == 0
    assert '"ok": true' in result.stdout
    assert '"command": "accounts"' in result.stdout
    assert '"email": "tester@example.com"' in result.stdout


def test_mark_read_supports_multiple_mail_ids_json(monkeypatch) -> None:
    from mailmaster.models import AccountCapabilities, MailRecord

    class _FakeMailMaster:
        def __init__(self) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=1,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=True,
                has_smtp_config=True,
                has_wmsvr_config=False,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=True,
                supports_wmsvr_bootstrap=False,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="imap",
                smtp_config_source="SMTPServerConfig",
                smtp_settings_source="SMTPServerConfig",
                smtp_credential_source="SMTPServerConfig",
                product_paths=["local-read", "smtp-send", "imap-mutations"],
                warnings=[],
            )

        def mark_read_many(self, account: str, mail_ids: list[str]) -> list[MailRecord]:
            return [
                MailRecord(
                    local_id=index,
                    remote_id=f"remote-{item}",
                    mailbox="INBOX",
                    subject=f"subject-{item}",
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
                    message_id=f"mid-{item}",
                    reference_ids="",
                )
                for index, item in enumerate(mail_ids, start=1)
            ]

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "mark-read",
            "--account",
            "tester@example.com",
            "--mail-id",
            "100",
            "--mail-id",
            "200",
        ],
    )

    assert result.exit_code == 0
    assert '"command": "mark-read"' in result.stdout
    assert '"count": 2' in result.stdout
    assert '"remote_id": "remote-100"' in result.stdout
    assert '"remote_id": "remote-200"' in result.stdout


def test_capabilities_supports_json_output(monkeypatch) -> None:
    class _FakeMailMaster:
        def __init__(self) -> None:
            pass

        def list_capabilities(self, **kwargs):
            from mailmaster.models import AccountCapabilities

            assert kwargs == {
                "query": None,
                "require_local_read": False,
                "require_send": False,
                "require_mutation": False,
                "require_wmsvr_bootstrap": False,
                "require_paths": None,
            }
            return [
                AccountCapabilities(
                    account_id=1,
                    email="tester@example.com",
                    name="tester@example.com",
                    has_local_store=True,
                    has_content_store=True,
                    has_imap_config=True,
                    has_smtp_config=True,
                    has_wmsvr_config=False,
                    supports_local_read=True,
                    supports_smtp_send=True,
                    supports_imap_mutations=True,
                    supports_wmsvr_bootstrap=False,
                    recommended_read_method="local-store",
                    recommended_send_method="smtp",
                    recommended_mutation_method="imap",
                    smtp_config_source="SMTPServerConfig",
                    smtp_settings_source="SMTPServerConfig",
                    smtp_credential_source="SMTPServerConfig",
                    product_paths=["local-read", "smtp-send", "imap-mutations"],
                    warnings=[],
                )
            ]

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(app, ["--format", "json", "capabilities"])

    assert result.exit_code == 0
    assert '"command": "capabilities"' in result.stdout
    assert '"count": 1' in result.stdout
    assert '"recommended_send_method": "smtp"' in result.stdout
    assert '"recommended_mutation_method": "imap"' in result.stdout


def test_capabilities_supports_filters_json(monkeypatch) -> None:
    class _FakeMailMaster:
        def __init__(self) -> None:
            pass

        def list_capabilities(self, **kwargs):
            assert kwargs == {
                "query": "163",
                "require_local_read": False,
                "require_send": True,
                "require_mutation": False,
                "require_wmsvr_bootstrap": True,
                "require_paths": ["smtp-send", "wmsvr-bootstrap"],
            }
            return []

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "capabilities",
            "--query",
            "163",
            "--sendable",
            "--bootstrap",
            "--path",
            "smtp-send",
            "--path",
            "wmsvr-bootstrap",
        ],
    )

    assert result.exit_code == 0
    assert '"command": "capabilities"' in result.stdout
    assert '"count": 0' in result.stdout
    assert '"query": "163"' in result.stdout
    assert '"require_send": true' in result.stdout


def test_smtp_send_returns_structured_error_when_unsupported(monkeypatch) -> None:
    from mailmaster.models import AccountCapabilities

    class _FakeStore:
        def get_account(self, identifier: str) -> Account:
            return Account(
                id=1,
                type=1,
                valid=True,
                name="user@example.com",
                email="user@example.com",
                data_path=Path(r"C:\MailMasterData\user@example.com_1"),
            )

    def _fake_paths_and_store_for_send() -> tuple[MailMasterPaths, _FakeStore]:
        paths = MailMasterPaths(
            install_root=Path(r"C:\Program Files (x86)\NetEase\MailMaster\Application"),
            launcher_exe=Path(r"C:\Program Files (x86)\NetEase\MailMaster\Application\mailmaster.exe"),
            local_root=Path(r"C:\Users\Example\AppData\Local\NetEase\MailMaster"),
            app_db=Path(r"C:\Users\Example\AppData\Local\NetEase\MailMaster\data\app.db"),
            accounts_root=Path(r"C:\MailMasterData"),
        )
        return paths, _FakeStore()

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=1,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=False,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                recommended_read_method="local-store",
                recommended_send_method="none",
                recommended_mutation_method="none",
                product_paths=["local-read", "wmsvr-bootstrap"],
                warnings=["wmsvr_private_write_not_supported"],
            )

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store_for_send)
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "smtp-send",
            "--from",
            "user@example.com",
            "--to",
            "dest@example.com",
            "--subject",
            "Test",
            "--body",
            "Hello",
        ],
    )

    assert result.exit_code == 2
    assert '"ok": false' in result.stdout
    assert '"command": "smtp-send"' in result.stdout
    assert '"code": "smtp_send_unsupported"' in result.stdout
    assert '"required_capability": "supports_smtp_send"' in result.stdout


def test_mark_read_returns_structured_error_when_unsupported(monkeypatch) -> None:
    from mailmaster.models import AccountCapabilities

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=1,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=True,
                has_wmsvr_config=False,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=False,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="none",
                product_paths=["local-read", "smtp-send"],
                warnings=[],
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "mark-read",
            "--account",
            "user@example.com",
            "--mail-id",
            "123",
        ],
    )

    assert result.exit_code == 2
    assert '"ok": false' in result.stdout
    assert '"command": "mark-read"' in result.stdout
    assert '"code": "imap_mutation_unsupported"' in result.stdout
    assert '"required_capability": "supports_imap_mutations"' in result.stdout


def test_mark_read_reports_the_ready_wmsvr_request_for_a_163_account(monkeypatch) -> None:
    """A 163/Wmsvr account gets the *the real* missing input, not a vague refusal.

    The request itself is capture-verified (`mbox:updateMessageInfos`, body byte for
    byte, envelope 622 -> 624), so the error must say that and name the one thing it
    still needs: the runtime session records `0x0101`/`0x0102`. The ids come from the
    store's own `RemoteId`, which is already the server's id format.
    """
    from mailmaster.models import AccountCapabilities

    class _FakeRecord:
        remote_id = "756:xtbC9B-JSGrM8v83VAAA3i"

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="none",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap"],
                warnings=["wmsvr_private_write_not_supported"],
            )

        def get_mail(self, account: str, mail_id: str) -> _FakeRecord:
            assert mail_id == "1"
            return _FakeRecord()

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "mark-read", "--account", "user@163.com", "--mail-id", "1"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "wmsvr_session_required"
    details = payload["error"]["details"]
    assert details["missing_envelope_records"] == ["0x0101 token", "0x0102 route"]
    ready = details["ready_request"]
    assert ready["method"] == "mbox:updateMessageInfos"
    assert ready["captured_len0"] == 624
    assert ready["ids"] == ["756:xtbC9B-JSGrM8v83VAAA3i"]
    assert ready["body_json"] == (
        '{"attrs":{"flags":{"read":true}},"ids":["756:xtbC9B-JSGrM8v83VAAA3i"]}'
    )

def test_mark_read_rides_the_wmsvr_private_protocol_when_imap_is_missing(monkeypatch) -> None:
    """A Wmsvr account without IMAP material marks read over the private protocol.

    The command must report the transport it used and the verified remote state
    change, because "the server accepted it" is only credible with the read-back.
    """
    from mailmaster.models import AccountCapabilities, MailRecord

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                supports_wmsvr_private_mutations=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="wmsvr-private",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap", "wmsvr-private-mutations"],
                warnings=[],
            )

        def mark_read_verified(self, account: str, mail_ids: list[str]) -> dict:
            assert mail_ids == ["1"]
            record = MailRecord(
                local_id=1,
                remote_id="755:xtbC8xIioGrPfdK2MAAA3v",
                mailbox="INBOX",
                subject="subject",
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
            return {
                "records": [record],
                "result": {
                    "transport": "wmsvr-private",
                    "method": "mbox:updateMessageInfos",
                    "code": "S_OK",
                    "ids": ["755:xtbC8xIioGrPfdK2MAAA3v"],
                    "remote_flags_before": [{"hasTag": True}],
                    "remote_flags_after": [{"read": True, "hasTag": True}],
                    "state_change_verified": True,
                },
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "mark-read", "--account", "user@163.com", "--mail-id", "1"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    data = payload["data"]
    assert data["transport"] == "wmsvr-private"
    assert data["status"] == "read"
    assert data["server_code"] == "S_OK"
    assert data["state_change_verified"] is True
    assert data["remote_flags_before"] == [{"hasTag": True}]
    assert data["remote_flags_after"] == [{"read": True, "hasTag": True}]
    assert data["count"] == 1


def test_mark_unread_reports_the_private_protocol_error_code(monkeypatch) -> None:
    """A private-protocol rejection is surfaced as its own stable error code."""
    from mailmaster.models import AccountCapabilities
    from mailmaster.wmsvr_mail import WmsvrMailError

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                supports_wmsvr_private_mutations=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="wmsvr-private",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap", "wmsvr-private-mutations"],
                warnings=[],
            )

        def mark_unread_verified(self, account: str, mail_ids: list[str]) -> dict:
            raise WmsvrMailError(
                "wmsvr_session_expired",
                "the logged-in session was refused by the business service",
                details={"reply_code": "FA_INVALID_SESSION", "method": "mbox:updateMessageInfos"},
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "mark-unread", "--account", "user@163.com", "--mail-id", "1"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "wmsvr_session_expired"
    assert payload["error"]["details"]["reply_code"] == "FA_INVALID_SESSION"
    assert payload["error"]["details"]["account"] == "user@163.com"

def test_mark_read_reports_a_missing_mail_as_structured_error(monkeypatch) -> None:
    """A mail id that is not in the local store is a user error, not a traceback."""
    from mailmaster.models import AccountCapabilities

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=5,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=True,
                has_smtp_config=True,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=True,
                supports_wmsvr_bootstrap=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="imap",
                product_paths=["local-read", "smtp-send", "imap-mutations", "wmsvr-bootstrap"],
                warnings=[],
            )

        def mark_read_many(self, account: str, mail_ids: list[str]) -> list:
            raise ValueError("Mail not found: 999")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "mark-read", "--account", "user@163.com", "--mail-id", "999"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "mail_not_found"
    assert payload["error"]["details"]["mail_ids"] == ["999"]

def test_move_mail_rides_the_wmsvr_private_protocol(monkeypatch) -> None:
    """A Wmsvr account without IMAP material moves with attrs.fid and a verified read-back."""
    from mailmaster.models import AccountCapabilities, MailRecord

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                supports_wmsvr_private_mutations=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="wmsvr-private",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap", "wmsvr-private-mutations"],
                warnings=[],
            )

        def move_mail_verified(self, account: str, mail_ids: list[str], *, target_mailbox: str) -> dict:
            assert mail_ids == ["1"]
            assert target_mailbox == "Archive"
            record = MailRecord(
                local_id=1,
                remote_id="755:xtbC8xIioGrPfdK2MAAA3v",
                mailbox="1",
                subject="subject",
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
            return {
                "records": [record],
                "result": {
                    "transport": "wmsvr-private",
                    "method": "mbox:updateMessageInfos",
                    "code": "S_OK",
                    "ids": ["755:xtbC8xIioGrPfdK2MAAA3v"],
                    "target_fid": 6702521,
                    "remote_folders_before": [1],
                    "remote_folders_after": [6702521],
                    "state_change_verified": True,
                    "target_mailbox": "Archive",
                },
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "move-mail",
            "--account",
            "user@163.com",
            "--mail-id",
            "1",
            "--target-mailbox",
            "Archive",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "wmsvr-private"
    assert data["server_code"] == "S_OK"
    assert data["target_fid"] == 6702521
    assert data["remote_folders_before"] == [1]
    assert data["remote_folders_after"] == [6702521]
    assert data["state_change_verified"] is True


def test_move_mail_reports_the_private_protocol_error_code(monkeypatch) -> None:
    """A private move rejection surfaces as its own stable code, not a traceback."""
    from mailmaster.models import AccountCapabilities
    from mailmaster.wmsvr_mail import WmsvrMailError

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                supports_wmsvr_private_mutations=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="wmsvr-private",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap", "wmsvr-private-mutations"],
                warnings=[],
            )

        def move_mail_verified(self, account: str, mail_ids: list[str], *, target_mailbox: str) -> dict:
            raise WmsvrMailError(
                "wmsvr_folder_not_found",
                "the server does not know that folder id",
                details={"target_fid": 999999},
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "move-mail",
            "--account",
            "user@163.com",
            "--mail-id",
            "1",
            "--target-mailbox",
            "999999",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "wmsvr_folder_not_found"
    assert payload["error"]["details"]["target_fid"] == 999999


def test_delete_mail_rides_the_wmsvr_private_protocol(monkeypatch) -> None:
    """A Wmsvr account without IMAP deletes with mbox:deleteMessages and a verified read-back."""
    from mailmaster.models import AccountCapabilities, MailRecord

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                supports_wmsvr_private_mutations=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="wmsvr-private",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap", "wmsvr-private-mutations"],
                warnings=[],
            )

        def delete_mail_verified(self, account: str, mail_ids: list[str]) -> dict:
            assert mail_ids == ["1"]
            record = MailRecord(
                local_id=1,
                remote_id="756:xtbC9B67OmrOOX76twAA3F",
                mailbox="7",
                subject="subject",
                summary="",
                sender_name="",
                sender_email="sender@example.com",
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
            return {
                "records": [record],
                "result": {
                    "transport": "wmsvr-private",
                    "method": "mbox:deleteMessages",
                    "code": "S_OK",
                    "delete_type": "batch",
                    "ids": ["756:xtbC9B67OmrOOX76twAA3F"],
                    "remote_folders_before": [7],
                    "remote_folders_after": [None],
                    "gone": [True],
                    "read_back_code": "S_PARTIAL_OK",
                    "state_change_verified": True,
                },
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "delete-mail", "--account", "user@163.com", "--mail-id", "1"],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "wmsvr-private"
    assert data["server_code"] == "S_OK"
    assert data["delete_type"] == "batch"
    assert data["remote_folders_before"] == [7]
    assert data["remote_folders_after"] == [None]
    assert data["gone"] == [True]
    assert data["state_change_verified"] is True


def test_delete_mail_reports_the_private_protocol_error_code(monkeypatch) -> None:
    """A private delete that the read-back cannot confirm surfaces as its own stable code."""
    from mailmaster.models import AccountCapabilities
    from mailmaster.wmsvr_mail import WmsvrMailError

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str) -> AccountCapabilities:
            return AccountCapabilities(
                account_id=7,
                email=account,
                name=account,
                has_local_store=True,
                has_content_store=True,
                has_imap_config=False,
                has_smtp_config=False,
                has_wmsvr_config=True,
                supports_local_read=True,
                supports_smtp_send=True,
                supports_imap_mutations=False,
                supports_wmsvr_bootstrap=True,
                supports_wmsvr_private_mutations=True,
                recommended_read_method="local-store",
                recommended_send_method="smtp",
                recommended_mutation_method="wmsvr-private",
                product_paths=["local-read", "smtp-send", "wmsvr-bootstrap", "wmsvr-private-mutations"],
                warnings=[],
            )

        def delete_mail_verified(self, account: str, mail_ids: list[str]) -> dict:
            raise WmsvrMailError(
                "wmsvr_state_change_not_verified",
                "the server accepted the delete but the read-back still shows the message",
                details={"ids": ["756:x"], "remote_folders_after": [7]},
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "delete-mail", "--account", "user@163.com", "--mail-id", "1"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "wmsvr_state_change_not_verified"
    assert payload["error"]["details"]["remote_folders_after"] == [7]

def test_send_mail_attach_over_the_private_protocol(monkeypatch, tmp_path) -> None:
    """`send-mail --attach` hands the files to the private send (round 84's four-step upload)."""
    report = tmp_path / "report.bin"
    report.write_bytes(bytes(range(64)))
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def send_mail_private(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "compose_id": "compose-1",
                "code": "S_OK",
                "sent_id": "721:<SentMid>",
                "sent_folder_fid": 3,
                "sent_subject": "with attachment",
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
                "attachments": [
                    {
                        "file_name": "report.bin",
                        "content_type": "application/octet-stream",
                        "size": 64,
                        "attachment_id": 1,
                        "actual_size": 64,
                        "packets": 1,
                        "sent": 64,
                        "completed": True,
                    }
                ],
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "with attachment",
            "--body",
            "text body",
            "--attach",
            str(report),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "wmsvr-private"
    assert data["state_change_verified"] is True
    assert data["attachments"][0]["file_name"] == "report.bin"
    assert data["attachments"][0]["packets"] == 1
    assert data["attachments"][0]["sent"] == 64
    assert data["attachments"][0]["attachment_id"] == 1
    assert data["attachments"][0]["completed"] is True
    assert calls[0]["attachments"] == [report]


def test_send_mail_attach_reports_an_unsupported_private_upload(monkeypatch, tmp_path) -> None:
    """Without the attachment capability the CLI refuses instead of silently dropping files."""
    report = tmp_path / "report.bin"
    report.write_bytes(b"x")

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(
                account, smtp=False, private_send=True, private_attachments=False
            )

        def send_mail_private(self, account: str, **kwargs) -> dict:  # pragma: no cover
            raise AssertionError("the send must not start without the attachment capability")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "x",
            "--body",
            "y",
            "--attach",
            str(report),
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "wmsvr_attachments_unsupported"


def _send_capabilities(
    account: str,
    *,
    smtp: bool,
    private_send: bool,
    private_mutations: bool = True,
    private_drafts: bool | None = None,
    private_attachments: bool | None = None,
    private_draft_send: bool | None = None,
    private_read: bool | None = None,
    smtp_settings_source: str | None = None,
):
    """The capability snapshot `send-mail` chooses a transport from (the private writes share a gate)."""
    from mailmaster.models import AccountCapabilities

    drafts = private_mutations if private_drafts is None else private_drafts
    attachments = private_send if private_attachments is None else private_attachments
    draft_send = private_mutations if private_draft_send is None else private_draft_send
    read = private_mutations if private_read is None else private_read
    product_paths = ["local-read", "wmsvr-bootstrap"]
    if smtp:
        product_paths.append("smtp-send")
    if private_mutations:
        product_paths.append("wmsvr-private-mutations")
    if private_send:
        product_paths.append("wmsvr-private-send")
    if drafts:
        product_paths.append("wmsvr-private-drafts")
    if attachments:
        product_paths.append("wmsvr-private-attachments")
    if draft_send:
        product_paths.append("wmsvr-private-draft-send")
    if read:
        product_paths.append("wmsvr-private-read")
    return AccountCapabilities(
        account_id=7,
        email=account,
        name=account,
        has_local_store=True,
        has_content_store=True,
        has_imap_config=False,
        has_smtp_config=smtp,
        has_wmsvr_config=True,
        supports_local_read=True,
        supports_smtp_send=smtp,
        supports_imap_mutations=False,
        supports_wmsvr_bootstrap=True,
        supports_wmsvr_private_mutations=private_mutations,
        supports_wmsvr_private_send=private_send,
        supports_wmsvr_private_drafts=drafts,
        supports_wmsvr_private_attachments=attachments,
        supports_wmsvr_private_draft_send=draft_send,
        supports_wmsvr_private_read=read,
        wmsvr_private_read_reason=None if read else "wmsvr_bootstrap_unavailable",
        recommended_read_method="local-store",
        recommended_send_method="smtp" if smtp else ("wmsvr-private" if private_send else "none"),
        recommended_mutation_method="wmsvr-private" if private_mutations else "none",
        smtp_settings_source=smtp_settings_source,
        product_paths=product_paths,
        warnings=[],
    )


def test_send_mail_auto_falls_back_to_the_wmsvr_private_protocol(monkeypatch) -> None:
    """`auto` rides the private protocol when the account has no SMTP material (round 62)."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def send_mail_private(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "compose_id": "compose-1",
                "code": "S_OK",
                "sent_id": "721:<SentMid>",
                "sent_folder_fid": 3,
                "sent_subject": "hello",
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "hello",
            "--body",
            "text body",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "wmsvr-private"
    assert data["status"] == "sent"
    assert data["server_code"] == "S_OK"
    assert data["compose_id"] == "compose-1"
    assert data["sent_folder_fid"] == 3
    assert data["state_change_verified"] is True
    assert calls == [
        {
            "account": "user@163.com",
            "to": ["dest@example.com"],
            "cc": [],
            "bcc": [],
            "subject": "hello",
            "body": "text body",
            "html_body": "",
        }
    ]


def test_send_mail_auto_prefers_smtp_when_available(monkeypatch) -> None:
    """SMTP stays the default transport whenever the account has a usable profile."""
    sent: list[dict] = []

    class _FakeAccess:
        def send_email(self, **kwargs) -> None:
            sent.append(kwargs)

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=True, private_send=True)

        def open_account(self, account: str) -> _FakeAccess:
            return _FakeAccess()

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "hello",
            "--body",
            "text body",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "smtp"
    assert sent == [
        {
            "to": ["dest@example.com"],
            "cc": None,
            "bcc": None,
            "subject": "hello",
            "body": "text body",
            "html_body": "",
        }
    ]


def test_send_mail_auto_prefers_private_when_the_smtp_profile_is_guessed(monkeypatch) -> None:
    """Round 113: a guessed SMTP profile loses to a working private send in `auto`."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(
                account,
                smtp=True,
                private_send=True,
                smtp_settings_source="guess_smtp_settings",
            )

        def send_mail_private(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "compose_id": "compose-1",
                "code": "S_OK",
                "sent_id": "721:<SentMid>",
                "sent_folder_fid": 3,
                "sent_subject": "hello",
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
            }

        def open_account(self, account: str):  # pragma: no cover - must not be selected
            raise AssertionError("a guessed SMTP profile must not be chosen by auto")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "hello",
            "--body",
            "text body",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "wmsvr-private"
    assert calls == [
        {
            "account": "user@163.com",
            "to": ["dest@example.com"],
            "cc": [],
            "bcc": [],
            "subject": "hello",
            "body": "text body",
            "html_body": "",
        }
    ]


def test_send_mail_explicit_smtp_reports_auth_failure_as_structured_json(monkeypatch) -> None:
    """Round 112: the 535 must be a JSON error, not an unhandled traceback."""
    import smtplib

    class _FakeAccess:
        def send_email(self, **kwargs) -> None:
            raise smtplib.SMTPAuthenticationError(535, b"Error: authentication failed")

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=True, private_send=True)

        def open_account(self, account: str) -> _FakeAccess:
            return _FakeAccess()

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "hello",
            "--body",
            "text body",
            "--transport",
            "smtp",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == "send-mail"
    assert payload["error"]["code"] == "smtp_auth_failed"
    assert payload["error"]["details"]["smtp_code"] == 535
    assert "authentication failed" in payload["error"]["details"]["smtp_error"]


def test_send_mail_reports_the_unverified_private_delivery(monkeypatch) -> None:
    """A delivery whose sent copy the read-back cannot resolve keeps its own stable code."""
    from mailmaster.wmsvr_mail import WmsvrMailError

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def send_mail_private(self, account: str, **kwargs) -> dict:
            raise WmsvrMailError(
                "wmsvr_state_change_not_verified",
                "the server accepted the delivery but the sent copy does not resolve in "
                "its sent folder",
                details={"sent_id": "721:<SentMid>", "state_change_verified": False},
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "hello",
            "--body",
            "text body",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "wmsvr_state_change_not_verified"
    assert payload["error"]["details"]["state_change_verified"] is False
    assert payload["error"]["details"]["account"] == "user@163.com"


def test_save_draft_reports_the_verified_draft(monkeypatch) -> None:
    """`save-draft` rides the private compose family and reports the read-back (round 70)."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def save_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "mode": "create",
                "recreated": False,
                "compose_id": "compose-1",
                "code": "S_OK",
                "draft_id": "821:<DraftMid>",
                "draft_folder_fid": 2,
                "draft_subject": "draft subject",
                "draft_size": 675,
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "draft subject",
            "--body",
            "draft body",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["status"] == "saved"
    assert data["transport"] == "wmsvr-private"
    assert data["server_code"] == "S_OK"
    assert data["draft_id"] == "821:<DraftMid>"
    assert data["draft_folder_fid"] == 2
    assert data["draft_size"] == 675
    assert data["readback_fallback"] is False
    assert data["state_change_verified"] is True
    assert data["mode"] == "create"
    assert data["recreated"] is False
    assert calls == [
        {
            "account": "user@163.com",
            "to": [],
            "cc": [],
            "bcc": [],
            "subject": "draft subject",
            "body": "draft body",
            "html_body": "",
            "compose_id": None,
        }
    ]


def test_save_draft_attach_uploads_and_reports_the_files(monkeypatch, tmp_path) -> None:
    """`save-draft --attach` hands the files to the private save and reports them (round 87)."""
    calls: list[dict] = []
    attachment = tmp_path / "report.bin"
    attachment.write_bytes(bytes(64))
    report = {
        "file_name": "report.bin",
        "size": 64,
        "attachment_id": 1,
        "actual_size": 64,
        "packets": 1,
        "sent": 64,
        "completed": True,
    }

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def save_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "action": "save",
                "code": "S_OK",
                "compose_id": "compose-1",
                "draft_id": "821:<DraftMid>",
                "draft_folder_fid": 2,
                "draft_subject": "draft with attachment",
                "draft_size": 12305,
                "readback_fallback": False,
                "state_change_verified": True,
                "attachments": [report],
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "draft with attachment",
            "--body",
            "draft body",
            "--attach",
            str(attachment),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["draft_id"] == "821:<DraftMid>"
    assert data["draft_size"] == 12305
    assert data["state_change_verified"] is True
    assert calls[0]["attachments"] == [attachment]
    assert data["attachments"] == [
        {
            "path": str(attachment),
            **report,
        }
    ]


def test_save_draft_attach_reports_an_unsupported_private_upload(monkeypatch, tmp_path) -> None:
    """A draft with an attachment needs the upload capability; without it the CLI refuses."""
    attachment = tmp_path / "report.bin"
    attachment.write_bytes(bytes(64))

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True,
                                      private_attachments=False)

        def save_mail_draft(self, account: str, **kwargs) -> dict:  # pragma: no cover
            raise AssertionError("the unsupported call must not reach the library")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "draft with attachment",
            "--body",
            "draft body",
            "--attach",
            str(attachment),
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "wmsvr_attachments_unsupported"


def test_save_draft_forwards_the_compose_id_and_reports_update(monkeypatch) -> None:
    """`--compose-id` turns the call into an update of that draft (round 72 semantics)."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def save_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "mode": "update",
                "compose_id": "compose-existing",
                "code": "S_OK",
                "draft_id": "821:<NewDraftMid>",
                "draft_folder_fid": 2,
                "draft_subject": "draft subject v2",
                "draft_size": 719,
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "draft subject v2",
            "--body",
            "draft body v2",
            "--compose-id",
            "compose-existing",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["status"] == "saved"
    assert data["mode"] == "update"
    assert data["compose_id"] == "compose-existing"
    assert data["draft_id"] == "821:<NewDraftMid>"
    assert data["state_change_verified"] is True
    assert calls == [
        {
            "account": "user@163.com",
            "to": [],
            "cc": [],
            "bcc": [],
            "subject": "draft subject v2",
            "body": "draft body v2",
            "html_body": "",
            "compose_id": "compose-existing",
        }
    ]


def test_save_draft_reports_an_account_without_the_private_path(monkeypatch) -> None:
    """Drafts are private-protocol only, so a missing capability is a structured error."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(
                account, smtp=True, private_send=False, private_mutations=False, private_drafts=False
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "draft subject",
            "--body",
            "draft body",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "draft_unsupported"
    assert payload["error"]["details"]["required_capability"] == "supports_wmsvr_private_drafts"
    assert "supports_wmsvr_private_drafts" in payload["error"]["details"]["capabilities"]


def test_send_mail_reports_when_no_send_transport_exists(monkeypatch) -> None:
    """An account with neither SMTP nor Wmsvr send material gets the capability snapshot."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(
                account, smtp=False, private_send=False, private_mutations=False
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "hello",
            "--body",
            "text body",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "send_unsupported"
    assert payload["error"]["details"]["requested_transport"] == "auto"
    assert "supports_wmsvr_private_send" in payload["error"]["details"]["capabilities"]


def test_save_draft_reports_a_recreated_draft_for_a_stale_compose_id(monkeypatch) -> None:
    """Round 74/75: a deleted draft's `--compose-id` still writes, and the payload says so."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def save_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "mode": "update",
                "recreated": True,
                "compose_id": "compose-stale",
                "code": "FS_UD0108",
                "draft_id": "821:<NewDraftMid>",
                "draft_folder_fid": 2,
                "draft_subject": "draft subject v3",
                "draft_size": 842,
                "read_back_code": "S_OK",
                "readback_fallback": True,
                "state_change_verified": True,
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "draft subject v3",
            "--body",
            "draft body v3",
            "--compose-id",
            "compose-stale",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["status"] == "saved"
    assert data["recreated"] is True
    assert data["server_code"] == "FS_UD0108"
    assert data["draft_id"] == "821:<NewDraftMid>"
    assert data["readback_fallback"] is True
    assert data["state_change_verified"] is True
    assert calls[0]["compose_id"] == "compose-stale"

def test_send_draft_reports_the_verified_sent_copy(monkeypatch) -> None:
    """`send-draft` re-opens the stored draft and reports the read-back (round 88/89)."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def send_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "from_draft": True,
                "draft_id": "755:<DraftMid>",
                "compose_id": "compose-restored",
                "to": ["user@163.com"],
                "cc": [],
                "bcc": [],
                "subject": "draft subject",
                "code": "S_OK",
                "saved_sent": {"msid": 12, "mid": "newMid"},
                "sent_id": "12:newMid",
                "sent_folder_fid": 3,
                "sent_subject": "draft subject",
                "sent_size": 12483,
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
                "attachments": [
                    {
                        "attachment_id": 1,
                        "type": "upload",
                        "file_name": "report.bin",
                        "content_type": "application/octet-stream",
                        "size": 8192,
                    }
                ],
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-draft",
            "--account",
            "user@163.com",
            "--draft-id",
            "755:<DraftMid>",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["status"] == "sent"
    assert data["transport"] == "wmsvr-private"
    assert data["from_draft"] is True
    assert data["server_code"] == "S_OK"
    assert data["draft_id"] == "755:<DraftMid>"
    assert data["sent_id"] == "12:newMid"
    assert data["sent_folder_fid"] == 3
    assert data["sent_size"] == 12483
    assert data["state_change_verified"] is True
    # the stored attachment rides along without a second upload
    assert data["attachments"] == [
        {
            "attachment_id": 1,
            "file_name": "report.bin",
            "content_type": "application/octet-stream",
            "size": 8192,
            "uploaded_again": False,
        }
    ]
    assert calls == [
        {
            "account": "user@163.com",
            "draft_id": "755:<DraftMid>",
        }
    ]


def test_send_draft_resolves_the_draft_by_subject(monkeypatch) -> None:
    """`--subject` resolves the draft id first, so a client-created draft can be sent."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def find_mail_draft(self, account: str, *, subject: str = "", limit: int = 20) -> dict:
            calls.append({"find": subject})
            return {"draft_id": "755:<FoundMid>", "subject": subject, "size": 12305}

        def send_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"send": kwargs.get("draft_id")})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "from_draft": True,
                "draft_id": kwargs.get("draft_id"),
                "compose_id": "compose-restored",
                "to": ["user@163.com"],
                "subject": "wanted draft",
                "code": "S_OK",
                "sent_id": "12:newMid",
                "sent_folder_fid": 3,
                "state_change_verified": True,
                "readback_fallback": False,
                "attachments": [],
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-draft",
            "--account",
            "user@163.com",
            "--subject",
            "wanted draft",
            "--to",
            "other@example.com",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["draft_id"] == "755:<FoundMid>"
    assert data["sent_folder_fid"] == 3
    assert calls == [{"find": "wanted draft"}, {"send": "755:<FoundMid>"}]


def test_send_draft_needs_a_draft_id_or_a_subject(monkeypatch) -> None:
    """Without either the draft cannot be addressed; the CLI refuses before logging in."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:  # pragma: no cover
            raise AssertionError("the CLI must refuse before touching the account")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(app, ["--format", "json", "send-draft", "--account", "user@163.com"])
    assert result.exit_code == 2


def test_send_draft_reports_an_account_without_the_private_path(monkeypatch) -> None:
    """A stored draft lives on the server, so without the private path there is no transport."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(
                account, smtp=True, private_send=False, private_drafts=False,
                private_draft_send=False,
            )

        def send_mail_draft(self, account: str, **kwargs) -> dict:  # pragma: no cover
            raise AssertionError("the unsupported call must not reach the library")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-draft",
            "--account",
            "user@163.com",
            "--draft-id",
            "755:<DraftMid>",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "draft_send_unsupported"


def test_fetch_mail_writes_the_source_and_reports_its_hash(monkeypatch, tmp_path) -> None:
    """`fetch-mail` writes the fetched bytes and reports their length and sha256 (round 93)."""
    import hashlib

    calls: list[dict] = []
    source = b"Received: from <RemoteId>\r\nSubject: <redacted>\r\n\r\nbody\r\n"
    out = tmp_path / "source.eml"

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_read=True)

        def fetch_mail_source(self, account: str, mail_id: str, **kwargs) -> dict:
            calls.append({"account": account, "mail_id": mail_id, **kwargs})
            return {
                "method": "wzpm:getMessageData",
                "mid": mail_id,
                "mode": "scan",
                "part_slot": 0,
                "offset": 0,
                "source": source,
                "length": len(source),
                "sha256": hashlib.sha256(source).hexdigest(),
                "source_slots": [0],
                "candidates": [{"part": 0, "length": len(source), "is_source": True}],
                "misses": [],
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "fetch-mail",
            "--account",
            "user@163.com",
            "--mail-id",
            "755:<RemoteId>",
            "--out",
            str(out),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["status"] == "fetched"
    assert data["transport"] == "wmsvr-private"
    assert data["method"] == "wzpm:getMessageData"
    assert data["mode"] == "scan"
    assert data["part_slot"] == 0
    assert data["length"] == len(source)
    assert data["sha256"] == hashlib.sha256(source).hexdigest()
    assert data["bytes_written"] == len(source)
    assert data["out"] == str(out)
    assert out.read_bytes() == source
    assert calls == [
        {"account": "user@163.com", "mail_id": "755:<RemoteId>", "part": None, "offset": 0, "max_part": 8}
    ]


def test_fetch_mail_reads_an_explicit_slot(monkeypatch) -> None:
    """`--part` reads that slot faithfully (mode `part`), without scanning."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def fetch_mail_source(self, account: str, mail_id: str, **kwargs) -> dict:
            calls.append({"account": account, "mail_id": mail_id, **kwargs})
            return {
                "method": "wzpm:getMessageData",
                "mid": mail_id,
                "mode": "part",
                "part_slot": 3,
                "offset": 512,
                "source": b"<!DOCTYPE html>",
                "length": 15,
                "sha256": "0" * 64,
                "source_slots": [3],
                "candidates": [{"part": 3, "length": 15, "is_source": False}],
                "misses": [],
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "fetch-mail",
            "--account",
            "user@163.com",
            "--mail-id",
            "755:<RemoteId>",
            "--part",
            "3",
            "--offset",
            "512",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["mode"] == "part"
    assert data["part_slot"] == 3
    assert data["offset"] == 512
    assert calls == [
        {"account": "user@163.com", "mail_id": "755:<RemoteId>", "part": 3, "offset": 512, "max_part": 8}
    ]


def test_fetch_mail_reports_a_slot_that_serves_nothing(monkeypatch) -> None:
    """A slot the server answers `FA_PART_NOT_FOUND` for is a failure, not an empty success."""
    from mailmaster.wmsvr_mail import ERROR_PART_NOT_FOUND, WmsvrMailError

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def fetch_mail_source(self, account: str, mail_id: str, **kwargs) -> dict:
            raise WmsvrMailError(
                ERROR_PART_NOT_FOUND,
                "slot 3 of that message served nothing",
                details={"reply_code": "FA_PART_NOT_FOUND", "part": 3},
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "fetch-mail",
            "--account",
            "user@163.com",
            "--mail-id",
            "755:<RemoteId>",
            "--part",
            "3",
        ],
    )

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "wmsvr_part_not_found"
    assert error["details"]["reply_code"] == "FA_PART_NOT_FOUND"


def test_fetch_mail_reports_a_window_without_a_source(monkeypatch) -> None:
    """No `Received:`-headed slice in the window is its own structured failure."""
    from mailmaster.wmsvr_mail import ERROR_SOURCE_NOT_FOUND, WmsvrMailError

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def fetch_mail_source(self, account: str, mail_id: str, **kwargs) -> dict:
            raise WmsvrMailError(
                ERROR_SOURCE_NOT_FOUND,
                "none of the slots 0..8 of that message carried a source slice",
                details={"slots_tried": list(range(9)), "served_slots": []},
            )

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "fetch-mail", "--account", "user@163.com", "--mail-id", "755:<RemoteId>"],
    )

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "wmsvr_source_not_found"
    assert error["details"]["served_slots"] == []


def test_fetch_mail_reports_an_offset_without_a_slot(monkeypatch) -> None:
    """`--offset` without `--part` is a caller mistake (the facade rejects it)."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

        def fetch_mail_source(self, account: str, mail_id: str, **kwargs) -> dict:
            raise ValueError("a byte offset needs a slot")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "fetch-mail",
            "--account",
            "user@163.com",
            "--mail-id",
            "755:<RemoteId>",
            "--offset",
            "512",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "fetch_invalid"


def test_fetch_mail_reports_an_account_without_the_private_read(monkeypatch) -> None:
    """An account without the private material gets the capability reason, not a traceback."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=False, private_read=False)

        def fetch_mail_source(self, account: str, mail_id: str, **kwargs) -> dict:
            raise AssertionError("the unsupported call must not reach the library")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "fetch-mail", "--account", "user@163.com", "--mail-id", "755:<RemoteId>"],
    )

    assert result.exit_code == 2
    error = json.loads(result.stdout)["error"]
    assert error["code"] == "mail_read_unsupported"
    assert error["details"]["required_capability"] == "supports_wmsvr_private_read"
    assert error["details"]["unavailable_reason"] == "wmsvr_bootstrap_unavailable"


def test_mailboxes_reports_a_missing_account_as_structured_error(monkeypatch) -> None:
    """An unknown account is a user error, not a traceback."""

    def _paths_and_missing_store():
        paths, _ = _fake_paths_and_store()

        class _MissingAccountStore:
            def get_account(self, identifier: str) -> Account:
                raise LocalLookupError("account_not_found", f"Account not found: {identifier}")

        return paths, _MissingAccountStore()

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _paths_and_missing_store)

    result = runner.invoke(app, ["--format", "json", "mailboxes", "--account", "zzzz"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "account_not_found"
    assert payload["error"]["details"]["account"] == "zzzz"


def test_list_reports_a_missing_mailbox_as_structured_error(monkeypatch) -> None:
    """An unknown mailbox name is a user error, not a traceback."""

    class _FakeAccountStore:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def list_mail(self, **kwargs):
            raise LocalLookupError("mailbox_not_found", "Mailbox not found: no-such-mailbox")

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)
    monkeypatch.setattr("mailmaster.cli.commands.AccountStore", _FakeAccountStore)

    result = runner.invoke(
        app,
        ["--format", "json", "list", "--account", "tester@example.com", "--mailbox", "no-such-mailbox"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "mailbox_not_found"
    assert payload["error"]["details"]["mailbox"] == "no-such-mailbox"


def test_read_reports_a_missing_mail_as_structured_error(monkeypatch) -> None:
    """An unknown mail id on the local read surface is a user error, not a traceback."""

    class _FakeAccountStore:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_details(self, mail_id: str):
            raise LocalLookupError("mail_not_found", f"Mail not found: {mail_id}")

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)
    monkeypatch.setattr("mailmaster.cli.commands.AccountStore", _FakeAccountStore)

    result = runner.invoke(
        app,
        ["--format", "json", "read", "--account", "tester@example.com", "--mail-id", "999"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "mail_not_found"
    assert payload["error"]["details"]["mail_ids"] == ["999"]


def test_search_reports_a_missing_mailbox_as_structured_error(monkeypatch) -> None:
    """The body-search path shares the mailbox lookup contract."""

    class _FakeAccountStore:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def search_mail(self, *args, **kwargs):
            raise LocalLookupError("mailbox_not_found", "Mailbox not found: no-such-mailbox")

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)
    monkeypatch.setattr("mailmaster.cli.commands.AccountStore", _FakeAccountStore)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "search",
            "--account",
            "tester@example.com",
            "needle",
            "--mailbox",
            "no-such-mailbox",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "mailbox_not_found"
    assert payload["error"]["details"]["mailbox"] == "no-such-mailbox"


def test_capabilities_reports_a_missing_account_as_structured_error(monkeypatch) -> None:
    """Capabilities is local-only; an unknown account follows the same contract."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app, ["--format", "json", "capabilities", "--account", "zzzz"]
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "account_not_found"
    assert payload["error"]["details"]["account"] == "zzzz"


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (["wmsvr-bootstrap", "--account", "zzzz"], "wmsvr-bootstrap"),
        (
            [
                "smtp-send",
                "--from",
                "zzzz",
                "--to",
                "nobody@example.invalid",
                "--subject",
                "r122",
                "--body",
                "x",
            ],
            "smtp-send",
        ),
        (
            [
                "send-mail",
                "--account",
                "zzzz",
                "--to",
                "nobody@example.invalid",
                "--subject",
                "r122",
                "--body",
                "x",
                "--transport",
                "smtp",
            ],
            "send-mail",
        ),
        (["send-draft", "--account", "zzzz", "--draft-id", "1"], "send-draft"),
        (["fetch-mail", "--account", "zzzz", "--mail-id", "1"], "fetch-mail"),
        (["save-draft", "--account", "zzzz", "--subject", "r122", "--body", "x"], "save-draft"),
        (["mark-read", "--account", "zzzz", "--mail-id", "1"], "mark-read"),
        (["mark-unread", "--account", "zzzz", "--mail-id", "1"], "mark-unread"),
        (
            [
                "move-mail",
                "--account",
                "zzzz",
                "--mail-id",
                "1",
                "--target-mailbox",
                "1",
            ],
            "move-mail",
        ),
        (["delete-mail", "--account", "zzzz", "--mail-id", "1"], "delete-mail"),
    ],
)
def test_unknown_account_is_a_structured_error_for_every_entry_point(
    monkeypatch, argv: list[str], command: str
) -> None:
    """All account-taking commands share the account_not_found contract."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

        def get_wmsvr_bootstrap(self, account: str | None = None):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(app, ["--format", "json", *argv])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == command
    assert payload["error"]["code"] == "account_not_found"
    assert payload["error"]["details"]["account"] == "zzzz"


def test_smtp_send_reports_a_missing_account_from_the_store_lookup(monkeypatch) -> None:
    """The second local lookup in smtp-send also uses the structured contract."""

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            class _Capability:
                supports_smtp_send = True

            return _Capability()

    def _paths_and_missing_store():
        paths, _ = _fake_paths_and_store()

        class _MissingAccountStore:
            def get_account(self, identifier: str) -> Account:
                raise LocalLookupError("account_not_found", f"Account not found: {identifier}")

        return paths, _MissingAccountStore()

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)
    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _paths_and_missing_store)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "smtp-send",
            "--from",
            "zzzz",
            "--to",
            "nobody@example.invalid",
            "--subject",
            "r122",
            "--body",
            "x",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["command"] == "smtp-send"
    assert payload["error"]["code"] == "account_not_found"
    assert payload["error"]["details"]["account"] == "zzzz"


def test_send_mail_markdown_body_over_wmsvr_private(monkeypatch) -> None:
    """`send-mail --markdown-body` renders Markdown + MathML cleanly on Wmsvr-private."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(
                account,
                smtp=True,
                private_send=True,
                smtp_settings_source="guess_smtp_settings",
            )

        def send_mail_private(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "compose_id": "compose-md-1",
                "code": "S_OK",
                "sent_id": "721:<SentMd>",
                "sent_folder_fid": 3,
                "sent_subject": "Markdown test",
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "Markdown test",
            "--markdown-body",
            "# Hello\n\nFormula $E=mc^2$",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "wmsvr-private"
    assert data["content_mode"] == "markdown"
    assert data["latex_mode"] == "mathml"
    assert len(calls) == 1
    assert "Hello" in calls[0]["body"]
    assert "<h1" in calls[0]["html_body"]
    assert "mathml-formula" in calls[0]["html_body"]
    assert "cid:" not in calls[0]["html_body"]


def test_send_mail_markdown_file_over_smtp(monkeypatch, tmp_path: Path) -> None:
    """`send-mail --markdown-file` renders Markdown and passes html_base_dir on SMTP."""
    md_file = tmp_path / "note.md"
    md_file.write_text("# Report\n\n**All green**", encoding="utf-8")
    sent: list[dict] = []

    class _FakeAccess:
        def send_email(self, **kwargs) -> None:
            sent.append(kwargs)

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=True, private_send=False)

        def open_account(self, account: str) -> _FakeAccess:
            return _FakeAccess()

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "send-mail",
            "--account",
            "user@example.com",
            "--to",
            "dest@example.com",
            "--subject",
            "File MD",
            "--markdown-file",
            str(md_file),
            "--latex-mode",
            "raw",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["transport"] == "smtp"
    assert data["content_mode"] == "markdown"
    assert data["latex_mode"] == "raw"
    assert len(sent) == 1
    assert "<h1" in sent[0]["html_body"]
    assert "<strong>All green</strong>" in sent[0]["html_body"]
    assert sent[0]["html_base_dir"] == tmp_path.resolve()


def test_save_draft_markdown_body(monkeypatch) -> None:
    """`save-draft --markdown-body` renders Markdown + MathML into the saved draft."""
    calls: list[dict] = []

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True, private_drafts=True)

        def save_mail_draft(self, account: str, **kwargs) -> dict:
            calls.append({"account": account, **kwargs})
            return {
                "transport": "wmsvr-private",
                "method": "mbox:compose",
                "mode": "create",
                "recreated": False,
                "compose_id": "compose-md-draft",
                "code": "S_OK",
                "draft_id": "821:<DraftMd>",
                "draft_folder_fid": 2,
                "draft_subject": "MD Draft",
                "draft_size": 900,
                "read_back_code": "S_OK",
                "readback_fallback": False,
                "state_change_verified": True,
            }

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "save-draft",
            "--account",
            "user@163.com",
            "--subject",
            "MD Draft",
            "--markdown-body",
            "## Draft\n\nMath $a+b=c$",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["status"] == "saved"
    assert data["content_mode"] == "markdown"
    assert data["latex_mode"] == "mathml"
    assert "<h2" in calls[0]["html_body"]
    assert "mathml-formula" in calls[0]["html_body"]


@pytest.mark.parametrize(
    ("argv", "expected_command"),
    [
        (
            ["--format", "json", "send-mail", "--account", "7", "--to", "a@b.com", "--transport", "bogus"],
            "send-mail",
        ),
        (
            ["--format=json", "send-mail", "--account", "7", "--to", "a@b.com", "--transport", "bogus"],
            "send-mail",
        ),
        (
            ["--format", "json", "send-mail", "--account", "7", "--to", "a@b.com", "--latex-mode", "invalid"],
            "send-mail",
        ),
        (
            ["--format", "json", "save-draft", "--account", "7", "--latex-mode", "invalid"],
            "save-draft",
        ),
        (
            [
                "--format",
                "json",
                "send-mail",
                "--account",
                "7",
                "--to",
                "a@b.com",
                "--markdown-body",
                "hi",
                "--markdown-file",
                "note.md",
            ],
            "send-mail",
        ),
        (["--format", "json", "send-mail", "--account", "7"], "send-mail"),
        (["--format", "json", "mailboxes"], "mailboxes"),
        (["--format", "json", "send-draft", "--account", "7"], "send-draft"),
        (["--format", "json", "list", "--account", "7", "--limit", "not-an-int"], "list"),
        (["--format", "json", "send-mail", "--account", "7", "--no-such-option"], "send-mail"),
        (["--format", "json", "no-such-subcommand"], "cli"),
    ],
)
def test_json_parameter_validation_errors(argv: list[str], expected_command: str) -> None:
    """Parameter validation errors under `--format json` emit the structured JSON envelope."""
    result = runner.invoke(app, argv)

    assert result.exit_code == 2
    assert "Traceback" not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == expected_command
    assert payload["error"]["code"] == "invalid_argument"
    assert isinstance(payload["error"]["message"], str) and payload["error"]["message"]
    assert isinstance(payload["error"]["details"], dict)


def test_text_mode_parameter_validation_preserves_plain_cli_output() -> None:
    """Without `--format json`, CLI parameter errors keep normal Click/Typer text output."""
    result = runner.invoke(
        app,
        ["send-mail", "--account", "7", "--to", "a@b.com", "--transport", "bogus"],
    )

    assert result.exit_code == 2
    assert not result.stdout.lstrip().startswith("{")


def test_smtp_send_unsupported_recommends_wmsvr_private_not_stale_message(monkeypatch) -> None:
    """When SMTP send is unsupported on a Wmsvr account, suggestions recommend `send-mail --transport wmsvr-private`."""
    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=False, private_send=True)

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "smtp-send",
            "--from",
            "user@163.com",
            "--to",
            "dest@example.com",
            "--subject",
            "Hi",
            "--body",
            "Body",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    suggestions = payload["error"]["details"]["suggestions"]
    assert any("send-mail" in item and "--transport wmsvr-private" in item for item in suggestions)
    assert all("not a supported CLI workflow" not in item for item in suggestions)


@pytest.mark.parametrize(
    "argv",
    [
        ["--json", "accounts"],
        ["accounts", "--json"],
        ["accounts", "--format", "json"],
        ["accounts", "--format=json"],
    ],
)
def test_json_and_trailing_format_work_before_or_after_subcommand(monkeypatch, argv: list[str]) -> None:
    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)

    result = runner.invoke(app, argv)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "accounts"
    assert payload["data"][0]["email"] == "tester@example.com"


@pytest.mark.parametrize(
    "argv",
    [
        ["list", "--account", "1", "--format", "json"],
        ["list", "--account", "1", "--format=json"],
        ["list", "--account", "1", "--json"],
        ["--json", "list", "--account", "1"],
    ],
)
def test_list_accepts_trailing_json_and_format_flags(monkeypatch, argv: list[str]) -> None:
    class _FakeAccountStore:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def list_mail(self, **kwargs):
            return []

    monkeypatch.setattr("mailmaster.cli.commands._paths_and_store", _fake_paths_and_store)
    monkeypatch.setattr("mailmaster.cli.commands.AccountStore", _FakeAccountStore)

    result = runner.invoke(app, argv)

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "list"
    assert payload["data"]["records"] == []


def test_trailing_format_bogus_still_raises_bad_parameter() -> None:
    text_res = runner.invoke(app, ["list", "--account", "1", "--format", "bogus"])
    assert text_res.exit_code == 2
    assert "text, json" in text_res.output

    json_res = runner.invoke(app, ["list", "--account", "1", "--json", "--format", "bogus"])
    assert json_res.exit_code == 2
    payload = json.loads(json_res.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_argument"
    assert payload["error"]["details"]["suggestions"]


@pytest.mark.parametrize(
    ("argv", "expected_command"),
    [
        (["send-mail", "--account", "1", "--to", "a@b.com", "--transport", "bad", "--json"], "send-mail"),
        (
            ["send-mail", "--account", "1", "--to", "a@b.com", "--transport", "bad", "--format", "json"],
            "send-mail",
        ),
        (
            ["send-mail", "--account", "1", "--to", "a@b.com", "--transport", "bad", "--format=json"],
            "send-mail",
        ),
        (["no-such-command", "--json"], "cli"),
    ],
)
def test_trailing_json_parameter_errors_emit_structured_json_with_suggestions(
    argv: list[str],
    expected_command: str,
) -> None:
    result = runner.invoke(app, argv)

    assert result.exit_code == 2
    assert "Traceback" not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == expected_command
    assert payload["error"]["code"] == "invalid_argument"
    suggestions = payload["error"]["details"]["suggestions"]
    assert any("--help" in item for item in suggestions)
    assert any("activate-skill" in item for item in suggestions)


def test_option_value_matching_json_flag_is_not_hoisted(monkeypatch) -> None:
    sent: list[dict] = []

    class _FakeAccess:
        def send_email(self, **kwargs) -> None:
            sent.append(kwargs)

    class _FakeMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_capabilities(self, account: str):
            return _send_capabilities(account, smtp=True, private_send=False)

        def open_account(self, account: str) -> _FakeAccess:
            return _FakeAccess()

    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    text_res = runner.invoke(
        app,
        [
            "send-mail",
            "--account",
            "user@example.com",
            "--to",
            "dest@example.com",
            "--subject",
            "--json",
            "--body",
            "hello",
        ],
    )
    assert text_res.exit_code == 0
    assert not text_res.stdout.lstrip().startswith("{")
    assert sent[-1]["subject"] == "--json"

    json_res = runner.invoke(
        app,
        [
            "send-mail",
            "--account",
            "user@example.com",
            "--to",
            "dest@example.com",
            "--subject",
            "--json",
            "--body",
            "hello",
            "--json",
        ],
    )
    assert json_res.exit_code == 0
    payload = json.loads(json_res.stdout)
    assert payload["ok"] is True
    assert payload["data"]["subject"] == "--json"


def test_root_help_displays_organized_panels_and_agent_tip() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for expected in (
        "activate-skill",
        "--json",
        "Setup & Skill",
        "Read & Search",
        "Send & Drafts",
        "Mailbox Actions",
        "Protocol Diagnostics (Advanced)",
    ):
        assert expected in result.stdout


@pytest.mark.parametrize(
    "command_name",
    [
        "capabilities",
        "list",
        "read",
        "search",
        "fetch-mail",
        "send-mail",
        "save-draft",
        "send-draft",
        "move-mail",
        "delete-mail",
        "wmsvr-login-probe",
    ],
)
def test_command_help_uses_plain_language_without_re_round_jargon(command_name: str) -> None:
    result = runner.invoke(app, [command_name, "--help"])

    assert result.exit_code == 0
    assert "round " not in result.stdout.lower()
    if command_name != "wmsvr-login-probe":
        assert "Examples:" in result.stdout
