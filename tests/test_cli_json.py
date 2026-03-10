from pathlib import Path

from typer.testing import CliRunner

from mailmaster.cli import app
from mailmaster.models import Account, MailMasterPaths


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
