from __future__ import annotations

import json

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mailmaster.cli import app
from mailmaster.store import LocalLookupError
from mailmaster.wmsvr import (
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_PRIMARY_KEY_DIGEST16,
    DEFAULT_D1_SIBLING_KEY_DIGEST16,
    WmsvrHardcodedPublicKey,
    WmsvrLoginContext,
)


runner = CliRunner()


class _FakeMailMaster:
    def __init__(self, *args, **kwargs) -> None:
        self.paths = type("_Paths", (), {"install_root": Path(r"C:\fake\Application")})()

    def get_wmsvr_login_context(self, account: str) -> WmsvrLoginContext:
        return WmsvrLoginContext(
            account=account,
            user=account,
            password="secret-pass",
            locale="zh_CN",
            app_version="5.7.2.1006",
            appver_inner=50070021006,
            device_id="WINTESTDEVICEID",
            cloud_id="cloud-id-123",
            cloud_token="cloud-token-456",
            master_fp="fingerprint-material",
            master_sdid="1027626894865072128",
        )


def _fake_key(label: str, digest: bytes) -> WmsvrHardcodedPublicKey:
    return WmsvrHardcodedPublicKey(
        label=label,
        pem="-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n",
        digest16=digest,
        bits=1024,
        exponent=65537,
        source_path=r"C:\fake\Application\5.7.2.1006\mastercore.dll",
        source_index=1,
    )


def test_wmsvr_keys_reports_recovered_material_match(monkeypatch) -> None:
    monkeypatch.setattr(
        "mailmaster.cli.wmsvr_commands.load_wmsvr_hardcoded_public_keys",
        lambda install_root=None: {
            "primary_default": _fake_key("primary_default", DEFAULT_D1_PRIMARY_KEY_DIGEST16),
            "fallback_default": _fake_key("fallback_default", DEFAULT_D1_FALLBACK_KEY_DIGEST16),
            "sibling_default": _fake_key("sibling_default", DEFAULT_D1_SIBLING_KEY_DIGEST16),
        },
    )
    # The commands import MailMaster inside the function body, so patch the facade module.
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(app, ["--format", "json", "wmsvr-keys"])

    assert result.exit_code == 0
    assert '"command": "wmsvr-keys"' in result.stdout
    assert '"matches_recovered_material": true' in result.stdout
    assert DEFAULT_D1_PRIMARY_KEY_DIGEST16.hex() in result.stdout


def test_wmsvr_keys_flags_drifted_key_material(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)
    monkeypatch.setattr(
        "mailmaster.cli.wmsvr_commands.load_wmsvr_hardcoded_public_keys",
        lambda install_root=None: {"primary_default": _fake_key("primary_default", b"\x00" * 16)},
    )

    result = runner.invoke(app, ["--format", "json", "wmsvr-keys"])

    assert result.exit_code == 0
    assert '"matches_recovered_material": false' in result.stdout


def test_wmsvr_login_context_redacts_auth_material_by_default(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(app, ["--format", "json", "wmsvr-login-context", "--account", "tester@163.com"])

    assert result.exit_code == 0
    assert "secret-pass" not in result.stdout
    assert "cloud-token-456" not in result.stdout
    assert "fingerprint-material" not in result.stdout
    assert "<redacted:11 chars>" in result.stdout
    assert '"redacted": true' in result.stdout
    assert '"appver_inner": 50070021006' in result.stdout


def test_wmsvr_login_context_show_secrets_reveals_material(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "wmsvr-login-context", "--account", "tester@163.com", "--show-secrets"],
    )

    assert result.exit_code == 0
    assert "secret-pass" in result.stdout
    assert '"redacted": false' in result.stdout


def test_wmsvr_login_probe_dry_run_never_transmits(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    def _fail(*args, **kwargs):
        raise AssertionError("dry run must not transmit")

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fail)

    result = runner.invoke(app, ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com"])

    assert result.exit_code == 0
    assert '"transmitted": false' in result.stdout
    assert '"method": "wzpa:loginone"' in result.stdout
    assert '"session_key_len": 16' in result.stdout


def test_wmsvr_login_probe_reports_sec_fingerprint_flag(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    def _fail(*args, **kwargs):
        raise AssertionError("dry run must not transmit")

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fail)

    off = runner.invoke(app, ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com"])
    on = runner.invoke(
        app,
        ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com", "--sec-fingerprint"],
    )

    assert off.exit_code == 0 and on.exit_code == 0
    assert '"sec_fingerprint": false' in off.stdout
    assert '"sec_fingerprint": true' in on.stdout
    # The sec block adds exactly four body fields: sec, secName, secOsType, secMdc.
    off_count = int(off.stdout.split('"body_field_count": ')[1].split(",")[0])
    on_count = int(on.stdout.split('"body_field_count": ')[1].split(",")[0])
    assert on_count == off_count + 4


def test_wmsvr_login_probe_send_transmits(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    calls: dict[str, object] = {}
    from mailmaster.wmsvr import WmsvrLoginProbeResult

    def _fake_probe(context, **kwargs):
        calls.update(kwargs)
        return WmsvrLoginProbeResult(
            method=kwargs.get("method", ""),
            session_key=b"\x01" * 16,
            client_id="mailwin|TEST.0.1",
            error="",
        )

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fake_probe)

    result = runner.invoke(
        app,
        ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com", "--send", "--word2", "0x0003"],
    )

    assert result.exit_code == 0
    assert '"transmitted": true' in result.stdout
    assert calls.get("word2") == 0x0003
    assert calls.get("prefetch_get_settings") is True


def test_wmsvr_login_probe_send_reports_response_fields_without_values(monkeypatch) -> None:
    """A probe run must say *which* fields the server answered with, and not leak them."""
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    from mailmaster.wmsvr import WmsvrLoginProbeResult

    response_body = json.dumps(
        {"code": "200", "mixmailToken": "TOPSECRETTOKENVALUE", "sid": "SIDVALUE"}
    ).encode("utf-8")

    def _fake_probe(context, **kwargs):
        return WmsvrLoginProbeResult(
            method=kwargs.get("method", ""),
            session_key=b"" * 16,
            client_id="mailwin|TEST.0.1",
            response_frame=None,
            decrypted_slice0=b"",
            decrypted_slice1=response_body,
            error="",
        )

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fake_probe)

    argv = ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com", "--send"]
    redacted = runner.invoke(app, argv)

    assert redacted.exit_code == 0
    # Names, status and lengths are the acceptance evidence and are always reported.
    assert "mixmailToken" in redacted.stdout
    assert '"code": "200"' in redacted.stdout
    assert '"sid"' in redacted.stdout
    # The values are live auth material and must not appear by default.
    assert "TOPSECRETTOKENVALUE" not in redacted.stdout
    assert "SIDVALUE" not in redacted.stdout

    exposed = runner.invoke(app, [*argv, "--show-secrets"])

    assert exposed.exit_code == 0
    assert "TOPSECRETTOKENVALUE" in exposed.stdout


def test_wmsvr_login_probe_reports_response_shape_for_unparsed_bodies(monkeypatch) -> None:
    """When the body is not the expected JSON, the run must still say what it is.

    The decisive probe cannot be repeated freely, and the response container is not
    settled, so "not JSON" must not render as a blank report: the shape line has to
    distinguish an undecryptable answer from a text body that simply uses other keys.
    """
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    from mailmaster.wmsvr import WmsvrLoginProbeResult

    noise = bytes(range(32))

    def _fake_probe(context, **kwargs):
        return WmsvrLoginProbeResult(
            method=kwargs.get("method", ""),
            session_key=b" " * 16,
            client_id="mailwin|TEST.0.1",
            response_frame=None,
            decrypted_slice0=noise,
            decrypted_slice1=b"loginType=1&sid=7",
            error="",
        )

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fake_probe)

    result = runner.invoke(
        app,
        ["wmsvr-login-probe", "--account", "tester@163.com", "--send"],
    )

    assert result.exit_code == 0
    assert "slice0_shape" in result.stdout
    assert "json=False" in result.stdout
    assert "printable=0.094" in result.stdout
    # slice1 is key=value text, not JSON: the names still have to be reported.
    assert "response_field_names_seen" in result.stdout
    assert "sid" in result.stdout


def test_wmsvr_login_probe_accepts_hex_word_options(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    calls: dict[str, object] = {}
    from mailmaster.wmsvr import WmsvrLoginProbeResult

    def _fake_probe(context, **kwargs):
        calls.update(kwargs)
        return WmsvrLoginProbeResult(method=kwargs.get("method", ""), session_key=b"", client_id="", error="")

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fake_probe)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "wmsvr-login-probe",
            "--account",
            "tester@163.com",
            "--send",
            "--word2",
            "0x0084",
            "--word4",
            "0x0003",
        ],
    )

    assert result.exit_code == 0
    assert calls.get("word2") == 0x0084
    assert calls.get("word4") == 0x0003


def test_wmsvr_login_probe_rejects_bad_word(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(app, ["wmsvr-login-probe", "--account", "tester@163.com", "--word2", "not-a-number"])

    assert result.exit_code != 0


def test_wmsvr_login_probe_defaults_to_key_exchange(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    def _fail(*args, **kwargs):
        raise AssertionError("dry run must not transmit")

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fail)

    default = runner.invoke(app, ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com"])
    replay = runner.invoke(
        app,
        [
            "--format",
            "json",
            "wmsvr-login-probe",
            "--account",
            "tester@163.com",
            "--replay-wrapped-key",
        ],
    )

    assert default.exit_code == 0 and replay.exit_code == 0
    # Exchanging our own key is the default because replaying the captured blob
    # cannot work: the server would unwrap a foreign key, not this run's.
    assert '"key_exchange": true' in default.stdout
    assert '"key_exchange": false' in replay.stdout


def test_wmsvr_login_probe_send_forwards_key_exchange_choice(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    calls: dict[str, object] = {}
    from mailmaster.wmsvr import WmsvrLoginProbeResult

    def _fake_probe(context, **kwargs):
        calls.update(kwargs)
        return WmsvrLoginProbeResult(
            method=kwargs.get("method", ""),
            session_key=b"\x01" * 16,
            client_id="mailwin|TEST.0.1",
            key_exchange=False,
            error="",
        )

    monkeypatch.setattr("mailmaster.cli.wmsvr_commands.execute_wmsvr_login_probe", _fake_probe)

    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "wmsvr-login-probe",
            "--account",
            "tester@163.com",
            "--send",
            "--replay-wrapped-key",
        ],
    )

    assert result.exit_code == 0
    assert calls["key_exchange"] is False
    assert '"key_exchange": false' in result.stdout


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (["wmsvr-login-context", "--account", "zzzz"], "wmsvr-login-context"),
        (["wmsvr-refresh-session", "--account", "zzzz"], "wmsvr-refresh-session"),
        (["wmsvr-get-settings", "--account", "zzzz"], "wmsvr-get-settings"),
        (["wmsvr-runtime-key", "--account", "zzzz"], "wmsvr-runtime-key"),
        (["wmsvr-login-probe", "--account", "zzzz"], "wmsvr-login-probe"),
    ],
)
def test_wmsvr_commands_report_missing_account_as_structured_error(
    monkeypatch,
    argv: list[str],
    command: str,
) -> None:
    """Every account-taking `wmsvr-*` inspection command returns structured `account_not_found`."""

    class _MissingAccountMailMaster:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get_wmsvr_login_context(self, account: str):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

        def refresh_wmsvr_master_session(self, account: str, **kwargs):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

        def probe_wmsvr_get_settings(self, account: str, **kwargs):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

        def probe_wmsvr_runtime_public_key(self, account: str, **kwargs):
            raise LocalLookupError("account_not_found", f"Account not found: {account}")

    monkeypatch.setattr("mailmaster._facade.MailMaster", _MissingAccountMailMaster)

    result = runner.invoke(app, ["--format", "json", *argv])

    assert result.exit_code == 2
    assert "Traceback" not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == command
    assert payload["error"]["code"] == "account_not_found"
    assert payload["error"]["details"]["account"] == "zzzz"


def test_wmsvr_login_probe_json_bad_word_returns_invalid_argument(monkeypatch) -> None:
    monkeypatch.setattr("mailmaster._facade.MailMaster", _FakeMailMaster)

    result = runner.invoke(
        app,
        ["--format", "json", "wmsvr-login-probe", "--account", "tester@163.com", "--word2", "not-a-number"],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == "wmsvr-login-probe"
    assert payload["error"]["code"] == "invalid_argument"
