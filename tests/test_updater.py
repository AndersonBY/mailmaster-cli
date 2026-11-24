from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from mailmaster.cli import app
from mailmaster.updater import (
    DEFAULT_GITHUB_LATEST_RELEASE_URL,
    UpdateCheckResult,
    UpdateError,
    _finalize_windows_shims,
    _stage_windows_shims,
    build_install_command,
    check_for_update,
    compare_versions,
    detect_install_method,
    fetch_latest_release,
    is_newer_version,
    perform_update,
    select_wheel_asset,
)


runner = CliRunner()


class _FakeResponse:
    def __init__(self, payload: Any, *, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", DEFAULT_GITHUB_LATEST_RELEASE_URL)
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("HTTP error", request=request, response=response)

    def json(self) -> Any:
        return self._payload


def _sample_release_payload(tag: str = "v0.2.0", *, with_wheel: bool = True) -> dict[str, Any]:
    version = tag.lstrip("v")
    assets = (
        [
            {
                "name": f"mailmaster-{version}.tar.gz",
                "browser_download_url": f"https://github.com/AndersonBY/mailmaster-cli/releases/download/{tag}/mailmaster-{version}.tar.gz",
            },
            {
                "name": f"mailmaster-{version}-py3-none-any.whl",
                "browser_download_url": f"https://github.com/AndersonBY/mailmaster-cli/releases/download/{tag}/mailmaster-{version}-py3-none-any.whl",
            },
        ]
        if with_wheel
        else []
    )
    return {
        "tag_name": tag,
        "html_url": f"https://github.com/AndersonBY/mailmaster-cli/releases/tag/{tag}",
        "published_at": "2026-11-24T10:00:00Z",
        "body": "Release notes for testing.",
        "assets": assets,
    }


def test_version_comparison_semantics() -> None:
    assert compare_versions("0.1.0", "v0.1.0") == 0
    assert is_newer_version("0.1.0", "0.1.1") is True
    assert is_newer_version("0.1.1", "0.1.1") is False
    assert is_newer_version("0.2.0", "0.1.9") is False
    assert is_newer_version("0.2.0", "0.10.0") is True
    assert is_newer_version("0.1.1rc1", "0.1.1") is True
    assert is_newer_version("0.1.1", "0.1.1rc1") is False


def test_select_wheel_asset_prefers_mailmaster_wheel_and_falls_back_to_git() -> None:
    url, name = select_wheel_asset(_sample_release_payload("v0.2.0")["assets"], "v0.2.0")
    assert name == "mailmaster-0.2.0-py3-none-any.whl"
    assert url.endswith("/mailmaster-0.2.0-py3-none-any.whl")

    fallback_url, fallback_name = select_wheel_asset([], "v0.2.0")
    assert fallback_name is None
    assert fallback_url == "git+https://github.com/AndersonBY/mailmaster-cli.git@v0.2.0"


def test_fetch_latest_release_extracts_metadata(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_get(url: str, **kwargs: Any) -> _FakeResponse:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return _FakeResponse(_sample_release_payload("v0.2.0"))

    monkeypatch.setattr("mailmaster.updater.httpx.get", _fake_get)

    release = fetch_latest_release(current_version="0.1.1")
    assert captured["url"] == DEFAULT_GITHUB_LATEST_RELEASE_URL
    assert captured["kwargs"]["headers"]["Accept"] == "application/vnd.github+json"
    assert captured["kwargs"]["headers"]["User-Agent"] == "mailmaster-cli/0.1.1"
    assert release.tag_name == "v0.2.0"
    assert release.version == "0.2.0"
    assert release.asset_name == "mailmaster-0.2.0-py3-none-any.whl"
    assert release.asset_url.endswith("mailmaster-0.2.0-py3-none-any.whl")


def test_fetch_latest_release_http_error_raises_structured_update_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "mailmaster.updater.httpx.get",
        lambda url, **kwargs: _FakeResponse({"message": "rate limit"}, status_code=403),
    )

    with pytest.raises(UpdateError) as exc_info:
        fetch_latest_release(current_version="0.1.1")

    assert exc_info.value.code == "update_check_failed"
    assert exc_info.value.details["status_code"] == 403


def test_detect_install_method_and_build_command(tmp_path: Path) -> None:
    (tmp_path / "uv-receipt.toml").write_text("[tool]\n", encoding="utf-8")
    assert detect_install_method(sys_prefix=tmp_path, uv_executable="uv.exe", has_pip=False) == "uv-tool"

    plain_prefix = tmp_path / "venv"
    plain_prefix.mkdir()
    assert detect_install_method(sys_prefix=plain_prefix, uv_executable="uv.exe", has_pip=True) == "pip"
    assert detect_install_method(sys_prefix=plain_prefix, uv_executable="uv.exe", has_pip=False) == "uv-pip"
    assert detect_install_method(sys_prefix=plain_prefix, uv_executable="", has_pip=False) == "unknown"

    uv_cmd = build_install_command(
        "https://example.com/mailmaster-0.2.0-py3-none-any.whl",
        install_method="uv-tool",
        python_executable="C:/env/python.exe",
        uv_executable="uv.exe",
    )
    assert uv_cmd == [
        "uv.exe",
        "pip",
        "install",
        "--python",
        "C:/env/python.exe",
        "--upgrade",
        "--reinstall-package",
        "mailmaster",
        "https://example.com/mailmaster-0.2.0-py3-none-any.whl",
    ]

    pip_upgrade = build_install_command(
        "https://example.com/mailmaster-0.2.0-py3-none-any.whl",
        install_method="pip",
        same_or_downgrade=False,
        python_executable="C:/env/python.exe",
    )
    assert pip_upgrade == [
        "C:/env/python.exe",
        "-m",
        "pip",
        "install",
        "--upgrade",
        "https://example.com/mailmaster-0.2.0-py3-none-any.whl",
    ]

    pip_force_same = build_install_command(
        "https://example.com/mailmaster-0.1.1-py3-none-any.whl",
        install_method="pip",
        same_or_downgrade=True,
        python_executable="C:/env/python.exe",
    )
    assert "--force-reinstall" in pip_force_same
    assert "--no-deps" in pip_force_same


def test_windows_shim_staging_and_rollback(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows-only shim staging test")
    scripts_dir = tmp_path / "Scripts"
    scripts_dir.mkdir()
    exe_path = scripts_dir / "mailmaster.exe"
    py_path = scripts_dir / "python.exe"
    exe_path.write_bytes(b"old-exe")
    py_path.write_bytes(b"py")

    staged, locked = _stage_windows_shims(sys_prefix=tmp_path, python_executable=str(py_path))
    assert len(staged) == 1
    assert locked == []
    assert not exe_path.exists()
    assert (scripts_dir / "mailmaster.exe.old").read_bytes() == b"old-exe"

    # Roll back on failed install
    _finalize_windows_shims(staged, succeeded=False)
    assert exe_path.read_bytes() == b"old-exe"
    assert not (scripts_dir / "mailmaster.exe.old").exists()

    # Clean up .old on successful install when new exe was written
    staged, locked = _stage_windows_shims(sys_prefix=tmp_path, python_executable=str(py_path))
    assert locked == []
    exe_path.write_bytes(b"new-exe")
    _finalize_windows_shims(staged, succeeded=True)
    assert exe_path.read_bytes() == b"new-exe"
    assert not (scripts_dir / "mailmaster.exe.old").exists()


def test_cli_update_check_json_and_text(monkeypatch) -> None:
    monkeypatch.setattr(
        "mailmaster.updater.httpx.get",
        lambda url, **kwargs: _FakeResponse(_sample_release_payload("v9.9.9")),
    )
    monkeypatch.setattr("mailmaster.updater.detect_editable_install", lambda: (False, None))
    monkeypatch.setattr("mailmaster.updater.detect_install_method", lambda: "uv-tool")

    json_res = runner.invoke(app, ["update", "--check", "--json"])
    assert json_res.exit_code == 0
    payload = json.loads(json_res.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "update"
    data = payload["data"]
    assert data["latest_version"] == "9.9.9"
    assert data["tag_name"] == "v9.9.9"
    assert data["update_available"] is True
    assert data["asset_url"].endswith("mailmaster-9.9.9-py3-none-any.whl")
    assert data["release_url"].endswith("/releases/tag/v9.9.9")

    text_res = runner.invoke(app, ["update", "--check"])
    assert text_res.exit_code == 0
    assert "Update available:" in text_res.stdout
    assert "v9.9.9" in text_res.stdout


def test_cli_update_up_to_date_skips_installer(monkeypatch) -> None:
    from mailmaster import __version__

    invoked: list[list[str]] = []
    monkeypatch.setattr(
        "mailmaster.updater.httpx.get",
        lambda url, **kwargs: _FakeResponse(_sample_release_payload(f"v{__version__}")),
    )
    monkeypatch.setattr("mailmaster.updater.detect_editable_install", lambda: (False, None))
    monkeypatch.setattr("mailmaster.updater.detect_install_method", lambda: "uv-tool")
    monkeypatch.setattr("mailmaster.updater.subprocess.run", lambda cmd, **kw: invoked.append(cmd))

    res = runner.invoke(app, ["update", "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert payload["ok"] is True
    assert payload["data"]["status"] == "up_to_date"
    assert payload["data"]["updated"] is False
    assert invoked == []

    text_res = runner.invoke(app, ["update"])
    assert text_res.exit_code == 0
    assert f"Already up to date (v{__version__})." in text_res.stdout


def test_cli_update_editable_guard_and_force_override(monkeypatch) -> None:
    invoked: list[list[str]] = []
    monkeypatch.setattr(
        "mailmaster.updater.httpx.get",
        lambda url, **kwargs: _FakeResponse(_sample_release_payload("v9.9.9")),
    )
    monkeypatch.setattr("mailmaster.updater.detect_editable_install", lambda: (True, "e:/Projects/mailmaster-cli"))
    monkeypatch.setattr("mailmaster.updater.detect_install_method", lambda: "uv-tool")
    monkeypatch.setattr("mailmaster.updater._stage_windows_shims", lambda: ([], []))
    monkeypatch.setattr("mailmaster.updater.cleanup_stale_windows_shims", lambda: [])

    def _fake_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
        invoked.append(cmd)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("mailmaster.updater.subprocess.run", _fake_run)

    # Without --force: warn & skip
    skip_res = runner.invoke(app, ["update", "--json"])
    assert skip_res.exit_code == 0
    skip_payload = json.loads(skip_res.stdout)
    assert skip_payload["data"]["status"] == "skipped_editable"
    assert skip_payload["data"]["updated"] is False
    assert invoked == []

    # With --force: proceeds to install wheel
    force_res = runner.invoke(app, ["update", "--force", "--yes", "--json"])
    assert force_res.exit_code == 0
    force_payload = json.loads(force_res.stdout)
    assert force_payload["data"]["status"] == "updated"
    assert force_payload["data"]["updated"] is True
    assert len(invoked) == 1
    assert invoked[0][-1].endswith("mailmaster-9.9.9-py3-none-any.whl")


def test_cli_update_error_envelopes(monkeypatch) -> None:
    monkeypatch.setattr(
        "mailmaster.updater.httpx.get",
        lambda url, **kwargs: (_ for _ in ()).throw(httpx.ConnectError("offline")),
    )

    err_res = runner.invoke(app, ["update", "--check", "--json"])
    assert err_res.exit_code == 2
    payload = json.loads(err_res.stdout)
    assert payload["ok"] is False
    assert payload["command"] == "update"
    assert payload["error"]["code"] == "update_check_failed"


def test_perform_update_reports_installer_failure(monkeypatch) -> None:
    check = UpdateCheckResult(
        current_version="0.1.0",
        latest_version="0.1.1",
        tag_name="v0.1.1",
        update_available=True,
        release_url="https://github.com/AndersonBY/mailmaster-cli/releases/tag/v0.1.1",
        asset_url="https://github.com/AndersonBY/mailmaster-cli/releases/download/v0.1.1/mailmaster-0.1.1-py3-none-any.whl",
        asset_name="mailmaster-0.1.1-py3-none-any.whl",
        published_at="2026-11-24T10:00:00Z",
        release_notes="",
        editable_install=False,
        editable_path=None,
        install_method="uv-tool",
    )
    monkeypatch.setattr("mailmaster.updater._stage_windows_shims", lambda: ([], []))
    monkeypatch.setattr("mailmaster.updater.cleanup_stale_windows_shims", lambda: [])
    monkeypatch.setattr(
        "mailmaster.updater.subprocess.run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="install boom"),
    )

    with pytest.raises(UpdateError) as exc_info:
        perform_update(check_result=check)

    assert exc_info.value.code == "update_install_failed"
    assert "install boom" in exc_info.value.details["output"]


def test_check_for_update_passes_explicit_current_version(monkeypatch) -> None:
    monkeypatch.setattr(
        "mailmaster.updater.httpx.get",
        lambda url, **kwargs: _FakeResponse(_sample_release_payload("v0.1.2")),
    )
    monkeypatch.setattr("mailmaster.updater.detect_editable_install", lambda: (False, None))
    monkeypatch.setattr("mailmaster.updater.detect_install_method", lambda: "pip")

    result = check_for_update(current_version="0.1.1")
    assert result.current_version == "0.1.1"
    assert result.latest_version == "0.1.2"
    assert result.update_available is True
    assert result.install_method == "pip"


def test_perform_update_schedules_detached_helper_when_shim_locked(monkeypatch, tmp_path: Path) -> None:
    spawned: list[tuple[list[str], list[Path]]] = []
    locked_exe = tmp_path / "mailmaster.exe"
    check = UpdateCheckResult(
        current_version="0.1.0",
        latest_version="0.1.1",
        tag_name="v0.1.1",
        update_available=True,
        release_url="https://github.com/AndersonBY/mailmaster-cli/releases/tag/v0.1.1",
        asset_url="https://github.com/AndersonBY/mailmaster-cli/releases/download/v0.1.1/mailmaster-0.1.1-py3-none-any.whl",
        asset_name="mailmaster-0.1.1-py3-none-any.whl",
        published_at="2026-11-24T10:00:00Z",
        release_notes="",
        editable_install=False,
        editable_path=None,
        install_method="uv-tool",
    )
    monkeypatch.setattr("mailmaster.updater.cleanup_stale_windows_shims", lambda: [])
    monkeypatch.setattr("mailmaster.updater._stage_windows_shims", lambda: ([], [locked_exe]))
    monkeypatch.setattr(
        "mailmaster.updater._spawn_detached_windows_updater",
        lambda cmd, paths: spawned.append((cmd, paths)),
    )

    result = perform_update(check_result=check)
    assert result.status == "scheduled"
    assert result.updated is False
    assert len(spawned) == 1
    assert spawned[0][1] == [locked_exe]
