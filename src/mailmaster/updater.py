"""Self-update helpers backed by GitHub Releases."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

import httpx

DEFAULT_GITHUB_REPO = "AndersonBY/mailmaster-cli"
DEFAULT_GITHUB_LATEST_RELEASE_URL = f"https://api.github.com/repos/{DEFAULT_GITHUB_REPO}/releases/latest"
DEFAULT_GITHUB_REPO_URL = f"https://github.com/{DEFAULT_GITHUB_REPO}.git"
DEFAULT_TIMEOUT_SECONDS = 15.0

_VERSION_RE = re.compile(r"^[vV]?(\d+(?:\.\d+)*)(.*)$")
_PRERELEASE_RE = re.compile(r"^(?:[-.]?(?:a|alpha|b|beta|rc|dev|pre))", re.IGNORECASE)


class UpdateError(RuntimeError):
    """Structured error raised when checking for or applying a CLI update fails."""

    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


@dataclass(slots=True)
class ReleaseInfo:
    """Metadata extracted from the latest GitHub Release."""

    tag_name: str
    version: str
    release_url: str
    asset_url: str
    asset_name: str | None
    published_at: str
    release_notes: str


@dataclass(slots=True)
class UpdateCheckResult:
    """Comparison between the currently installed version and the latest release."""

    current_version: str
    latest_version: str
    tag_name: str
    update_available: bool
    release_url: str
    asset_url: str
    asset_name: str | None
    published_at: str
    release_notes: str
    editable_install: bool
    editable_path: str | None
    install_method: str


@dataclass(slots=True)
class UpdateResult:
    """Outcome of running ``mailmaster update``."""

    status: str
    current_version: str
    latest_version: str
    tag_name: str
    update_available: bool
    updated: bool
    release_url: str
    asset_url: str
    published_at: str
    install_method: str
    editable_install: bool
    editable_path: str | None
    command: list[str]
    message: str


def normalize_version_string(raw: str) -> str:
    """Strip whitespace and a leading ``v``/``V`` prefix from a version or tag."""
    text = raw.strip()
    if text.startswith(("v", "V")):
        text = text[1:]
    return text.strip()


def parse_version(raw: str) -> tuple[tuple[int, ...], int, str]:
    """Parse a release version into a comparable tuple.

    Final releases sort after pre-releases of the same numeric tuple
    (for example ``0.1.1`` > ``0.1.1rc1``).
    """
    normalized = normalize_version_string(raw)
    match = _VERSION_RE.match(normalized)
    if not match:
        return ((), 0, normalized)
    numbers = tuple(int(part) for part in match.group(1).split("."))
    suffix = match.group(2).strip()
    if not suffix:
        return (numbers, 1, "")
    if _PRERELEASE_RE.match(suffix):
        return (numbers, 0, suffix.lower())
    return (numbers, 2, suffix.lower())


def compare_versions(left: str, right: str) -> int:
    """Compare two version strings: return -1 if left < right, 0 if equal, 1 if left > right."""
    left_nums, left_stage, left_suffix = parse_version(left)
    right_nums, right_stage, right_suffix = parse_version(right)
    max_len = max(len(left_nums), len(right_nums))
    left_padded = left_nums + (0,) * (max_len - len(left_nums))
    right_padded = right_nums + (0,) * (max_len - len(right_nums))
    left_key = (left_padded, left_stage, left_suffix)
    right_key = (right_padded, right_stage, right_suffix)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def is_newer_version(current_version: str, latest_version: str) -> bool:
    """Return True when ``latest_version`` is strictly newer than ``current_version``."""
    return compare_versions(current_version, latest_version) < 0


def get_current_version() -> str:
    """Return the running ``mailmaster`` package version."""
    from . import __version__

    return __version__


def select_wheel_asset(assets: Any, tag_name: str, *, repo_url: str = DEFAULT_GITHUB_REPO_URL) -> tuple[str, str | None]:
    """Pick the best `.whl` download URL from a GitHub Release assets list."""
    fallback_url = f"git+{repo_url}@{tag_name}"
    if not isinstance(assets, list):
        return fallback_url, None

    preferred: tuple[str, str] | None = None
    fallback_wheel: tuple[str, str] | None = None
    for item in assets:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        download_url = str(item.get("browser_download_url") or "").strip()
        if not name.lower().endswith(".whl") or not download_url:
            continue
        if name.lower().startswith("mailmaster-"):
            preferred = (download_url, name)
            break
        if fallback_wheel is None:
            fallback_wheel = (download_url, name)

    if preferred is not None:
        return preferred
    if fallback_wheel is not None:
        return fallback_wheel
    return fallback_url, None


def fetch_latest_release(
    *,
    api_url: str = DEFAULT_GITHUB_LATEST_RELEASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    current_version: str | None = None,
    repo_url: str = DEFAULT_GITHUB_REPO_URL,
) -> ReleaseInfo:
    """Query GitHub Releases for the latest published release."""
    version_tag = current_version or get_current_version()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"mailmaster-cli/{version_tag}",
    }
    try:
        response = httpx.get(
            api_url,
            headers=headers,
            timeout=timeout,
            follow_redirects=True,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        raise UpdateError(
            "update_check_failed",
            f"GitHub Releases API returned HTTP {status_code} while checking for updates.",
            details={
                "api_url": api_url,
                "status_code": status_code,
                "suggestions": [
                    "Check your internet connection or GitHub API rate limits and retry.",
                    f"Inspect releases manually at https://github.com/{DEFAULT_GITHUB_REPO}/releases.",
                ],
            },
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise UpdateError(
            "update_check_failed",
            f"Failed to query GitHub Releases for the latest version: {exc}",
            details={
                "api_url": api_url,
                "exception": type(exc).__name__,
                "suggestions": [
                    "Check your network connection or proxy settings and try again.",
                    f"Inspect releases manually at https://github.com/{DEFAULT_GITHUB_REPO}/releases.",
                ],
            },
        ) from exc

    if not isinstance(payload, dict):
        raise UpdateError(
            "update_check_failed",
            "GitHub Releases API returned an unexpected payload.",
            details={"api_url": api_url},
        )

    tag_name = str(payload.get("tag_name") or "").strip()
    if not tag_name:
        raise UpdateError(
            "update_check_failed",
            "GitHub Releases API response did not include a release tag_name.",
            details={"api_url": api_url},
        )

    latest_version = normalize_version_string(tag_name)
    release_url = str(payload.get("html_url") or f"https://github.com/{DEFAULT_GITHUB_REPO}/releases/tag/{tag_name}")
    published_at = str(payload.get("published_at") or "")
    release_notes = str(payload.get("body") or "").strip()
    asset_url, asset_name = select_wheel_asset(payload.get("assets"), tag_name, repo_url=repo_url)

    return ReleaseInfo(
        tag_name=tag_name,
        version=latest_version,
        release_url=release_url,
        asset_url=asset_url,
        asset_name=asset_name,
        published_at=published_at,
        release_notes=release_notes,
    )


def detect_editable_install() -> tuple[bool, str | None]:
    """Return ``(is_editable, source_path)`` when running from an editable or git checkout."""
    try:
        dist = importlib.metadata.distribution("mailmaster")
        direct_url_raw = dist.read_text("direct_url.json")
        if direct_url_raw:
            direct_url = json.loads(direct_url_raw)
            dir_info = direct_url.get("dir_info") if isinstance(direct_url, dict) else None
            if isinstance(dir_info, dict) and dir_info.get("editable") is True:
                return True, str(direct_url.get("url") or "") or None
    except (importlib.metadata.PackageNotFoundError, ValueError, OSError):
        pass

    module_file = Path(__file__).resolve()
    parts_lower = {part.lower() for part in module_file.parts}
    if "site-packages" not in parts_lower and "dist-packages" not in parts_lower:
        for parent in module_file.parents:
            if (parent / "pyproject.toml").is_file() and (parent / ".git").exists():
                return True, str(parent)
    return False, None


def detect_install_method(
    *,
    sys_prefix: str | Path | None = None,
    uv_executable: str | None = None,
    has_pip: bool | None = None,
) -> str:
    """Identify the best installer backend for the active Python environment."""
    prefix = Path(sys_prefix if sys_prefix is not None else sys.prefix)
    uv_bin = uv_executable if uv_executable is not None else shutil.which("uv")
    pip_available = has_pip if has_pip is not None else (importlib.util.find_spec("pip") is not None)

    if (prefix / "uv-receipt.toml").is_file() and uv_bin:
        return "uv-tool"
    if pip_available:
        return "pip"
    if uv_bin:
        return "uv-pip"
    return "unknown"


def build_install_command(
    asset_url: str,
    *,
    install_method: str,
    same_or_downgrade: bool = False,
    python_executable: str | None = None,
    uv_executable: str | None = None,
) -> list[str]:
    """Construct the package-installer command for updating ``mailmaster``."""
    py_exe = python_executable or sys.executable
    if install_method in {"uv-tool", "uv-pip"}:
        uv_bin = uv_executable or shutil.which("uv") or "uv"
        return [
            uv_bin,
            "pip",
            "install",
            "--python",
            py_exe,
            "--upgrade",
            "--reinstall-package",
            "mailmaster",
            asset_url,
        ]
    if install_method == "pip":
        cmd = [py_exe, "-m", "pip", "install", "--upgrade"]
        if same_or_downgrade:
            cmd.extend(["--force-reinstall", "--no-deps"])
        cmd.append(asset_url)
        return cmd
    raise UpdateError(
        "update_installer_unavailable",
        "No supported package installer (uv or pip) was found for this Python environment.",
        details={
            "python_executable": py_exe,
            "asset_url": asset_url,
            "suggestions": [
                f"Upgrade manually with uv: uv tool install --upgrade --force {asset_url}",
                f"Or upgrade manually with pip: python -m pip install --upgrade {asset_url}",
            ],
        },
    )


def _candidate_windows_shims(
    *,
    sys_prefix: str | Path | None = None,
    python_executable: str | None = None,
) -> list[Path]:
    """Return candidate ``mailmaster.exe`` shim paths in the active environment."""
    prefix = Path(sys_prefix if sys_prefix is not None else sys.prefix)
    py_dir = Path(python_executable or sys.executable).resolve().parent
    candidates = [
        prefix / "Scripts" / "mailmaster.exe",
        py_dir / "mailmaster.exe",
    ]
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def cleanup_stale_windows_shims(
    *,
    sys_prefix: str | Path | None = None,
    python_executable: str | None = None,
) -> list[Path]:
    """Best-effort removal of leftover ``mailmaster.exe.old`` files from prior updates."""
    if os.name != "nt":
        return []
    removed: list[Path] = []
    for exe_path in _candidate_windows_shims(sys_prefix=sys_prefix, python_executable=python_executable):
        old_path = exe_path.with_name(f"{exe_path.name}.old")
        if old_path.exists():
            try:
                old_path.unlink()
                removed.append(old_path)
            except OSError:
                pass
    return removed


_DETACHED_UPDATER_SCRIPT = """
import json, os, subprocess, sys, time
cmd = json.loads(sys.argv[1])
locked_paths = json.loads(sys.argv[2])
deadline = time.monotonic() + 30.0
while time.monotonic() < deadline:
    still_locked = False
    for raw in locked_paths:
        if os.path.exists(raw):
            probe = raw + ".update-probe"
            try:
                if os.path.exists(probe):
                    os.unlink(probe)
                os.rename(raw, probe)
                os.rename(probe, raw)
            except OSError:
                still_locked = True
                break
    if not still_locked:
        break
    time.sleep(0.2)
subprocess.run(cmd, check=False)
""".strip()


def _stage_windows_shims(
    *,
    sys_prefix: str | Path | None = None,
    python_executable: str | None = None,
) -> tuple[list[tuple[Path, Path]], list[Path]]:
    """Rename Windows ``mailmaster.exe`` shims to ``.old`` before overwrite.

    Returns ``(staged_pairs, locked_paths)``. If the active Windows launcher
    holds a non-shareable lock (`WinError 32`), its path is reported in
    ``locked_paths`` so the caller can hand off to a short detached updater
    that runs immediately after this process exits.
    """
    if os.name != "nt":
        return [], []
    staged: list[tuple[Path, Path]] = []
    locked: list[Path] = []
    for exe_path in _candidate_windows_shims(sys_prefix=sys_prefix, python_executable=python_executable):
        if not exe_path.is_file():
            continue
        old_path = exe_path.with_name(f"{exe_path.name}.old")
        if old_path.exists():
            try:
                old_path.unlink()
            except OSError:
                locked.append(exe_path)
                continue
        try:
            exe_path.rename(old_path)
            staged.append((exe_path, old_path))
        except OSError:
            locked.append(exe_path)
    return staged, locked


def _spawn_detached_windows_updater(
    cmd: list[str],
    locked_paths: list[Path],
    *,
    python_executable: str | None = None,
) -> None:
    """Spawn a detached Python helper that waits for locked shims to close and runs ``cmd``."""
    py_exe = python_executable or sys.executable
    flags = (
        getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    subprocess.Popen(
        [
            py_exe,
            "-c",
            _DETACHED_UPDATER_SCRIPT,
            json.dumps(cmd),
            json.dumps([str(path) for path in locked_paths]),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
    )


def _finalize_windows_shims(staged: list[tuple[Path, Path]], *, succeeded: bool) -> None:
    """Clean up or roll back renamed Windows ``mailmaster.exe.old`` shims."""
    for exe_path, old_path in staged:
        if succeeded:
            if not exe_path.exists() and old_path.exists():
                try:
                    old_path.rename(exe_path)
                except OSError:
                    pass
                continue
            if old_path.exists():
                try:
                    old_path.unlink()
                except OSError:
                    # Still held by the running process; cleaned up on the next run.
                    pass
        else:
            if not exe_path.exists() and old_path.exists():
                try:
                    old_path.rename(exe_path)
                except OSError:
                    pass


def check_for_update(
    *,
    api_url: str = DEFAULT_GITHUB_LATEST_RELEASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    current_version: str | None = None,
) -> UpdateCheckResult:
    """Check GitHub Releases and compare against the currently installed version."""
    current = current_version or get_current_version()
    release = fetch_latest_release(api_url=api_url, timeout=timeout, current_version=current)
    editable, editable_path = detect_editable_install()
    install_method = detect_install_method()
    return UpdateCheckResult(
        current_version=current,
        latest_version=release.version,
        tag_name=release.tag_name,
        update_available=is_newer_version(current, release.version),
        release_url=release.release_url,
        asset_url=release.asset_url,
        asset_name=release.asset_name,
        published_at=release.published_at,
        release_notes=release.release_notes,
        editable_install=editable,
        editable_path=editable_path,
        install_method=install_method,
    )


def perform_update(
    *,
    force: bool = False,
    api_url: str = DEFAULT_GITHUB_LATEST_RELEASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    current_version: str | None = None,
    check_result: UpdateCheckResult | None = None,
) -> UpdateResult:
    """Check GitHub Releases and install the latest wheel when needed."""
    cleanup_stale_windows_shims()
    check = check_result or check_for_update(
        api_url=api_url,
        timeout=timeout,
        current_version=current_version,
    )

    if check.editable_install and not force:
        return UpdateResult(
            status="skipped_editable",
            current_version=check.current_version,
            latest_version=check.latest_version,
            tag_name=check.tag_name,
            update_available=check.update_available,
            updated=False,
            release_url=check.release_url,
            asset_url=check.asset_url,
            published_at=check.published_at,
            install_method=check.install_method,
            editable_install=True,
            editable_path=check.editable_path,
            command=[],
            message=(
                f"Skipped self-update because mailmaster is running from an editable/source checkout"
                f"{f' ({check.editable_path})' if check.editable_path else ''}. "
                "Update your repository with 'git pull', or pass '--force' to install the release wheel anyway."
            ),
        )

    if not check.update_available and not force:
        return UpdateResult(
            status="up_to_date",
            current_version=check.current_version,
            latest_version=check.latest_version,
            tag_name=check.tag_name,
            update_available=False,
            updated=False,
            release_url=check.release_url,
            asset_url=check.asset_url,
            published_at=check.published_at,
            install_method=check.install_method,
            editable_install=check.editable_install,
            editable_path=check.editable_path,
            command=[],
            message=f"Already up to date (v{check.current_version}).",
        )

    cmd = build_install_command(
        check.asset_url,
        install_method=check.install_method,
        same_or_downgrade=not check.update_available,
    )
    staged, locked = _stage_windows_shims()
    if locked:
        _finalize_windows_shims(staged, succeeded=False)
        try:
            _spawn_detached_windows_updater(cmd, locked)
        except OSError as exc:
            raise UpdateError(
                "update_install_failed",
                f"Could not schedule background updater for locked Windows executable: {exc}",
                details={
                    "command": cmd,
                    "locked_paths": [str(path) for path in locked],
                    "asset_url": check.asset_url,
                    "suggestions": [
                        f"Close running mailmaster processes and run: uv tool install --upgrade --force {check.asset_url}",
                    ],
                },
            ) from exc
        return UpdateResult(
            status="scheduled",
            current_version=check.current_version,
            latest_version=check.latest_version,
            tag_name=check.tag_name,
            update_available=check.update_available,
            updated=False,
            release_url=check.release_url,
            asset_url=check.asset_url,
            published_at=check.published_at,
            install_method=check.install_method,
            editable_install=check.editable_install,
            editable_path=check.editable_path,
            command=cmd,
            message=(
                f"Scheduled update to mailmaster v{check.latest_version} in the background "
                "(waiting for the running mailmaster.exe process to exit)."
            ),
        )

    succeeded = False
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            stdout = (completed.stdout or "").strip()
            excerpt = (stderr or stdout)[-1000:]
            raise UpdateError(
                "update_install_failed",
                f"Failed to install mailmaster {check.tag_name} (exit code {completed.returncode}).",
                details={
                    "command": cmd,
                    "returncode": completed.returncode,
                    "output": excerpt,
                    "asset_url": check.asset_url,
                    "release_url": check.release_url,
                    "suggestions": [
                        f"Retry manually: uv tool install --upgrade --force {check.asset_url}",
                        f"Download the release directly from {check.release_url}.",
                    ],
                },
            )
        succeeded = True
    except OSError as exc:
        raise UpdateError(
            "update_install_failed",
            f"Could not launch installer command: {exc}",
            details={
                "command": cmd,
                "exception": type(exc).__name__,
                "asset_url": check.asset_url,
                "suggestions": [
                    f"Upgrade manually: uv tool install --upgrade --force {check.asset_url}",
                ],
            },
        ) from exc
    finally:
        _finalize_windows_shims(staged, succeeded=succeeded)

    if check.current_version == check.latest_version:
        summary = f"Reinstalled mailmaster v{check.latest_version} ({check.release_url})."
    else:
        summary = f"Updated mailmaster from v{check.current_version} to v{check.latest_version} ({check.release_url})."

    return UpdateResult(
        status="updated",
        current_version=check.current_version,
        latest_version=check.latest_version,
        tag_name=check.tag_name,
        update_available=check.update_available,
        updated=True,
        release_url=check.release_url,
        asset_url=check.asset_url,
        published_at=check.published_at,
        install_method=check.install_method,
        editable_install=check.editable_install,
        editable_path=check.editable_path,
        command=cmd,
        message=summary,
    )


__all__ = [
    "DEFAULT_GITHUB_LATEST_RELEASE_URL",
    "DEFAULT_GITHUB_REPO",
    "DEFAULT_GITHUB_REPO_URL",
    "ReleaseInfo",
    "UpdateCheckResult",
    "UpdateError",
    "UpdateResult",
    "build_install_command",
    "check_for_update",
    "cleanup_stale_windows_shims",
    "compare_versions",
    "detect_editable_install",
    "detect_install_method",
    "fetch_latest_release",
    "get_current_version",
    "is_newer_version",
    "normalize_version_string",
    "parse_version",
    "perform_update",
    "select_wheel_asset",
]
