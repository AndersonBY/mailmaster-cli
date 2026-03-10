from __future__ import annotations

import os
import winreg
from pathlib import Path

from .models import MailMasterPaths


def _query_registry_path() -> Path | None:
    candidates = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\App Paths\mailmaster.exe"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\mailmaster.exe"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\App Paths\mailmaster.exe"),
    ]
    for hive, key in candidates:
        try:
            with winreg.OpenKey(hive, key) as handle:
                value, _ = winreg.QueryValueEx(handle, "")
                path = Path(value)
                if path.exists():
                    return path
        except FileNotFoundError:
            continue
    return None


def discover_paths() -> MailMasterPaths:
    launcher = _query_registry_path()
    if launcher is None:
        fallback = Path(r"C:\Program Files (x86)\NetEase\MailMaster\Application\mailmaster.exe")
        launcher = fallback if fallback.exists() else None

    local_root = Path(os.path.expandvars(r"%LOCALAPPDATA%\NetEase\MailMaster"))
    data_root = local_root / "data"
    app_db = data_root / "app.db"
    accounts_root = Path(r"C:\MailMasterData")

    return MailMasterPaths(
        install_root=launcher.parent if launcher else None,
        launcher_exe=launcher,
        local_root=local_root,
        app_db=app_db,
        accounts_root=accounts_root,
    )

