from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wintypes
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .discovery import discover_paths


DEFAULT_FIXED_PASSWORD = "%A5&d)#weAJA&\\/?^wej@f3*9!$("
DEFAULT_SALT = "%A5&d)#@f3*9!$("
DEFAULT_IV = b"P1C2M3A4I5L6N7B8"

_TOKEN_QUERY = 8


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", wintypes.LPVOID)]


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if pad <= 0 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad]


def _extract_ascii_strings(blob: bytes) -> list[str]:
    parts = blob.split(b"\x00")
    results: list[str] = []
    for part in parts:
        if len(part) < 4:
            continue
        try:
            text = part.decode("ascii")
        except UnicodeDecodeError:
            continue
        if all(32 <= ord(ch) < 127 for ch in text):
            results.append(text)
    return results


def _iter_mastercore_candidates(install_root: Path | None = None) -> list[Path]:
    if install_root is None:
        install_root = discover_paths().install_root
    if install_root is None or not install_root.exists():
        return []
    candidates = sorted(install_root.rglob("mastercore.dll"), key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates


_SECURITY_CONSTANTS_CACHE: dict[Path | None, tuple[bytes, str, str]] = {}


def get_security_constants(install_root: Path | None = None) -> tuple[bytes, str, str]:
    cache_key = install_root.resolve() if install_root is not None else None
    cached = _SECURITY_CONSTANTS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    for dll_path in _iter_mastercore_candidates(install_root):
        try:
            raw = dll_path.read_bytes()
        except OSError:
            continue
        marker = raw.find(b"Init encryptor failed")
        if marker < 0:
            continue
        window = raw[max(0, marker - 256) : marker]
        strings = _extract_ascii_strings(window)
        if len(strings) < 3:
            continue
        iv, salt, fixed_password = strings[-3:]
        if len(iv) == 16 and 8 <= len(salt) <= 32 and len(fixed_password) >= 16:
            result = (iv.encode("ascii"), salt, fixed_password)
            _SECURITY_CONSTANTS_CACHE[cache_key] = result
            return result

    result = (DEFAULT_IV, DEFAULT_SALT, DEFAULT_FIXED_PASSWORD)
    _SECURITY_CONSTANTS_CACHE[cache_key] = result
    return result


def _derive_key(password: str, install_root: Path | None = None) -> bytes:
    _, salt, _ = get_security_constants(install_root)
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)


def _decrypt_aes_cbc(ciphertext: bytes, password: str, install_root: Path | None = None) -> bytes:
    iv, _, _ = get_security_constants(install_root)
    decryptor = Cipher(algorithms.AES(_derive_key(password, install_root)), modes.CBC(iv)).decryptor()
    return _pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())


def _get_current_user_sid() -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_uint, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    process = kernel32.GetCurrentProcess()
    if not advapi32.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        buf = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(token, 1, buf, required, ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())

        token_user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER)).contents
        string_sid = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(token_user.User, ctypes.byref(string_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            value = string_sid.value
            if value is None:
                raise RuntimeError("Failed to convert current user SID to string.")
            return value
        finally:
            kernel32.LocalFree(string_sid)
    finally:
        kernel32.CloseHandle(token)


def build_runtime_password_from_sid(sid: str, install_root: Path | None = None) -> str:
    _, salt, fixed_password = get_security_constants(install_root)
    if len(sid) < 3:
        return fixed_password
    replace_len = min(5, max(len(sid) - 3, 0))
    return sid[:3] + salt + sid[3 + replace_len :]


def get_runtime_password(install_root: Path | None = None) -> str:
    return build_runtime_password_from_sid(_get_current_user_sid(), install_root)


def decrypt_account_config_blob(blob: bytes, install_root: Path | None = None) -> dict[str, Any]:
    _, _, fixed_password = get_security_constants(install_root)
    return json.loads(_decrypt_aes_cbc(blob, fixed_password, install_root).decode("utf-8"))


def decrypt_config_password(password_b64: str, install_root: Path | None = None) -> str:
    if not password_b64:
        return ""
    raw = base64.b64decode(password_b64)
    try:
        return _decrypt_aes_cbc(raw, get_runtime_password(install_root), install_root).decode("utf-8")
    except Exception:
        return ""


def load_server_configs(mail_db: Path, *, install_root: Path | None = None) -> dict[str, dict[str, Any]]:
    conn = sqlite3.connect(mail_db)
    try:
        rows = conn.execute(
            "SELECT Key, Value FROM AccountConfig WHERE Key IN ('IMAPServerConfig', 'SMTPServerConfig', 'WmsvrServerConfig')"
        ).fetchall()
    finally:
        conn.close()

    configs: dict[str, dict[str, Any]] = {}
    for key, value in rows:
        if value is None:
            continue
        data = decrypt_account_config_blob(value, install_root)
        raw_password = str(data.get("pass") or "")
        data["password"] = decrypt_config_password(raw_password, install_root)
        data["password_b64"] = raw_password
        configs[str(key)] = data
    return configs
