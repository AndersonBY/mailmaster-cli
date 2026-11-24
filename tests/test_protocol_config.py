import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mailmaster.protocol_config import (
    DEFAULT_FIXED_PASSWORD,
    DEFAULT_IV,
    DEFAULT_SALT,
    build_runtime_password_from_sid,
    decrypt_account_config_blob,
    decrypt_config_password,
    decrypt_fixed_protected_blob,
    decrypt_runtime_protected_blob,
    get_security_constants,
)


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def _encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(_pkcs7_pad(data)) + encryptor.finalize()


def test_build_runtime_password_from_sid() -> None:
    sid = "S-1-5-21-309520271-1010210484-4206788573-1001"
    assert build_runtime_password_from_sid(sid) == "S-1%A5&d)#@f3*9!$(-309520271-1010210484-4206788573-1001"


def test_decrypt_account_config_blob_and_inner_password(monkeypatch) -> None:
    iv = b"0123456789ABCDEF"
    salt = "unit-test-salt"
    fixed_password = "unit-test-fixed-password"
    runtime_password = "unit-test-runtime-password"

    monkeypatch.setattr(
        "mailmaster.protocol_config.get_security_constants",
        lambda install_root=None: (iv, salt, fixed_password),
    )
    monkeypatch.setattr("mailmaster.protocol_config.get_runtime_password", lambda install_root=None: runtime_password)

    from hashlib import pbkdf2_hmac

    outer_key = pbkdf2_hmac("sha1", fixed_password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)
    inner_key = pbkdf2_hmac("sha1", runtime_password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)

    inner_plain = b"example-password-123"
    inner_cipher = _encrypt_aes_cbc(inner_plain, inner_key, iv)
    config_plain = {
        "host": "smtp.example.com",
        "port": 465,
        "user": "sender@example.com",
        "pass": base64.b64encode(inner_cipher).decode("ascii"),
    }
    outer_cipher = _encrypt_aes_cbc(json.dumps(config_plain).encode("utf-8"), outer_key, iv)

    config = decrypt_account_config_blob(outer_cipher)
    assert config["host"] == "smtp.example.com"
    assert config["port"] == 465
    assert config["user"] == "sender@example.com"

    password = decrypt_config_password(config["pass"])
    assert password == "example-password-123"


def test_decrypt_fixed_and_runtime_protected_blobs(monkeypatch) -> None:
    iv = b"0123456789ABCDEF"
    salt = "unit-test-salt"
    fixed_password = "unit-test-fixed-password"
    runtime_password = "unit-test-runtime-password"

    monkeypatch.setattr(
        "mailmaster.protocol_config.get_security_constants",
        lambda install_root=None: (iv, salt, fixed_password),
    )
    monkeypatch.setattr("mailmaster.protocol_config.get_runtime_password", lambda install_root=None: runtime_password)

    from hashlib import pbkdf2_hmac

    fixed_key = pbkdf2_hmac("sha1", fixed_password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)
    runtime_key = pbkdf2_hmac("sha1", runtime_password.encode("utf-8"), salt.encode("utf-8"), 256, dklen=32)

    fixed_plain = b'{"kind":"fixed"}'
    runtime_plain = b'{"kind":"runtime"}'
    fixed_cipher = _encrypt_aes_cbc(fixed_plain, fixed_key, iv)
    runtime_cipher = _encrypt_aes_cbc(runtime_plain, runtime_key, iv)

    assert decrypt_fixed_protected_blob(fixed_cipher) == fixed_plain
    assert decrypt_runtime_protected_blob(runtime_cipher) == runtime_plain


def test_fallback_security_constants_match_expected_digests(tmp_path: Path) -> None:
    assert isinstance(DEFAULT_FIXED_PASSWORD, str)
    assert isinstance(DEFAULT_SALT, str)
    assert isinstance(DEFAULT_IV, bytes)
    assert len(DEFAULT_FIXED_PASSWORD) == 28
    assert len(DEFAULT_SALT) == 15
    assert len(DEFAULT_IV) == 16
    assert (
        hashlib.sha256(DEFAULT_FIXED_PASSWORD.encode("ascii")).hexdigest()
        == "281bee06a0796be3fe8cd57414b2494794347f92165961f0425e8b89093c0424"
    )
    assert (
        hashlib.sha256(DEFAULT_SALT.encode("ascii")).hexdigest()
        == "41e64efff3154d111ead4f8b0025dfed2689211e139bc5973426b114fde7967e"
    )
    assert (
        hashlib.sha256(DEFAULT_IV).hexdigest()
        == "0c24f5ba0efbaad5228ba8af1209ad4a07b79db03ca2d640c2f8a937c33e6864"
    )
    assert get_security_constants(tmp_path) == (DEFAULT_IV, DEFAULT_SALT, DEFAULT_FIXED_PASSWORD)
