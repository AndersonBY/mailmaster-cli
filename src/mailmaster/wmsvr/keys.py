"""Embedded `mastercore.dll` RSA public-key extraction, digesting, and key-update unwrapping."""

from __future__ import annotations

import re as _re
from dataclasses import dataclass
from hashlib import md5
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..discovery import discover_paths
from .tlv import KNOWN_WMSVR_HARDCODED_KEY_DIGESTS, _resolve_wmsvr_hook

_PUBLIC_KEY_PEM_PATTERN = _re.compile(
    rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----",
    _re.S,
)


@dataclass(slots=True, frozen=True)
class WmsvrHardcodedPublicKey:
    """One public key block extracted from `mastercore.dll`."""

    label: str
    pem: str
    digest16: bytes
    bits: int
    exponent: int
    source_path: str = ""
    source_index: int = -1

    @property
    def digest_hex(self) -> str:
        return self.digest16.hex()


@dataclass(slots=True)
class WmsvrDecodedKeyUpdate:
    """Decoded runtime key material from a `GET_SETTINGS -> 0x01f0` response."""

    version: int
    der_bytes: bytes
    pem: str
    digest16: bytes
    matched_hardcoded_key: str = ""

    @property
    def digest_hex(self) -> str:
        return self.digest16.hex()


_HARDCODED_WMSVR_KEYS_CACHE: dict[Path | None, dict[str, WmsvrHardcodedPublicKey]] = {}


def _iter_mastercore_dll_candidates(install_root: Path | None = None) -> list[Path]:
    root = install_root if install_root is not None else discover_paths().install_root
    if root is None or not root.exists():
        return []
    return sorted(
        root.rglob("mastercore.dll"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def _normalize_public_key_pem(pem: bytes) -> bytes:
    normalized = pem.replace(b"\r\r\n", b"\n").replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = [line.strip() for line in normalized.split(b"\n") if line.strip()]
    return b"\n".join(lines) + b"\n"


def _load_rsa_public_key(key_data: bytes | str) -> rsa.RSAPublicKey:
    raw = key_data.encode("ascii") if isinstance(key_data, str) else key_data
    public_key = (
        serialization.load_pem_public_key(raw)
        if b"-----BEGIN" in raw
        else serialization.load_der_public_key(raw)
    )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Only RSA public keys are supported for Wmsvr key handling.")
    return public_key


def _coerce_wmsvr_public_key(
    public_key: WmsvrHardcodedPublicKey | rsa.RSAPublicKey | bytes | str,
) -> rsa.RSAPublicKey:
    if isinstance(public_key, WmsvrHardcodedPublicKey):
        key_data: bytes | str = public_key.pem
    else:
        key_data = public_key
    if isinstance(key_data, rsa.RSAPublicKey):
        return key_data

    raw = key_data.encode("utf-8") if isinstance(key_data, str) else key_data
    if b"-----BEGIN PUBLIC KEY-----" in raw:
        loaded = serialization.load_pem_public_key(raw)
    else:
        loaded = serialization.load_der_public_key(raw)
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return loaded


def compute_wmsvr_public_key_digest(key_data: bytes | str) -> bytes:
    """Compute the confirmed MailMaster digest for one RSA public key."""
    public_key = _load_rsa_public_key(key_data)
    numbers = public_key.public_numbers()
    modulus_hex_upper = format(numbers.n, "X")
    exponent_hex_lower = format(numbers.e, "x").zfill(((numbers.e.bit_length() + 7) // 8) * 2)
    digest_text = f"{modulus_hex_upper},{exponent_hex_lower}".encode("ascii")
    return md5(digest_text).digest()


def _describe_public_key(
    key_data: bytes | str,
    *,
    label: str,
    source_path: str = "",
    source_index: int = -1,
) -> WmsvrHardcodedPublicKey:
    public_key = _load_rsa_public_key(key_data)
    digest16 = compute_wmsvr_public_key_digest(key_data)
    numbers = public_key.public_numbers()
    pem_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return WmsvrHardcodedPublicKey(
        label=label,
        pem=pem_bytes.decode("ascii"),
        digest16=digest16,
        bits=public_key.key_size,
        exponent=numbers.e,
        source_path=source_path,
        source_index=source_index,
    )


def load_wmsvr_hardcoded_public_keys(
    install_root: Path | None = None,
) -> dict[str, WmsvrHardcodedPublicKey]:
    """Scan the latest installed `mastercore.dll` for embedded public keys."""
    cache_key = install_root.resolve() if install_root is not None else None
    cached = _HARDCODED_WMSVR_KEYS_CACHE.get(cache_key)
    if cached is not None:
        return cached

    label_by_digest = {
        digest.hex(): label
        for label, digest in KNOWN_WMSVR_HARDCODED_KEY_DIGESTS.items()
    }

    for dll_path in _iter_mastercore_dll_candidates(install_root):
        try:
            raw = dll_path.read_bytes()
        except OSError:
            continue

        found: dict[str, WmsvrHardcodedPublicKey] = {}
        seen_digests: set[bytes] = set()
        for index, match in enumerate(_PUBLIC_KEY_PEM_PATTERN.finditer(raw)):
            pem = _normalize_public_key_pem(match.group(0))
            try:
                digest16 = compute_wmsvr_public_key_digest(pem)
                label = label_by_digest.get(digest16.hex(), f"embedded_{index}")
                key = _describe_public_key(
                    pem,
                    label=label,
                    source_path=str(dll_path),
                    source_index=index,
                )
            except (TypeError, ValueError):
                continue
            if key.digest16 in seen_digests:
                continue
            seen_digests.add(key.digest16)
            found[key.label] = key

        if found:
            _HARDCODED_WMSVR_KEYS_CACHE[cache_key] = found
            return found

    result: dict[str, WmsvrHardcodedPublicKey] = {}
    _HARDCODED_WMSVR_KEYS_CACHE[cache_key] = result
    return result


def get_wmsvr_hardcoded_public_key(
    label: str,
    *,
    install_root: Path | None = None,
) -> WmsvrHardcodedPublicKey:
    """Return one labeled hardcoded key from `mastercore.dll`."""
    loader = _resolve_wmsvr_hook(
        "load_wmsvr_hardcoded_public_keys",
        load_wmsvr_hardcoded_public_keys,
        _ORIG_LOAD_HARDCODED_KEYS,
    )
    keys = loader(install_root)
    try:
        return keys[label]
    except KeyError as exc:
        raise ValueError(f"Wmsvr hardcoded public key not found: {label}") from exc


def find_wmsvr_hardcoded_public_key_by_digest(
    digest16: bytes,
    *,
    install_root: Path | None = None,
) -> WmsvrHardcodedPublicKey | None:
    """Return the installed hardcoded key whose digest matches `digest16`."""
    loader = _resolve_wmsvr_hook(
        "load_wmsvr_hardcoded_public_keys",
        load_wmsvr_hardcoded_public_keys,
        _ORIG_LOAD_HARDCODED_KEYS,
    )
    for key in loader(install_root).values():
        if key.digest16 == digest16:
            return key
    return None


def unwrap_wmsvr_key_update_blob(
    key_blob: bytes,
    sibling_public_key: bytes | str | WmsvrHardcodedPublicKey,
) -> bytes:
    """Recover the inner DER payload from a `0x01f0` sibling-slot key-update blob."""
    key_data = (
        sibling_public_key.pem
        if isinstance(sibling_public_key, WmsvrHardcodedPublicKey)
        else sibling_public_key
    )
    public_key = _load_rsa_public_key(key_data)
    public_numbers = public_key.public_numbers()
    block_size = (public_key.key_size + 7) // 8
    if len(key_blob) != block_size:
        raise ValueError(f"Key-update blob must be {block_size} bytes, got {len(key_blob)}")

    cipher_int = int.from_bytes(key_blob, "big")
    plain_int = pow(cipher_int, public_numbers.e, public_numbers.n)
    encoded_message = plain_int.to_bytes(block_size, "big")

    if not encoded_message.startswith(b"\x00\x01"):
        raise ValueError("Key-update blob is not a PKCS#1 type-1 block.")
    separator = encoded_message.find(b"\x00", 2)
    if separator < 10:
        raise ValueError("Key-update blob has invalid PKCS#1 padding.")
    if any(byte != 0xFF for byte in encoded_message[2:separator]):
        raise ValueError("Key-update blob contains non-0xFF PKCS#1 padding bytes.")
    return encoded_message[separator + 1 :]


def der_bytes_to_public_key_pem(der_bytes: bytes) -> str:
    """Wrap DER public-key bytes as a canonical PEM block."""
    public_key = _load_rsa_public_key(der_bytes)
    pem_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


_ORIG_LOAD_HARDCODED_KEYS = load_wmsvr_hardcoded_public_keys
