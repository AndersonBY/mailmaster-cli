"""d1 framing, AES-CBC slice encryption, session-key wrapping, and raw TCP I/O."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .bootstrap import WmsvrLoginContext, WmsvrPeerCandidate, WmsvrSession
from .keys import (
    _HARDCODED_WMSVR_KEYS_CACHE as _HARDCODED_WMSVR_KEYS_CACHE,
    _PUBLIC_KEY_PEM_PATTERN as _PUBLIC_KEY_PEM_PATTERN,
    WmsvrDecodedKeyUpdate as WmsvrDecodedKeyUpdate,
    WmsvrHardcodedPublicKey as WmsvrHardcodedPublicKey,
    _coerce_wmsvr_public_key as _coerce_wmsvr_public_key,
    _describe_public_key as _describe_public_key,
    _iter_mastercore_dll_candidates as _iter_mastercore_dll_candidates,
    _load_rsa_public_key as _load_rsa_public_key,
    _normalize_public_key_pem as _normalize_public_key_pem,
    compute_wmsvr_public_key_digest as compute_wmsvr_public_key_digest,
    der_bytes_to_public_key_pem as der_bytes_to_public_key_pem,
    find_wmsvr_hardcoded_public_key_by_digest as find_wmsvr_hardcoded_public_key_by_digest,
    get_wmsvr_hardcoded_public_key as get_wmsvr_hardcoded_public_key,
    load_wmsvr_hardcoded_public_keys as load_wmsvr_hardcoded_public_keys,
    unwrap_wmsvr_key_update_blob as unwrap_wmsvr_key_update_blob,
)
from .tlv import (
    D1_CONTROL_TAG_KEY_DIGEST,
    D1_CONTROL_TAG_KEY_VERSION,
    D1_KEY_EXCHANGE_BLOCK_LEN,
    D1_SLICE_PADDING_NUL,
    D1_SLICE_PADDING_PKCS7,
    D1_WORD0_HAS_EXTRA16,
    D1_WORD0_HAS_LEN0,
    D1_WORD0_HAS_LEN1,
    DEFAULT_D1_AES_IV,
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_GET_SETTINGS_SIGNATURE,
    DEFAULT_D1_GET_SETTINGS_WORD0,
    DEFAULT_D1_GET_SETTINGS_WORD2,
    DEFAULT_D1_GET_SETTINGS_WORD4,
    DEFAULT_D1_KEY_VERSION,
    DEFAULT_D1_RPC_WORD2,
    DEFAULT_D1_RPC_WORD4,
    DEFAULT_D1_SLICE_PADDING,
    TAG_ACCOUNT,
    TAG_CLIENT_ID,
    TAG_DEVICE_INFO,
    TAG_HOST,
    TAG_METHOD,
    TAG_PORT,
    TAG_ROUTE,
    TAG_TICKET,
    TAG_TOKEN,
    TAG_TRACE_ID,
    TAG_VERSION,
    _resolve_wmsvr_hook,
    decode_leb128,
    decode_tlv_envelope,
    encode_leb128,
    encode_tlv_envelope,
)


class WmsvrTransportError(Exception):
    """Raised when the Wmsvr transport fails."""


# ---------------------------------------------------------------------------
# d1 wire dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class WmsvrRequest:
    """A fully constructed Wmsvr protocol request."""

    method: str
    body_json: str
    envelope: bytes = b""
    session: WmsvrSession = field(default_factory=WmsvrSession)

    def to_wire(self) -> tuple[bytes, bytes]:
        """Return (envelope_bytes, body_bytes) ready for transmission."""
        return self.envelope, self.body_json.encode("utf-8")

    def to_d1_plain_layout(self) -> WmsvrD1PlainLayout:
        """Return the confirmed pre-encryption d1 body layout."""
        return build_d1_plain_layout(self.envelope, self.body_json.encode("utf-8"))


@dataclass(slots=True)
class WmsvrD1PlainLayout:
    """Confirmed plaintext layout before the private d1 block transform."""

    section_len: int
    padded_json_len: int
    body_prefix: bytes
    padded_envelope: bytes
    padded_json: bytes

    @property
    def padded_slice0(self) -> bytes:
        return self.padded_envelope

    @property
    def padded_slice1(self) -> bytes:
        return self.padded_json

    @property
    def slice0_len(self) -> int:
        return self.section_len

    @property
    def slice1_len(self) -> int:
        return self.padded_json_len

    @property
    def encrypted_plaintext(self) -> bytes:
        """Bytes that feed into the private encrypted-region transform."""
        return self.padded_envelope + self.padded_json

    @property
    def body_len(self) -> int:
        """Plain body length before region encryption is applied."""
        return len(self.body_prefix) + len(self.encrypted_plaintext)

    def to_unencrypted_body(self) -> bytes:
        """Return `[body_prefix][encrypted_plaintext]` for analysis/debugging."""
        return self.body_prefix + self.encrypted_plaintext


@dataclass(slots=True)
class WmsvrD1Header:
    """Parsed/constructed raw d1 frame header."""

    word0: int
    word2: int
    word4: int
    seq: int = 0
    extra16: int | None = None
    len0: int | None = None
    len1: int | None = None

    @property
    def frame_type(self) -> int:
        return (self.word0 >> 8) & 0xFF

    @property
    def has_extra16(self) -> bool:
        return bool(self.word0 & D1_WORD0_HAS_EXTRA16)

    @property
    def has_len0(self) -> bool:
        return bool(self.word0 & D1_WORD0_HAS_LEN0)

    @property
    def has_len1(self) -> bool:
        return bool(self.word0 & D1_WORD0_HAS_LEN1)

    def to_bytes(self) -> bytes:
        parts = [
            b"\xD1",
            struct.pack(">H", self.word0 & 0xFFFF),
            struct.pack(">H", self.word4 & 0xFFFF),
            struct.pack(">H", self.word2 & 0xFFFF),
            struct.pack(">H", self.seq & 0xFFFF),
        ]
        if self.has_extra16:
            parts.append(struct.pack(">H", int(self.extra16 or 0) & 0xFFFF))
        if self.has_len0:
            parts.append(encode_leb128(int(self.len0 or 0)))
        if self.has_len1:
            parts.append(encode_leb128(int(self.len1 or 0)))
        return b"".join(parts)


@dataclass(slots=True)
class WmsvrD1Frame:
    """Structured raw d1 frame with optional split slices."""

    header: WmsvrD1Header
    slice0: bytes = b""
    slice1: bytes = b""
    remainder: bytes = b""

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.slice0 + self.slice1 + self.remainder


@dataclass(slots=True)
class WmsvrGetSettingsResponse:
    """Parsed metadata from a raw d1 `GET_SETTINGS` response frame."""

    business_code: int | None = None
    key_version: int | None = None
    key_blob: bytes = b""
    frame: WmsvrD1Frame | None = None


@dataclass(slots=True)
class WmsvrD1RequestContext:
    """Low-level material needed to build raw encrypted d1 requests."""

    key_version: int = DEFAULT_D1_KEY_VERSION
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16
    master_fp: str = ""
    master_sdid: str = ""
    device_info_json: str = ""
    session_key: bytes = b""
    word2: int = DEFAULT_D1_RPC_WORD2
    word4: int = DEFAULT_D1_RPC_WORD4

    @property
    def key_digest32(self) -> bytes:
        return normalize_d1_key_digest(self.key_digest16)

    def with_session_key(self, session_key: bytes) -> WmsvrD1RequestContext:
        return WmsvrD1RequestContext(
            key_version=self.key_version,
            key_digest16=self.key_digest16,
            master_fp=self.master_fp,
            master_sdid=self.master_sdid,
            device_info_json=self.device_info_json,
            session_key=session_key,
            word2=self.word2,
            word4=self.word4,
        )


def decode_get_settings_key_update(
    response: WmsvrGetSettingsResponse,
    *,
    install_root: Path | None = None,
    sibling_public_key: bytes | str | WmsvrHardcodedPublicKey | None = None,
) -> WmsvrDecodedKeyUpdate:
    """Decode a `GET_SETTINGS` key-update response into runtime key material."""
    if response.business_code != 0x01F0:
        raise ValueError(f"Expected business_code=0x01f0, got {response.business_code!r}")
    if response.key_version is None:
        raise ValueError("Key-update response is missing tag 0x0001 version.")
    if not response.key_blob:
        raise ValueError("Key-update response is missing slice1 key blob.")

    sibling_key = sibling_public_key
    if sibling_key is None:
        sibling_key = get_wmsvr_hardcoded_public_key(
            "sibling_default",
            install_root=install_root,
        )

    der_bytes = unwrap_wmsvr_key_update_blob(response.key_blob, sibling_key)
    pem = der_bytes_to_public_key_pem(der_bytes)
    digest16 = compute_wmsvr_public_key_digest(pem)

    matched_hardcoded_key = ""
    for label, key in load_wmsvr_hardcoded_public_keys(install_root).items():
        if key.digest16 == digest16:
            matched_hardcoded_key = label
            break

    return WmsvrDecodedKeyUpdate(
        version=response.key_version,
        der_bytes=der_bytes,
        pem=pem,
        digest16=digest16,
        matched_hardcoded_key=matched_hardcoded_key,
    )


# ---------------------------------------------------------------------------
# Runtime tail & envelope builders
# ---------------------------------------------------------------------------


def _as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _build_wmsvr_runtime_tail_records(
    *,
    ticket: str = "",
    trace_id: str = "",
    device_info_json: str = "",
    client_id: str = "",
) -> list[tuple[int, bytes]]:
    records: list[tuple[int, bytes]] = []
    if ticket:
        records.append((TAG_TICKET, ticket.encode("utf-8")))
    if trace_id:
        records.append((TAG_TRACE_ID, trace_id.encode("utf-8")))
    if device_info_json:
        records.append((TAG_DEVICE_INFO, device_info_json.encode("utf-8")))
    if client_id:
        records.append((TAG_CLIENT_ID, client_id.encode("utf-8")))
    return records


def build_wmsvr_runtime_tail_records(session: WmsvrSession) -> list[tuple[int, bytes]]:
    """Build the shared runtime tail used by normal and startup-family requests."""
    return _build_wmsvr_runtime_tail_records(
        ticket=session.ticket,
        trace_id=session.trace_id,
        device_info_json=session.device_info,
        client_id=session.client_id,
    )


def build_envelope(session: WmsvrSession, method: str) -> bytes:
    """Build the TLV envelope for a Wmsvr request."""
    records: list[tuple[int, bytes]] = [
        (TAG_VERSION, b"\x00\x00\x00\x01"),
        (TAG_METHOD, method.encode("utf-8")),
    ]
    if session.token:
        records.append((TAG_TOKEN, session.token.encode("utf-8")))
    if session.route:
        records.append((TAG_ROUTE, session.route.encode("utf-8")))
    if session.host:
        records.append((TAG_HOST, session.host.encode("utf-8")))
    if session.port:
        records.append((TAG_PORT, struct.pack(">H", session.port)))
    if session.account_desc:
        records.append((TAG_ACCOUNT, session.account_desc.encode("utf-8")))
    records.extend(build_wmsvr_runtime_tail_records(session))
    return encode_tlv_envelope(records)


def build_envelope_with_records(
    session: WmsvrSession,
    method: str,
    extra_records: Iterable[tuple[int, bytes]] = (),
) -> bytes:
    """`build_envelope` plus extra records, placed where the client's writer emits them."""
    extras = list(extra_records)
    if not extras:
        return build_envelope(session, method)
    records = decode_tlv_envelope(build_envelope(session, method))
    out: list[tuple[int, bytes]] = []
    inserted = False
    for tag, value in records:
        if tag == TAG_ACCOUNT and not inserted:
            out.extend(extras)
            inserted = True
        out.append((tag, value))
    if not inserted:
        out.extend(extras)
    return encode_tlv_envelope(out)


def build_request(
    session: WmsvrSession,
    method: str,
    body: dict[str, Any] | None,
) -> WmsvrRequest:
    """Build a complete Wmsvr request with TLV envelope and JSON body."""
    body_json = "" if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    envelope = build_envelope(session, method)
    return WmsvrRequest(
        method=method,
        body_json=body_json,
        envelope=envelope,
        session=session,
    )


# ---------------------------------------------------------------------------
# d1 slice padding, crypto, and frame construction
# ---------------------------------------------------------------------------


def pad_d1_slice(data: bytes, padding: str = DEFAULT_D1_SLICE_PADDING) -> bytes:
    """Pad one plaintext d1 slice to the AES block size the way the client does."""
    if not data:
        return b""
    remainder = len(data) % 16
    if padding == D1_SLICE_PADDING_PKCS7:
        pad_len = 16 - remainder
        fill = bytes([pad_len])
    elif padding == D1_SLICE_PADDING_NUL:
        pad_len = 0 if remainder == 0 else 16 - remainder
        fill = b"\x00"
    else:
        raise ValueError(f"Unknown d1 slice padding rule: {padding!r}")
    return data + (fill * pad_len)


def align16(data: bytes) -> bytes:
    """Pad data to the next 16-byte boundary with NUL bytes (legacy rule)."""
    return pad_d1_slice(data, D1_SLICE_PADDING_NUL)


def strip_wmsvr_slice_padding(data: bytes) -> bytes:
    """Strip the trailing block padding a d1 slice carries (PKCS#7 or NUL)."""
    if not data:
        return data
    last = data[-1]
    if 1 <= last <= 16 and len(data) >= last and data[-last:] == bytes([last]) * last:
        return data[:-last]
    return data.rstrip(b"\x00")


def build_d1_slice_layout(
    slice0: bytes,
    slice1: bytes = b"",
    *,
    padding: str = DEFAULT_D1_SLICE_PADDING,
) -> WmsvrD1PlainLayout:
    """Build the confirmed plaintext layout for one outbound d1 frame."""
    padded_envelope = pad_d1_slice(slice0, padding)
    padded_json = pad_d1_slice(slice1, padding) if slice1 else b""
    body_prefix = encode_leb128(len(padded_json)) if padded_json else b""
    return WmsvrD1PlainLayout(
        section_len=len(padded_envelope),
        padded_json_len=len(padded_json),
        body_prefix=body_prefix,
        padded_envelope=padded_envelope,
        padded_json=padded_json,
    )


def build_d1_plain_layout(envelope: bytes, body_bytes: bytes) -> WmsvrD1PlainLayout:
    """Backward-compatible wrapper for normal `TLV + JSON` request bodies."""
    return build_d1_slice_layout(envelope, body_bytes)


def normalize_d1_key_digest(digest: bytes) -> bytes:
    """Normalize a GET_SETTINGS key digest to the observed 32-byte wire format."""
    if len(digest) == 16:
        return digest + (b"\x00" * 16)
    if len(digest) == 32:
        return digest
    raise ValueError(f"D1 key digest must be 16 or 32 bytes, got {len(digest)}")


def build_wmsvr_d1_request_context(
    login_context: WmsvrLoginContext,
    *,
    key_version: int = DEFAULT_D1_KEY_VERSION,
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    session_key: bytes = b"",
    word2: int = DEFAULT_D1_RPC_WORD2,
    word4: int = DEFAULT_D1_RPC_WORD4,
) -> WmsvrD1RequestContext:
    """Build the low-level d1 request context from login/bootstrap material."""
    return WmsvrD1RequestContext(
        key_version=key_version,
        key_digest16=key_digest16,
        master_fp=login_context.master_fp,
        master_sdid=login_context.master_sdid,
        device_info_json=login_context.device_info_json,
        session_key=session_key,
        word2=word2,
        word4=word4,
    )


def build_wmsvr_d1_control_tlv(context: WmsvrD1RequestContext) -> bytes:
    """Build the confirmed `AB74A0` control-material prefix."""
    return encode_tlv_envelope(
        [
            (D1_CONTROL_TAG_KEY_VERSION, struct.pack(">I", context.key_version & 0xFFFFFFFF)),
            (D1_CONTROL_TAG_KEY_DIGEST, context.key_digest32),
        ]
    )


def generate_wmsvr_d1_session_key() -> bytes:
    """Generate the client-side 16-byte AES key stored at `session+0x44`."""
    return os.urandom(16)


def _require_wmsvr_d1_session_key(session_key: bytes) -> bytes:
    if len(session_key) != 16:
        raise ValueError(f"Wmsvr d1 session key must be 16 bytes, got {len(session_key)}")
    return session_key


def wrap_wmsvr_d1_session_key(
    session_key: bytes,
    public_key: WmsvrHardcodedPublicKey | rsa.RSAPublicKey | bytes | str,
) -> bytes:
    """Wrap the 16-byte d1 session key with the current Wmsvr public key."""
    key = _require_wmsvr_d1_session_key(session_key)
    rsa_public_key = _coerce_wmsvr_public_key(public_key)
    return rsa_public_key.encrypt(key, padding.PKCS1v15())


def encrypt_wmsvr_d1_slice(data: bytes, session_key: bytes) -> bytes:
    """Encrypt one aligned payload slice with the confirmed AES-128-CBC transform."""
    key = _require_wmsvr_d1_session_key(session_key)
    if len(data) % 16 != 0:
        raise ValueError("Wmsvr d1 slice length must already be 16-byte aligned before encryption.")
    if not data:
        return b""
    encryptor = Cipher(algorithms.AES(key), modes.CBC(DEFAULT_D1_AES_IV)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def decrypt_wmsvr_d1_slice(data: bytes, session_key: bytes) -> bytes:
    """Decrypt one aligned payload slice with the confirmed AES-128-CBC transform."""
    key = _require_wmsvr_d1_session_key(session_key)
    if len(data) % 16 != 0:
        raise ValueError("Wmsvr d1 slice length must be a multiple of 16 bytes.")
    if not data:
        return b""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(DEFAULT_D1_AES_IV)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def build_wmsvr_d1_encrypted_frame(
    slice0: bytes,
    *,
    session_key: bytes,
    slice1_bytes: bytes = b"",
    body_bytes: bytes | None = None,
    seq: int = 1,
    word2: int = DEFAULT_D1_RPC_WORD2,
    word4: int = DEFAULT_D1_RPC_WORD4,
    word0: int | None = None,
    padding: str = DEFAULT_D1_SLICE_PADDING,
) -> WmsvrD1Frame:
    """Build one raw encrypted d1 frame from already-encoded plaintext slices."""
    if body_bytes is not None and slice1_bytes:
        raise ValueError("Pass either `slice1_bytes` or `body_bytes`, not both.")
    resolved_slice1 = body_bytes if body_bytes is not None else slice1_bytes
    layout = build_d1_slice_layout(slice0, resolved_slice1, padding=padding)
    encrypted_slice0 = encrypt_wmsvr_d1_slice(layout.padded_slice0, session_key)
    encrypted_slice1 = (
        encrypt_wmsvr_d1_slice(layout.padded_slice1, session_key)
        if layout.padded_slice1
        else b""
    )
    resolved_word0 = word0 if word0 is not None else (0xB000 if encrypted_slice1 else 0xA000)
    if bool(resolved_word0 & D1_WORD0_HAS_LEN1) != bool(encrypted_slice1):
        raise ValueError("Provided `word0` does not match the presence of slice1.")
    return WmsvrD1Frame(
        header=WmsvrD1Header(
            word0=resolved_word0,
            word2=word2,
            word4=word4,
            seq=seq,
            len0=layout.slice0_len,
            len1=layout.slice1_len if encrypted_slice1 else None,
        ),
        slice0=encrypted_slice0,
        slice1=encrypted_slice1,
    )


def decrypt_wmsvr_d1_frame_slices(
    frame: WmsvrD1Frame,
    session_key: bytes,
) -> tuple[bytes, bytes]:
    """Decrypt the payload slices of one already-parsed encrypted d1 frame."""
    return (
        decrypt_wmsvr_d1_slice(frame.slice0, session_key),
        decrypt_wmsvr_d1_slice(frame.slice1, session_key) if frame.slice1 else b"",
    )


def build_wmsvr_d1_request_frame(
    context: WmsvrD1RequestContext,
    session: WmsvrSession,
    method: str,
    *,
    body: dict[str, Any] | None = None,
    seq: int = 1,
    include_d1_control: bool = False,
) -> WmsvrD1Frame:
    """Build a raw encrypted d1 request from the Wmsvr envelope + JSON body."""
    request = build_request(session, method, body)
    envelope = request.envelope
    if include_d1_control:
        envelope = build_wmsvr_d1_control_tlv(context) + envelope
    session_key = context.session_key or generate_wmsvr_d1_session_key()
    return build_wmsvr_d1_encrypted_frame(
        envelope,
        slice1_bytes=request.body_json.encode("utf-8"),
        seq=seq,
        session_key=session_key,
        word2=context.word2,
        word4=context.word4,
    )


def build_wmsvr_d1_binary_request_frame(
    context: WmsvrD1RequestContext,
    session: WmsvrSession,
    method: str,
    *,
    payload: bytes = b"",
    records: Iterable[tuple[int, bytes]] = (),
    seq: int = 1,
) -> WmsvrD1Frame:
    """Build an encrypted d1 request whose body is raw bytes, with optional extra records."""
    envelope = build_envelope_with_records(session, method, records)
    session_key = context.session_key or generate_wmsvr_d1_session_key()
    return build_wmsvr_d1_encrypted_frame(
        envelope,
        slice1_bytes=bytes(payload),
        seq=seq,
        session_key=session_key,
        word2=context.word2,
        word4=context.word4,
    )


def build_wmsvr_pre_auth_frame(
    context: WmsvrD1RequestContext,
    *,
    public_key: WmsvrHardcodedPublicKey | rsa.RSAPublicKey | bytes | str | None = None,
    install_root: Path | None = None,
    session_key: bytes | None = None,
    seq: int = 1,
    word2: int = 0x0003,
    word4: int = 0x0003,
) -> tuple[WmsvrD1Frame, bytes, bytes]:
    """Build the standalone `AB5870 -> AB74A0` pre-auth control packet."""
    resolved_session_key = (
        session_key if session_key is not None else generate_wmsvr_d1_session_key()
    )
    resolved_public_key = public_key
    if resolved_public_key is None:
        finder = _resolve_wmsvr_hook(
            "find_wmsvr_hardcoded_public_key_by_digest",
            find_wmsvr_hardcoded_public_key_by_digest,
            _ORIG_FIND_KEY_BY_DIGEST,
        )
        resolved_public_key = finder(
            context.key_digest16,
            install_root=install_root,
        )
    if resolved_public_key is None:
        raise ValueError(
            "No hardcoded Wmsvr public key matched the current digest; pass `public_key=` explicitly."
        )
    wrapper = _resolve_wmsvr_hook(
        "wrap_wmsvr_d1_session_key",
        wrap_wmsvr_d1_session_key,
        _ORIG_WRAP_SESSION_KEY,
    )
    wrapped_session_key = wrapper(
        resolved_session_key,
        resolved_public_key,
    )
    frame = build_wmsvr_d1_encrypted_frame(
        build_wmsvr_d1_control_tlv(context),
        body_bytes=wrapped_session_key,
        session_key=resolved_session_key,
        seq=seq,
        word2=word2,
        word4=word4,
    )
    return frame, resolved_session_key, wrapped_session_key


def build_get_settings_tlv(
    *,
    version: int = DEFAULT_D1_KEY_VERSION,
    digest: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
) -> bytes:
    """Build the confirmed plaintext TLV slice for d1 `GET_SETTINGS`."""
    records = [
        (0x0001, struct.pack(">I", version & 0xFFFFFFFF)),
        (0x0002, normalize_d1_key_digest(digest)),
    ]
    return encode_tlv_envelope(records)


def build_get_settings_frame(
    *,
    version: int = DEFAULT_D1_KEY_VERSION,
    digest: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    seq: int = 0,
    signature: bytes = DEFAULT_D1_GET_SETTINGS_SIGNATURE,
    wrapped_session_key: bytes | None = None,
) -> WmsvrD1Frame:
    """Build the currently confirmed raw d1 `GET_SETTINGS` frame."""
    slice0 = build_get_settings_tlv(version=version, digest=digest)
    tail = signature if wrapped_session_key is None else wrapped_session_key
    if len(tail) != D1_KEY_EXCHANGE_BLOCK_LEN:
        raise ValueError(
            f"GET_SETTINGS slice1 must be {D1_KEY_EXCHANGE_BLOCK_LEN} bytes "
            f"(RSA-1024), got {len(tail)}"
        )
    header = WmsvrD1Header(
        word0=DEFAULT_D1_GET_SETTINGS_WORD0,
        word2=DEFAULT_D1_GET_SETTINGS_WORD2,
        word4=DEFAULT_D1_GET_SETTINGS_WORD4,
        seq=seq,
        len0=len(slice0),
        len1=len(tail),
    )
    return WmsvrD1Frame(header=header, slice0=slice0, slice1=tail)


def build_wmsvr_key_exchange_frame(
    *,
    key_version: int = DEFAULT_D1_KEY_VERSION,
    key_digest16: bytes = DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    session_key: bytes | None = None,
    public_key: WmsvrHardcodedPublicKey | rsa.RSAPublicKey | bytes | str | None = None,
    install_root: Path | None = None,
    seq: int = 0,
) -> tuple[WmsvrD1Frame, bytes]:
    """Build the `GET_SETTINGS` frame that hands the server *our* d1 session key."""
    resolved_key = session_key if session_key is not None else generate_wmsvr_d1_session_key()
    resolved_key = _require_wmsvr_d1_session_key(resolved_key)
    resolved_public_key = public_key
    if resolved_public_key is None:
        finder = _resolve_wmsvr_hook(
            "find_wmsvr_hardcoded_public_key_by_digest",
            find_wmsvr_hardcoded_public_key_by_digest,
            _ORIG_FIND_KEY_BY_DIGEST,
        )
        resolved_public_key = finder(
            key_digest16,
            install_root=install_root,
        )
    if resolved_public_key is None:
        raise ValueError(
            "No hardcoded Wmsvr public key matched the current digest "
            f"{key_digest16.hex()}; cannot wrap the session key."
        )
    wrapper = _resolve_wmsvr_hook(
        "wrap_wmsvr_d1_session_key",
        wrap_wmsvr_d1_session_key,
        _ORIG_WRAP_SESSION_KEY,
    )
    wrapped = wrapper(resolved_key, resolved_public_key)
    frame = build_get_settings_frame(
        version=key_version,
        digest=key_digest16,
        seq=seq,
        wrapped_session_key=wrapped,
    )
    return frame, resolved_key


# ---------------------------------------------------------------------------
# d1 frame parsing & raw socket I/O
# ---------------------------------------------------------------------------


def parse_d1_frame(data: bytes) -> WmsvrD1Frame:
    """Parse one raw d1 frame into header + split slices + remainder."""
    if len(data) < 9 or data[0] != 0xD1:
        raise ValueError("Not a d1 frame")

    word0 = struct.unpack_from(">H", data, 1)[0]
    word4 = struct.unpack_from(">H", data, 3)[0]
    word2 = struct.unpack_from(">H", data, 5)[0]
    seq = struct.unpack_from(">H", data, 7)[0]
    offset = 9

    extra16: int | None = None
    len0: int | None = None
    len1: int | None = None

    if word0 & D1_WORD0_HAS_EXTRA16:
        if offset + 2 > len(data):
            raise ValueError("Truncated d1 extra16")
        extra16 = struct.unpack_from(">H", data, offset)[0]
        offset += 2
    if word0 & D1_WORD0_HAS_LEN0:
        len0, offset = decode_leb128(data, offset)
    if word0 & D1_WORD0_HAS_LEN1:
        len1, offset = decode_leb128(data, offset)

    start = offset
    end0 = start + (len0 or 0)
    end1 = end0 + (len1 or 0)
    if end1 > len(data):
        raise ValueError("Truncated d1 frame body")

    return WmsvrD1Frame(
        header=WmsvrD1Header(
            word0=word0,
            word2=word2,
            word4=word4,
            seq=seq,
            extra16=extra16,
            len0=len0,
            len1=len1,
        ),
        slice0=data[start:end0],
        slice1=data[end0:end1],
        remainder=data[end1:],
    )


def describe_d1_frame(data: bytes) -> dict[str, Any]:
    """Return a compact parsed description for one d1 frame."""
    frame = parse_d1_frame(data)
    header = frame.header
    return {
        "word0": f"0x{header.word0:04x}",
        "frame_type": f"0x{header.frame_type:02x}",
        "word4": f"0x{header.word4:04x}",
        "word2": f"0x{header.word2:04x}",
        "seq": header.seq,
        "extra16": None if header.extra16 is None else f"0x{header.extra16:04x}",
        "len0": header.len0,
        "len1": header.len1,
        "slice0_hex": frame.slice0[:32].hex(),
        "slice1_hex": frame.slice1[:32].hex(),
        "remainder_len": len(frame.remainder),
    }


def parse_get_settings_response(data: bytes) -> WmsvrGetSettingsResponse:
    """Parse the currently confirmed metadata from a d1 `GET_SETTINGS` response."""
    frame = parse_d1_frame(data)
    key_version: int | None = None
    if frame.slice0:
        try:
            for tag, value in decode_tlv_envelope(frame.slice0):
                if tag == 0x0001 and len(value) == 4:
                    key_version = struct.unpack(">I", value)[0]
                    break
        except ValueError:
            key_version = None
    return WmsvrGetSettingsResponse(
        business_code=frame.header.extra16,
        key_version=key_version,
        key_blob=frame.slice1,
        frame=frame,
    )


def _recv_exactly(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Socket closed while receiving d1 frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_leb128(sock: socket.socket) -> bytes:
    parts = bytearray()
    while True:
        chunk = _recv_exactly(sock, 1)
        parts.extend(chunk)
        if (chunk[0] & 0x80) == 0:
            return bytes(parts)


def d1_socket_family(host: str) -> int:
    """Address family for a located d1 peer (IPv6 or IPv4)."""
    try:
        return socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return socket.AF_INET
    return infos[0][0] if infos else socket.AF_INET


def open_d1_socket(peer: WmsvrPeerCandidate, *, timeout: float) -> socket.socket:
    """Connect to one located d1 peer, honouring the peer's address family."""
    sock = socket.socket(d1_socket_family(peer.host), socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((peer.host, peer.port))
    except Exception:
        sock.close()
        raise
    return sock


def recv_d1_frame(sock: socket.socket, *, timeout: float | None = None) -> WmsvrD1Frame:
    """Receive one complete d1 frame from a socket using the confirmed header layout."""
    previous_timeout = sock.gettimeout()
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        fixed = _recv_exactly(sock, 9)
        if fixed[0] != 0xD1:
            raise ValueError("Not a d1 frame")
        word0 = struct.unpack_from(">H", fixed, 1)[0]

        extra = b""
        if word0 & D1_WORD0_HAS_EXTRA16:
            extra = _recv_exactly(sock, 2)

        len0_part = b""
        len1_part = b""
        len0 = 0
        len1 = 0
        if word0 & D1_WORD0_HAS_LEN0:
            len0_part = _recv_leb128(sock)
            len0, _ = decode_leb128(len0_part)
        if word0 & D1_WORD0_HAS_LEN1:
            len1_part = _recv_leb128(sock)
            len1, _ = decode_leb128(len1_part)

        payload = _recv_exactly(sock, len0 + len1)
        raw = fixed + extra + len0_part + len1_part + payload
        return parse_d1_frame(raw)
    finally:
        if timeout is not None:
            sock.settimeout(previous_timeout)


def send_d1_frame(sock: socket.socket, frame: WmsvrD1Frame | bytes) -> None:
    """Send a raw d1 frame through an already connected socket."""
    raw = frame.to_bytes() if isinstance(frame, WmsvrD1Frame) else frame
    sock.sendall(raw)


def exchange_get_settings(
    sock: socket.socket,
    *,
    request: WmsvrD1Frame | None = None,
    timeout: float | None = None,
) -> WmsvrGetSettingsResponse:
    """Send one `GET_SETTINGS` request on an already connected socket and parse one response."""
    outbound = request or build_get_settings_frame()
    sender = _resolve_wmsvr_hook("send_d1_frame", send_d1_frame, _ORIG_SEND_D1_FRAME)
    receiver = _resolve_wmsvr_hook("recv_d1_frame", recv_d1_frame, _ORIG_RECV_D1_FRAME)
    sender(sock, outbound)
    inbound = receiver(sock, timeout=timeout)
    return parse_get_settings_response(inbound.to_bytes())


def query_get_settings_peer(
    peer: WmsvrPeerCandidate,
    *,
    request: WmsvrD1Frame | None = None,
    timeout: float = 10.0,
) -> WmsvrGetSettingsResponse:
    """Connect to one d1 peer, send `GET_SETTINGS`, and parse the first response."""
    sock = socket.create_connection((peer.host, peer.port), timeout=timeout)
    try:
        exchanger = _resolve_wmsvr_hook(
            "exchange_get_settings",
            exchange_get_settings,
            _ORIG_EXCHANGE_GET_SETTINGS,
        )
        return exchanger(sock, request=request, timeout=timeout)
    finally:
        sock.close()


_ORIG_FIND_KEY_BY_DIGEST = find_wmsvr_hardcoded_public_key_by_digest
_ORIG_WRAP_SESSION_KEY = wrap_wmsvr_d1_session_key
_ORIG_SEND_D1_FRAME = send_d1_frame
_ORIG_RECV_D1_FRAME = recv_d1_frame
_ORIG_EXCHANGE_GET_SETTINGS = exchange_get_settings
