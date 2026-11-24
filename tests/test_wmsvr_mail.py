"""Tests for the product-grade Wmsvr mailbox path (`wmsvr_mail`).

Everything here is offline: the LZ4 container decoder, the reply parser, the
structured error mapping and the verified mark flow are exercised against
synthetic frames, so no network and no credentials are involved.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any, cast

import pytest

from mailmaster.wmsvr_mail import (
    COMPOSE_MAILER_EXT,
    ERROR_COMPOSE_ID_UNKNOWN,
    ERROR_LOGIN_CREDENTIAL_MISSING,
    ERROR_METHOD_REJECTED,
    ERROR_NOT_VERIFIED,
    ERROR_PART_NOT_FOUND,
    ERROR_READ_STREAM_INCOMPLETE,
    ERROR_SESSION_EXPIRED,
    ERROR_SOURCE_NOT_FOUND,
    METHOD_GET_MESSAGE_DATA,
    PART_SOURCE_HEAD,
    READ_MARKER_FIRST,
    READ_MARKER_LAST,
    READ_MARKER_MIDDLE,
    parse_read_frame_marker,
    parse_reply_numeric_code,
    WmsvrMailError,
    WmsvrMailSession,
    decode_lz4_block,
    decode_wmsvr_payload,
    parse_reply_code,
    parse_reply_method,
    raise_for_reply,
    strip_slice_padding,
)
from mailmaster import wmsvr as _w

# The masked reply the round-56 probe decoded, as the byte string the container
# carries. The remote id is a placeholder, exactly as the evidence log stores it.
SAMPLE_JSON = (
    b'[{"fid":1,"flags":{"read":true,"hasTag":true},"mid":"<RemoteId>","label0":0}]'
)
# Round 56's observed container header bytes: magic (8) + [0x26][u32le comp][u32le unc][u32le 0].
SAMPLE_HEADER = b"LZ4Block" + bytes.fromhex("265c0000005d00000000000000")


def lz4_literal_block(data: bytes) -> bytes:
    """Encode `data` as a valid LZ4 block that uses literals only."""
    out = bytearray()
    length = len(data)
    if length < 15:
        out.append(length << 4)
    else:
        out.append(0xF0)
        remaining = length - 15
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    out += data
    return bytes(out)


def lz4_block_with_match() -> tuple[bytes, bytes]:
    """A block that exercises the match-copy path: 8 literals + a 4-byte copy."""
    literals = b"abcdefgh"
    block = bytearray()
    block.append(len(literals) << 4)  # lit_len=8, match_len=0 -> copies 4 bytes
    block += literals
    block += len(literals).to_bytes(2, "little")  # offset back to the literals
    block += bytes([0x40]) + b"1234"  # final literals-only sequence (token 0x40)
    expected = literals + literals[:4] + b"1234"
    return bytes(block), expected


def test_decode_lz4_literal_block() -> None:
    payload = b"hello lz4"
    block = lz4_literal_block(payload)
    assert decode_lz4_block(block, len(payload)) == payload


def test_decode_lz4_long_literal_block() -> None:
    payload = bytes(range(256)) * 2
    block = lz4_literal_block(payload)
    assert decode_lz4_block(block, len(payload)) == payload


def test_decode_lz4_match_copy() -> None:
    block, expected = lz4_block_with_match()
    assert decode_lz4_block(block, len(expected)) == expected


def test_decode_lz4_rejects_bad_offset() -> None:
    block, _ = lz4_block_with_match()
    corrupted = bytearray(block)
    # The 2-byte offset sits right after the literals: point it past the output.
    corrupted[1 + 8] = 0xFF
    corrupted[1 + 8 + 1] = 0xFF
    assert decode_lz4_block(bytes(corrupted), 64) is None


def test_decode_lz4_rejects_truncated_block() -> None:
    block = lz4_literal_block(b"payload")
    assert decode_lz4_block(block[:-2], 7) is None


def test_decode_lz4_rejects_size_mismatch() -> None:
    block = lz4_literal_block(b"payload")
    assert decode_lz4_block(block, 8) is None


def test_decode_wmsvr_payload_container() -> None:
    block = lz4_literal_block(SAMPLE_JSON)
    header = b"LZ4Block" + bytes([0x26]) + len(block).to_bytes(4, "little") + len(SAMPLE_JSON).to_bytes(
        4, "little"
    ) + b"\x00" * 4
    decoded, meta = decode_wmsvr_payload(header + block + b"LZ4Block" + b"\x00" * 15)
    assert decoded == SAMPLE_JSON
    assert meta["container"] is True
    assert meta["compressed_len"] == len(block)
    assert meta["uncompressed_len"] == len(SAMPLE_JSON)
    assert meta["trailer_len"] == 8 + 15


def test_round56_container_header_layout_is_read_as_sizes() -> None:
    """The header bytes observed in round 56 parse as [type][u32le comp][u32le unc][u32le 0]."""
    decoded, meta = decode_wmsvr_payload(SAMPLE_HEADER)
    assert decoded is None  # no block behind the header in this fixture
    assert meta["container"] is True
    assert meta["compressed_len"] == 0x5C  # 92, the round-56 compressed size
    assert meta["uncompressed_len"] == 0x5D  # 93, the round-56 decoded size
    assert meta["error"] == "lz4_block_invalid"


def test_decode_wmsvr_payload_plain_json_with_pkcs7() -> None:
    pad = 16 - (len(SAMPLE_JSON) % 16)
    plain = SAMPLE_JSON + bytes([pad]) * pad
    decoded, meta = decode_wmsvr_payload(plain)
    assert decoded == SAMPLE_JSON
    assert meta == {"container": False, "plain": True}


def test_decode_wmsvr_payload_garbage() -> None:
    decoded, meta = decode_wmsvr_payload(b"\xff\xfe\xfd" * 4)
    assert decoded is None
    assert meta["container"] is False


def test_strip_slice_padding_only_strips_full_pad_blocks() -> None:
    assert strip_slice_padding(b"data" + b"\x0c" * 12) == b"data"
    # 0x0b bytes that are not a full padding block stay untouched.
    assert strip_slice_padding(b"data\x0b") == b"data\x0b"


def test_parse_reply_code_and_method() -> None:
    from mailmaster.wmsvr import encode_tlv_envelope

    slice0 = encode_tlv_envelope([(0x0100, b"mbox:updateMessageInfos")])
    slice0 += b'\x01Q\x01\x00\x01R\x0f{"code":"S_OK"}' + b"\x0c" * 12
    assert parse_reply_code(slice0) == "S_OK"
    assert parse_reply_method(slice0) == "mbox:updateMessageInfos"
    assert parse_reply_code(b"nothing here") is None


def test_raise_for_reply_maps_server_codes() -> None:
    raise_for_reply({"code": "S_OK"}, method="wzp:getMessageInfos")  # no raise
    with pytest.raises(WmsvrMailError) as excinfo:
        raise_for_reply({"code": "FA_INVALID_SESSION"}, method="wzp:getMessageInfos")
    assert excinfo.value.code == ERROR_SESSION_EXPIRED
    assert excinfo.value.details["reply_code"] == "FA_INVALID_SESSION"
    with pytest.raises(WmsvrMailError) as unknown:
        raise_for_reply({"code": "FA_UNSUPPORT_RECALL"}, method="mbox:updateMessageInfos")
    assert unknown.value.code == "wmsvr_method_rejected"


class _FakeSession(WmsvrMailSession):
    """A session whose transport is a scripted flag sequence."""

    def __init__(self, flag_sequence: list[dict]) -> None:
        self._flag_sequence = list(flag_sequence)
        self._folder_sequence: list[int] = []
        self._folder_writes: list[tuple[list[str], int]] = []
        self.writes: list[tuple[list[str], bool]] = []
        self.login_context = cast(Any, None)
        self.session = cast(Any, None)
        self.session_key = b"\x00" * 16
        self.client_id = "test"
        self.sock = cast(Any, None)
        self.peer = cast(Any, None)

    def get_message_flags(self, ids):
        return [dict(self._flag_sequence.pop(0))]

    def set_message_read(self, ids, *, read):
        self.writes.append((list(ids), read))
        return {"code": "S_OK"}


def test_set_message_folder_verified_accepts_a_real_move() -> None:
    """The move body is `attrs.fid`; the read-back must show the new folder."""
    session = _FakeSession([])
    session._folder_sequence = [1, 6702521]
    session._folder_writes = []

    def get_message_folders(ids):
        return [session._folder_sequence.pop(0)]

    def set_message_folder(ids, *, fid):
        session._folder_writes.append((list(ids), fid))
        return {"code": "S_OK"}

    session.get_message_folders = get_message_folders  # type: ignore[method-assign]
    session.set_message_folder = set_message_folder  # type: ignore[method-assign]

    result = session.set_message_folder_verified(["755:x"], fid=6702521)
    assert result["state_change_verified"] is True
    assert result["remote_folders_before"] == [1]
    assert result["remote_folders_after"] == [6702521]
    assert result["target_fid"] == 6702521
    assert session._folder_writes == [(["755:x"], 6702521)]


def test_set_message_folder_verified_rejects_a_silent_move() -> None:
    session = _FakeSession([])
    session._folder_sequence = [1, 1]
    session._folder_writes = []

    session.get_message_folders = lambda ids: [session._folder_sequence.pop(0)]  # type: ignore[method-assign]
    session.set_message_folder = lambda ids, *, fid: {"code": "S_OK"}  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.set_message_folder_verified(["755:x"], fid=6702521)
    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["remote_folders_after"] == [1]


def test_parse_reply_numeric_code() -> None:
    sample = bytes.fromhex("0aeb") + b'{"code":1}' + bytes.fromhex("0606")
    assert parse_reply_numeric_code(sample) == 1
    assert parse_reply_numeric_code(b'{"code":"S_OK"}') is None


def test_set_message_read_verified_accepts_a_real_change() -> None:
    session = _FakeSession([{"read": True, "hasTag": True}, {"hasTag": True}])
    result = session.set_message_read_verified(["755:x"], read=False)
    assert result["state_change_verified"] is True
    assert result["remote_flags_before"] == [{"read": True, "hasTag": True}]
    assert result["remote_flags_after"] == [{"hasTag": True}]
    assert session.writes == [(["755:x"], False)]


def test_set_message_read_verified_rejects_a_silent_write() -> None:
    session = _FakeSession([{"read": True}, {"read": True}])
    with pytest.raises(WmsvrMailError) as excinfo:
        session.set_message_read_verified(["755:x"], read=False)
    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["state_change_verified"] is False


def test_set_message_read_verified_honours_expected_before() -> None:
    session = _FakeSession([{"hasTag": True}, {"read": True}])
    with pytest.raises(WmsvrMailError):
        session.set_message_read_verified(["755:x"], read=True, expected_before={"755:x": True})


def test_open_session_requires_a_password() -> None:
    from mailmaster.wmsvr import WmsvrLoginContext, WmsvrPeerCandidate
    from mailmaster.wmsvr_mail import open_wmsvr_mail_session

    context = WmsvrLoginContext(
        account="user@163.com",
        user="user@163.com",
        password="",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    with pytest.raises(WmsvrMailError) as excinfo:
        open_wmsvr_mail_session(context, master_session_token="token")
    assert excinfo.value.code == ERROR_LOGIN_CREDENTIAL_MISSING


def test_open_session_requires_a_token() -> None:
    from mailmaster.wmsvr import WmsvrLoginContext, WmsvrPeerCandidate
    from mailmaster.wmsvr_mail import open_wmsvr_mail_session

    context = WmsvrLoginContext(
        account="user@163.com",
        user="user@163.com",
        password="secret",
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        peer_candidates=[WmsvrPeerCandidate(host="10.0.0.1", port=16201)],
    )
    with pytest.raises(WmsvrMailError) as excinfo:
        open_wmsvr_mail_session(context, master_session_token="")
    assert excinfo.value.code == "wmsvr_bootstrap_missing"


def test_reply_code_regex_does_not_leak_into_error_details() -> None:
    """Errors carry codes and shapes, never credentials or session material."""
    with pytest.raises(WmsvrMailError) as excinfo:
        raise_for_reply({"code": "FA_MAIL_NOT_FOUND"}, method="wzp:getMessageInfos")
    blob = json.dumps(excinfo.value.to_dict())
    assert "token" not in blob.lower()
    assert "cookie" not in blob.lower()


def test_delete_messages_builds_delete_type_and_ids() -> None:
    """Round 59: `mbox:deleteMessages` carries `deleteType` + `ids` (batch/account only)."""
    session = _FakeSession([])
    calls: list[tuple[str, dict | None]] = []

    def fake_request(method, body=None):
        calls.append((method, body))
        return {"code": "S_OK"}

    session.request = fake_request  # type: ignore[method-assign]
    reply = session.delete_messages(["755:x", "722:y"])
    assert reply["code"] == "S_OK"
    assert calls == [("mbox:deleteMessages", {"deleteType": "batch", "ids": ["755:x", "722:y"]})]

    with pytest.raises(ValueError):
        session.delete_messages([])
    with pytest.raises(ValueError):
        session.delete_messages(["755:x"], delete_type="nonsense")


def test_delete_messages_verified_accepts_a_removed_message() -> None:
    """A read-back that no longer resolves the id is the round-59 verified removal."""
    session = _FakeSession([])
    reads = [
        {"755:x": {"mid": "755:x", "fid": 7}},
        {},
    ]
    codes = ["S_OK", "S_PARTIAL_OK"]
    session._records_by_mid = lambda ids, *, fields=(): (reads.pop(0), {"code": codes.pop(0)})  # type: ignore[method-assign]
    session.delete_messages = lambda ids, *, delete_type="batch": {"code": "S_OK"}  # type: ignore[method-assign]

    result = session.delete_messages_verified(["755:x"])
    assert result["state_change_verified"] is True
    assert result["remote_folders_before"] == [7]
    assert result["remote_folders_after"] == [None]
    assert result["gone"] == [True]
    assert result["delete_type"] == "batch"
    assert result["read_back_code"] == "S_PARTIAL_OK"


def test_delete_messages_verified_rejects_a_silent_delete() -> None:
    """`S_OK` plus a read-back that still shows the folder is not a verified delete."""
    session = _FakeSession([])
    reads = [
        {"755:x": {"mid": "755:x", "fid": 7}},
        {"755:x": {"mid": "755:x", "fid": 7}},
    ]
    session._records_by_mid = lambda ids, *, fields=(): (reads.pop(0), {"code": "S_OK"})  # type: ignore[method-assign]
    session.delete_messages = lambda ids, *, delete_type="batch": {"code": "S_OK"}  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.delete_messages_verified(["755:x"])
    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["remote_folders_after"] == [7]


def test_delete_messages_verified_accepts_an_already_absent_message() -> None:
    """An id the read-back never resolves before or after the delete reached the end state."""
    session = _FakeSession([])
    reads = [{}, {}]
    session._records_by_mid = lambda ids, *, fields=(): (reads.pop(0), {"code": "S_PARTIAL_OK"})  # type: ignore[method-assign]
    session.delete_messages = lambda ids, *, delete_type="batch": {"code": "S_OK"}  # type: ignore[method-assign]

    result = session.delete_messages_verified(["755:x"])
    assert result["state_change_verified"] is True
    assert result["already_absent"] == [True]
    assert result["gone"] == [False]
    assert result["remote_folders_before"] == [None]
    assert result["remote_folders_after"] == [None]


# The two compose bodies of round 62. Recipients, the account and the ids are
# placeholders here; the real ones only ever appear in the live logs, sanitized.
SENT_REPLY = {
    "code": "S_OK",
    "records": {
        "deliveryMsgType": 1,
        "saveSentCopy": True,
        "sentTInfo": "<TInfo>",
        "account": "<account>",
        "savedSent": {"imapFolder": "Sent Items", "msid": 721, "mid": "<SentMid>"},
    },
}


# The `send_mail` result shape (the reply's `savedSent` is lifted to the top level).
SENT_RESULT = {
    "transport": "wmsvr-private",
    "method": "mbox:compose",
    "compose_id": "compose-1",
    "code": "S_OK",
    "saved_sent": {"imapFolder": "Sent Items", "msid": 721, "mid": "<SentMid>"},
}


def test_create_compose_requires_a_compose_id() -> None:
    """A reply without a compose object cannot be delivered against."""
    session = _FakeSession([])
    session.request = lambda method, body=None: {"code": "S_OK", "records": []}  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.create_compose()
    assert excinfo.value.code == ERROR_METHOD_REJECTED
    assert excinfo.value.details["action"] == "continue"


def test_send_mail_builds_the_two_compose_bodies() -> None:
    """Round 62: `action:"continue"` mints the compose id, `action:"deliver"` sends."""
    session = _FakeSession([])
    calls: list[tuple[str, dict]] = []
    replies = [
        {"code": "S_OK", "records": {"id": "compose-1", "subject": "", "isHtml": True}},
        SENT_REPLY,
    ]

    def request(method, body=None):
        calls.append((method, dict(body or {})))
        return replies.pop(0)

    session.request = request  # type: ignore[method-assign]

    result = session.send_mail(
        account="<account>", to=["<to>"], subject="hello", html_body="<p>hi</p>"
    )

    assert [method for method, _ in calls] == ["mbox:compose", "mbox:compose"]
    assert calls[0][1] == {
        "action": "continue",
        "returnInfo": True,
        "xMailerExt": COMPOSE_MAILER_EXT,
    }
    delivered = calls[1][1]
    assert delivered["action"] == "deliver"
    assert delivered["id"] == "compose-1"
    assert delivered["attrs"] == {
        "account": "<account>",
        "to": ["<to>"],
        "cc": [],
        "bcc": [],
        "content": "<p>hi</p>",
        "isHtml": True,
        "requestReadReceipt": False,
        "saveSentCopy": True,
        "showOneRcpt": False,
        "subject": "hello",
    }
    assert delivered["notReturn"] == ["content", "headers", "attachments"]
    assert delivered["returnSavedSent"] is True
    assert result["compose_id"] == "compose-1"
    assert result["code"] == "S_OK"
    assert result["saved_sent"]["mid"] == "<SentMid>"
    assert result["transport"] == "wmsvr-private"


def test_send_mail_reuses_a_supplied_compose_id() -> None:
    """One compose object can be delivered explicitly (mirrors the client's re-use)."""
    session = _FakeSession([])
    bodies: list[dict] = []
    session.request = lambda method, body=None: (  # type: ignore[method-assign]
        bodies.append(dict(body or {})) or SENT_REPLY
    )

    session.send_mail(account="<account>", to=["<to>"], text_body="plain", compose_id="compose-9")

    assert len(bodies) == 1
    assert bodies[0]["id"] == "compose-9"
    assert bodies[0]["attrs"]["content"] == "plain"
    assert bodies[0]["attrs"]["isHtml"] is False


def test_send_mail_requires_a_body_and_a_recipient() -> None:
    session = _FakeSession([])

    with pytest.raises(ValueError):
        session.send_mail(account="<account>", to=[], html_body="<p>x</p>")
    with pytest.raises(ValueError):
        session.send_mail(account="<account>", to=["<to>"])


def test_send_mail_verified_runs_the_two_step_form_end_to_end() -> None:
    """The shipped path: mint the compose, deliver it, read the reported copy back."""
    session = _FakeSession([])
    calls: list[tuple[str, dict]] = []
    replies = [
        {"code": "S_OK", "records": {"id": "compose-7", "subject": "", "isHtml": True}},
        SENT_REPLY,
    ]

    def request(method, body=None):
        calls.append((method, dict(body or {})))
        return replies.pop(0)

    session.request = request  # type: ignore[method-assign]
    session._records_by_mid = lambda ids, *, fields=None: (  # type: ignore[method-assign]
        {"721:<SentMid>": {"mid": "721:<SentMid>", "fid": 3, "subject": "hello"}},
        {"code": "S_OK"},
    )

    result = session.send_mail_verified(
        account="<account>", to=["<to>"], subject="hello", text_body="hi"
    )

    assert [method for method, _ in calls] == ["mbox:compose", "mbox:compose"]
    assert calls[1][1]["id"] == "compose-7"
    assert calls[1][1]["attrs"]["subject"] == "hello"
    assert result["compose_id"] == "compose-7"
    assert result["sent_id"] == "721:<SentMid>"
    assert result["readback_fallback"] is False
    assert result["state_change_verified"] is True


def test_send_mail_verified_accepts_the_reported_sent_copy() -> None:
    """The delivery reply hands back the sent copy's id, which must resolve in-session."""
    session = _FakeSession([])
    session.send_mail = lambda **kwargs: dict(SENT_RESULT)  # type: ignore[method-assign]
    reads: list[list[str]] = []

    def records_by_mid(ids, *, fields=None):
        reads.append(list(ids))
        return {"721:<SentMid>": {"mid": "721:<SentMid>", "fid": 3, "subject": "hello"}}, {"code": "S_OK"}

    session._records_by_mid = records_by_mid  # type: ignore[method-assign]

    result = session.send_mail_verified(
        account="<account>", to=["<to>"], subject="hello", text_body="hi"
    )

    assert reads == [["721:<SentMid>"]]
    assert result["sent_id"] == "721:<SentMid>"
    assert result["sent_folder_fid"] == 3
    assert result["sent_subject"] == "hello"
    assert result["readback_fallback"] is False
    assert result["state_change_verified"] is True


def test_send_mail_verified_rejects_a_missing_sent_copy() -> None:
    """A delivery whose sent copy does not resolve is a state change we cannot prove."""
    session = _FakeSession([])
    session.send_mail = lambda **kwargs: dict(SENT_RESULT)  # type: ignore[method-assign]
    session._records_by_mid = lambda ids, *, fields=None: (  # type: ignore[method-assign]
        {},
        {"code": "S_PARTIAL_OK"},
    )

    with pytest.raises(WmsvrMailError) as excinfo:
        session.send_mail_verified(
            account="<account>", to=["<to>"], subject="hello", text_body="hi"
        )
    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["sent_id"] == "721:<SentMid>"
    assert excinfo.value.details["state_change_verified"] is False
    assert excinfo.value.details["read_back_code"] == "S_PARTIAL_OK"


def test_send_mail_verified_rejects_a_wrong_subject() -> None:
    """The id resolving with someone else's subject is not proof of this send."""
    session = _FakeSession([])
    session.send_mail = lambda **kwargs: dict(SENT_RESULT)  # type: ignore[method-assign]
    session._records_by_mid = lambda ids, *, fields=None: (  # type: ignore[method-assign]
        {"721:<SentMid>": {"mid": "721:<SentMid>", "fid": 3, "subject": "another mail"}},
        {"code": "S_OK"},
    )

    with pytest.raises(WmsvrMailError) as excinfo:
        session.send_mail_verified(
            account="<account>", to=["<to>"], subject="hello", text_body="hi"
        )
    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["sent_subject"] == "another mail"


def test_send_mail_verified_falls_back_to_the_sent_folder_listing() -> None:
    """Without `savedSent` the client's own post-send listing (`fids:[3]`) is the fallback."""
    session = _FakeSession([])
    session.send_mail = lambda **kwargs: {"code": "S_OK", "saved_sent": {}}  # type: ignore[method-assign]
    listings: list[dict] = []

    def request_lenient(method, body=None):
        listings.append({"method": method, "body": dict(body or {})})
        return {"code": "S_OK", "records": ["721:<SentMid>", "721:<Older>"]}

    session.request_lenient = request_lenient  # type: ignore[method-assign]
    session._records_by_mid = lambda ids, *, fields=None: (  # type: ignore[method-assign]
        {
            "721:<SentMid>": {"mid": "721:<SentMid>", "fid": 3, "subject": "hello"},
            "721:<Older>": {"mid": "721:<Older>", "fid": 3, "subject": "older mail"},
        },
        {"code": "S_OK"},
    )

    result = session.send_mail_verified(
        account="<account>", to=["<to>"], subject="hello", text_body="hi"
    )

    assert listings == [
        {"method": "wzp:listMessages", "body": {"desc": True, "fids": [3], "limit": 5}}
    ]
    assert result["sent_id"] == "721:<SentMid>"
    assert result["readback_fallback"] is True
    assert result["state_change_verified"] is True


# The round-66/69 `action:"save"` reply: `draftId` is the `<msid>:<mid>` remote id of the
# new draft. Placeholders here; the live ids only ever appear in the sanitized logs.
SAVE_REPLY = {
    "code": "S_OK",
    "records": {
        "deliveryMsgType": 3,
        "saveSentCopy": True,
        "account": "<account>",
        "id": "compose-1",
        "draftId": "821:<DraftMid>",
    },
}

# The `attrs` block both compose actions send (round 62 deliver, round 69 save).
DRAFT_ATTRS = {
    "account": "<account>",
    "to": ["<to>"],
    "cc": [],
    "bcc": [],
    "content": "draft body",
    "isHtml": False,
    "requestReadReceipt": False,
    "saveSentCopy": True,
    "showOneRcpt": False,
    "subject": "draft subject",
}


def test_save_draft_builds_the_save_body() -> None:
    """`action:"save"` reuses the deliver body and the minted compose id (rounds 66/69)."""
    session = _FakeSession([])
    calls: list[tuple[str, dict]] = []
    replies = [{"code": "S_OK", "records": {"id": "compose-1"}}, SAVE_REPLY]

    def request_lenient(method, body=None):
        calls.append((method, dict(body or {})))
        return replies.pop(0)

    session.request_lenient = request_lenient  # type: ignore[method-assign]

    result = session.save_draft(
        account="<account>", to=["<to>"], subject="draft subject", text_body="draft body"
    )

    assert [method for method, _ in calls] == ["mbox:compose", "mbox:compose"]
    assert calls[0][1] == {
        "action": "continue",
        "returnInfo": True,
        "xMailerExt": COMPOSE_MAILER_EXT,
    }
    saved = calls[1][1]
    assert saved["action"] == "save"
    assert saved["id"] == "compose-1"
    assert saved["attrs"] == DRAFT_ATTRS
    assert saved["notReturn"] == ["content", "headers", "attachments"]
    assert result["action"] == "save"
    assert result["code"] == "S_OK"
    assert result["draft_id"] == "821:<DraftMid>"
    assert result["compose_id"] == "compose-1"
    assert result["transport"] == "wmsvr-private"


def test_save_draft_requires_a_draft_id() -> None:
    """A save reply without `draftId` means the write did not happen."""
    session = _FakeSession([])
    replies = [{"code": "S_OK", "records": {"id": "compose-1"}}, {"code": "S_OK", "records": {}}]
    session.request_lenient = lambda method, body=None: replies.pop(0)  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.save_draft(account="<account>", to=["<to>"], subject="s", text_body="b")

    assert excinfo.value.code == ERROR_METHOD_REJECTED
    assert excinfo.value.details["action"] == "save"


def test_save_draft_requires_a_recipient_and_a_body() -> None:
    session = _FakeSession([])

    with pytest.raises(ValueError):
        session.save_draft(account="<account>", to=[], text_body="draft body")
    with pytest.raises(ValueError):
        session.save_draft(account="<account>", to=["<to>"])


def test_save_draft_verified_accepts_a_resolved_draft() -> None:
    """The reply's `draftId` must resolve in the same session (round 70 productization)."""
    session = _FakeSession([])
    session.save_draft = lambda **kwargs: {"code": "S_OK", "draft_id": "821:<DraftMid>"}  # type: ignore[method-assign]
    asked: list[tuple] = []

    def records_by_mid(ids, *, fields=None):
        asked.append((list(ids), tuple(fields or ())))
        return (
            {
                "821:<DraftMid>": {
                    "mid": "821:<DraftMid>",
                    "fid": 2,
                    "subject": "draft subject",
                    "size": 675,
                }
            },
            {"code": "S_OK"},
        )

    session._records_by_mid = records_by_mid  # type: ignore[method-assign]

    result = session.save_draft_verified(
        account="<account>", to=["<to>"], subject="draft subject", text_body="draft body"
    )

    assert asked == [(["821:<DraftMid>"], ("id", "fid", "subject", "size"))]
    assert result["draft_folder_fid"] == 2
    assert result["draft_size"] == 675
    assert result["draft_subject"] == "draft subject"
    assert result["read_back_code"] == "S_OK"
    assert result["readback_fallback"] is False
    assert result["state_change_verified"] is True


def test_save_draft_verified_rejects_a_draft_that_does_not_resolve() -> None:
    session = _FakeSession([])
    session.save_draft = lambda **kwargs: {"code": "S_OK", "draft_id": "821:<DraftMid>"}  # type: ignore[method-assign]
    session._records_by_mid = lambda ids, *, fields=None: ({}, {"code": "S_PARTIAL_OK"})  # type: ignore[method-assign]
    session.request_lenient = lambda method, body=None: {"code": "S_OK", "records": []}  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.save_draft_verified(
            account="<account>", to=["<to>"], subject="draft subject", text_body="draft body"
        )

    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["state_change_verified"] is False
    assert excinfo.value.details["draft_id"] == "821:<DraftMid>"


def test_save_draft_verified_falls_back_to_the_drafts_folder_listing() -> None:
    """A draft id that does not resolve is still confirmed by the `fids:[2]` listing."""
    session = _FakeSession([])
    session.save_draft = lambda **kwargs: {"code": "S_OK", "draft_id": "821:<Missing>"}  # type: ignore[method-assign]
    listings: list[dict] = []

    def records_by_mid(ids, *, fields=None):
        if list(ids) == ["821:<Missing>"]:
            return {}, {"code": "S_PARTIAL_OK"}
        return (
            {
                "821:<DraftMid>": {
                    "mid": "821:<DraftMid>",
                    "fid": 2,
                    "subject": "draft subject",
                    "size": 675,
                },
                "821:<Older>": {
                    "mid": "821:<Older>",
                    "fid": 2,
                    "subject": "older draft",
                    "size": 640,
                },
            },
            {"code": "S_OK"},
        )

    def request_lenient(method, body=None):
        listings.append({"method": method, "body": dict(body or {})})
        return {"code": "S_OK", "records": ["821:<DraftMid>", "821:<Older>"]}

    session._records_by_mid = records_by_mid  # type: ignore[method-assign]
    session.request_lenient = request_lenient  # type: ignore[method-assign]

    result = session.save_draft_verified(
        account="<account>", to=["<to>"], subject="draft subject", text_body="draft body"
    )

    assert listings == [
        {"method": "wzp:listMessages", "body": {"desc": True, "fids": [2], "limit": 5}}
    ]
    assert result["draft_id"] == "821:<DraftMid>"
    assert result["readback_fallback"] is True
    assert result["state_change_verified"] is True


def test_save_draft_with_a_compose_id_updates_that_draft() -> None:
    """An existing compose id means update: one request, no `continue`, `mode="update"` (round 72)."""
    session = _FakeSession([])
    calls: list[tuple[str, dict]] = []

    def request_lenient(method, body=None):
        calls.append((method, dict(body or {})))
        return SAVE_REPLY

    session.request_lenient = request_lenient  # type: ignore[method-assign]

    result = session.save_draft(
        account="<account>",
        to=["<to>"],
        subject="draft subject",
        text_body="draft body",
        compose_id="compose-existing",
    )

    # the compose object is NOT minted again - the caller's id is posted verbatim
    assert [method for method, _ in calls] == ["mbox:compose"]
    assert calls[0][1]["action"] == "save"
    assert calls[0][1]["id"] == "compose-existing"
    assert calls[0][1]["attrs"] == DRAFT_ATTRS
    assert result["mode"] == "update"
    assert result["compose_id"] == "compose-existing"
    assert result["draft_id"] == "821:<DraftMid>"


def test_save_draft_without_a_compose_id_reports_create() -> None:
    """The default form still mints a compose object and reports `mode="create"`."""
    session = _FakeSession([])
    replies = [{"code": "S_OK", "records": {"id": "compose-1"}}, SAVE_REPLY]
    session.request_lenient = lambda method, body=None: replies.pop(0)  # type: ignore[method-assign]

    result = session.save_draft(
        account="<account>", to=["<to>"], subject="draft subject", text_body="draft body"
    )

    assert result["mode"] == "create"
    assert result["compose_id"] == "compose-1"


def test_save_draft_verified_forwards_the_compose_id() -> None:
    """The verified path must carry `compose_id` through, or the CLI could never update a draft."""
    session = _FakeSession([])
    seen: list[dict] = []

    def save_draft(**kwargs):
        seen.append(dict(kwargs))
        return {"code": "S_OK", "draft_id": "821:<DraftMid>", "mode": kwargs.get("compose_id") and "update"}

    session.save_draft = save_draft  # type: ignore[method-assign]

    def records_by_mid(ids, *, fields=None):
        return (
            {"821:<DraftMid>": {"mid": "821:<DraftMid>", "fid": 2, "subject": "draft subject", "size": 719}},
            {"code": "S_OK"},
        )

    session._records_by_mid = records_by_mid  # type: ignore[method-assign]

    result = session.save_draft_verified(
        account="<account>",
        to=["<to>"],
        subject="draft subject",
        text_body="draft body",
        compose_id="compose-existing",
    )

    assert seen[0]["compose_id"] == "compose-existing"
    assert seen[0]["text_body"] == "draft body"
    assert result["mode"] == "update"
    assert result["draft_size"] == 719
    assert result["state_change_verified"] is True


# --- round 75: the stale-composeId shape (`FS_UD0108`, no `draftId`, success-marked word0) ---------

RECREATED_REPLY = {
    "code": "FS_UD0108",
    "word0": 62496,
    "records": {
        "code": "FS_UD0108",
        "id": "compose-stale",
        "subject": "draft subject",
        "content": "draft body",
        "isHtml": False,
        "saveSentCopy": True,
        "deliveryMsgType": 3,
        "savedDate": "2026-10-16 14:05:09",
        "modifiedDate": "2026-10-16 14:05:09",
    },
}


def test_save_draft_reports_a_recreated_draft_instead_of_a_rejection() -> None:
    """Round 74: a deleted draft's composeId still writes, and the reply is a status, not a verdict."""
    session = _FakeSession([])
    replies = [RECREATED_REPLY]
    session.request_lenient = lambda method, body=None: replies.pop(0)  # type: ignore[method-assign]

    result = session.save_draft(
        account="<account>",
        to=["<to>"],
        subject="draft subject",
        text_body="draft body",
        compose_id="compose-stale",
    )

    assert result["recreated"] is True
    assert result["draft_id"] is None
    assert result["code"] == "FS_UD0108"
    assert result["mode"] == "update"
    assert result["compose_id"] == "compose-stale"


def test_save_draft_reports_an_unrecognised_compose_id_as_such() -> None:
    """Round 76: `FA_ID_NOT_FOUND` covers "never issued" and "expired", so it gets its own code."""
    session = _FakeSession([])
    replies = [{"code": "FA_ID_NOT_FOUND", "word0": 57376, "records": None}]
    session.request_lenient = lambda method, body=None: replies.pop(0)  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.save_draft(
            account="<account>",
            to=["<to>"],
            subject="draft subject",
            text_body="draft body",
            compose_id="compose-never-issued",
        )

    assert excinfo.value.code == ERROR_COMPOSE_ID_UNKNOWN
    assert "expired" in excinfo.value.message
    assert excinfo.value.details["code"] == "FA_ID_NOT_FOUND"
    assert excinfo.value.details["compose_id_supplied"] is True


def test_save_draft_keeps_the_generic_error_for_other_unknown_codes() -> None:
    """Only `FA_ID_NOT_FOUND` gets the dedicated code; anything else stays a plain rejection."""
    session = _FakeSession([])
    replies = [{"code": "FA_SOMETHING_NEW", "word0": 1234, "records": None}]
    session.request_lenient = lambda method, body=None: replies.pop(0)  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.save_draft(
            account="<account>",
            to=["<to>"],
            subject="draft subject",
            text_body="draft body",
            compose_id="compose-1",
        )

    assert excinfo.value.code == ERROR_METHOD_REJECTED
    assert excinfo.value.details["reply_code"] == "FA_SOMETHING_NEW"


def test_save_draft_verified_resolves_a_recreated_draft_from_the_folder() -> None:
    """A recreated save has no id in the reply, so the drafts folder supplies it (round 75)."""
    session = _FakeSession([])
    session.save_draft = lambda **kwargs: {  # type: ignore[method-assign]
        "code": "FS_UD0108",
        "recreated": True,
        "draft_id": None,
        "subject": "draft subject",
    }
    listings: list[dict] = []
    asked: list[tuple] = []

    def records_by_mid(ids, *, fields=None):
        asked.append((list(ids), tuple(fields or ())))
        return (
            {"821:<NewDraftMid>": {"mid": "821:<NewDraftMid>", "fid": 2, "subject": "draft subject",
                                   "size": 833}},
            {"code": "S_OK"},
        )

    def request_lenient(method, body=None):
        listings.append({"method": method, "body": dict(body or {})})
        return {"code": "S_OK", "records": ["821:<NewDraftMid>", "821:<Older>"]}

    session._records_by_mid = records_by_mid  # type: ignore[method-assign]
    session.request_lenient = request_lenient  # type: ignore[method-assign]
    session.create_compose = lambda: {"id": "compose-minted"}  # type: ignore[method-assign]

    result = session.save_draft_verified(
        account="<account>",
        to=["<to>"],
        subject="draft subject",
        text_body="draft body",
        compose_id="compose-stale",
    )

    assert listings == [
        {"method": "wzp:listMessages", "body": {"desc": True, "fids": [2], "limit": 5}}
    ]
    assert asked == [(["821:<NewDraftMid>", "821:<Older>"], ("id", "fid", "subject", "size"))]
    assert result["recreated"] is True
    assert result["draft_id"] == "821:<NewDraftMid>"
    assert result["readback_fallback"] is True
    assert result["state_change_verified"] is True
    assert result["draft_size"] == 833


def test_save_draft_verified_refuses_to_call_an_unfindable_recreated_draft_a_success() -> None:
    """If the folder does not hold it, the write stays unverified - never a silent success."""
    session = _FakeSession([])
    session.save_draft = lambda **kwargs: {  # type: ignore[method-assign]
        "code": "FS_UD0108",
        "recreated": True,
        "draft_id": None,
        "subject": "draft subject",
    }
    session.request_lenient = lambda method, body=None: {"code": "S_OK", "records": []}  # type: ignore[method-assign]

    with pytest.raises(WmsvrMailError) as excinfo:
        session.save_draft_verified(
            account="<account>",
            to=["<to>"],
            subject="draft subject",
            text_body="draft body",
            compose_id="compose-stale",
        )

    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["recreated"] is True


# ---------------------------------------------------------------------------
# The read path (rounds 92/93): `wzpm:getMessageData`


# The 28 B verdict the server answers a slot it cannot serve with (round 93, observed
# byte-identical in every miss).
PART_NOT_FOUND_JSON = b'{"code":"FA_PART_NOT_FOUND"}'
SOURCE_BYTES = b"Received: from <RemoteId>\r\nSubject: <redacted>\r\n\r\nbody\r\n"
HTML_BYTES = b"<!DOCTYPE html><html><body>hi</body></html>"


class _FakeReadSession(WmsvrMailSession):
    """A session whose read path is a scripted list of `(payload, code, extra16)` replies."""

    def __init__(self, replies: Sequence[tuple[bytes | None, str | None, int]]) -> None:
        self._replies = list(replies)
        self.bodies: list[dict] = []
        self.login_context = cast(Any, None)
        self.session = cast(Any, None)
        self.session_key = b"\x00" * 16
        self.client_id = "test"
        self.sock = cast(Any, None)
        self.peer = cast(Any, None)
        self._pending_read_ack = False

    def _request_with_payload(self, method, body):
        self.bodies.append({"method": method, **dict(body)})
        payload, code, extra16 = self._replies.pop(0)
        reply = {
            "code": code,
            "extra16": extra16,
            "len1": len(payload) + 16 if payload else None,
            "records": None,
        }
        return payload, {"container": False, "plain": True}, reply

    def _drain_read_ack(self):
        # The scripted reply lists omit the trailing ack frames, so report one as consumed;
        # otherwise the r117 pending-ack guard would read the next scripted empty reply as a
        # late ack and reach for the (absent) socket.
        return {"empty_ack": True}


def test_read_message_slice_builds_the_recovered_body() -> None:
    """The body is the four keys the client's own request class carries (round 92)."""
    session = _FakeReadSession([(SOURCE_BYTES, None, 0x00C8)])
    result = session.read_message_slice("<RemoteId>", part=0, offset=512)

    assert session.bodies == [{
        "method": METHOD_GET_MESSAGE_DATA,
        "mid": "<RemoteId>",
        "part": 0,
        "offset": 512,
        "extra": "",
    }]
    assert result["served"] is True
    assert result["empty"] is False
    assert result["payload"] == SOURCE_BYTES
    assert result["length"] == len(SOURCE_BYTES)
    assert result["sha256"] == hashlib.sha256(SOURCE_BYTES).hexdigest()
    assert result["code"] is None


def test_read_message_slice_reports_a_part_not_found_reply_as_data() -> None:
    """A miss is data, not an exception: the scan needs to keep going."""

    session = _FakeReadSession([(PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x5000)])
    result = session.read_message_slice("<RemoteId>", part=3)

    assert result["served"] is False
    assert result["empty"] is False
    assert result["code"] == "FA_PART_NOT_FOUND"
    assert result["extra16"] == 0x5000
    assert result["length"] == len(PART_NOT_FOUND_JSON)
    assert result["sha256"] is None
    assert not result["payload"].startswith(PART_SOURCE_HEAD)


def test_read_message_slice_reports_an_empty_reply_as_empty() -> None:
    """Some slots answer with no payload at all (`extra16=0x00C8`, no slice1)."""

    session = _FakeReadSession([(None, None, 0x00C8)])
    result = session.read_message_slice("<RemoteId>", part=1)

    assert result["served"] is False
    assert result["empty"] is True
    assert result["code"] is None
    assert result["length"] == 0


def test_fetch_message_source_picks_the_slice_by_its_received_header() -> None:
    """Round 93: the slot cannot be computed, so the scan identifies the source by content."""

    session = _FakeReadSession([
        (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x5000),
        (None, None, 0x00C8),
        (HTML_BYTES, None, 0x00C8),
        (SOURCE_BYTES, None, 0x00C8),
    ])
    result = session.fetch_message_source("<RemoteId>", max_part=3)

    assert result["part_slot"] == 3
    assert result["source"] == SOURCE_BYTES
    assert result["length"] == len(SOURCE_BYTES)
    assert result["sha256"] == hashlib.sha256(SOURCE_BYTES).hexdigest()
    assert result["source_slots"] == [3]
    assert [item["part"] for item in result["candidates"]] == [2, 3]
    assert [item["is_source"] for item in result["candidates"]] == [False, True]
    assert result["candidates"][1]["head"] == "Received: from <"
    assert result["misses"] == [
        {"part": 0, "code": "FA_PART_NOT_FOUND", "empty": False},
        {"part": 1, "code": None, "empty": True},
    ]


def test_fetch_message_source_finds_a_source_whose_slot_moved() -> None:
    """Round 93 live: the read that answered slot 0 answers slot 4 later in the session."""

    session = _FakeReadSession([
        (None, None, 0x00C8),
        (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x5000),
        (None, None, 0x00C8),
        (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x5000),
        (SOURCE_BYTES, None, 0x00C8),
    ])
    result = session.fetch_message_source("<RemoteId>", max_part=4)

    assert result["part_slot"] == 4
    assert result["source"] == SOURCE_BYTES
    assert [item["part"] for item in result["candidates"]] == [4]
    assert [item["part"] for item in result["misses"]] == [0, 1, 2, 3]


def test_fetch_message_source_raises_when_no_slot_carries_a_source() -> None:
    """A window can always miss (the addressing depends on the connection's history)."""

    session = _FakeReadSession([
        (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x5000),
        (None, None, 0x00C8),
    ] * 2)

    with pytest.raises(WmsvrMailError) as excinfo:
        session.fetch_message_source("<RemoteId>", max_part=3)

    assert excinfo.value.code == ERROR_SOURCE_NOT_FOUND
    assert excinfo.value.details["method"] == METHOD_GET_MESSAGE_DATA
    assert excinfo.value.details["served_slots"] == []
    assert excinfo.value.details["slots_tried"] == [0, 1, 2, 3]
    assert excinfo.value.details["mid"] == "<RemoteId>"


def test_read_message_slice_pages_inside_a_known_slot() -> None:
    """Paging re-reads the slot a scan reported: the slice shrinks by the offset (round 92)."""
    session = _FakeReadSession([
        (SOURCE_BYTES, None, 0x00C8),
        (SOURCE_BYTES[12:], None, 0x00C8),
    ])
    first = session.fetch_message_source("<RemoteId>", max_part=0)
    page = session.read_message_slice("<RemoteId>", part=first["part_slot"], offset=12)

    assert session.bodies == [
        {"method": METHOD_GET_MESSAGE_DATA, "mid": "<RemoteId>", "part": 0, "offset": 0, "extra": ""},
        {"method": METHOD_GET_MESSAGE_DATA, "mid": "<RemoteId>", "part": 0, "offset": 12, "extra": ""},
    ]
    assert first["length"] == len(SOURCE_BYTES)
    assert page["served"] is True
    assert page["length"] == len(SOURCE_BYTES) - 12
    assert first["source"].endswith(page["payload"])


def test_reply_code_map_covers_the_read_paths_own_verdict() -> None:
    """`FA_PART_NOT_FOUND` maps to the read path's structured code."""
    from mailmaster.wmsvr_mail import _REPLY_CODE_TO_ERROR

    assert _REPLY_CODE_TO_ERROR["FA_PART_NOT_FOUND"] == ERROR_PART_NOT_FOUND


# ---------------------------------------------------------------------------
# Round 113: a served part is streamed as marker-tagged frames


def _padded(data: bytes) -> bytes:
    """PKCS#7-pad a synthetic slice0 the way the real reply is padded."""
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _read_slice0(marker: int | None) -> bytes:
    records = [
        (_w.TAG_METHOD, METHOD_GET_MESSAGE_DATA.encode()),
        (0x0016, b"x" * 21),
    ]
    if marker is not None:
        records.append((0x000C, int(marker).to_bytes(2, "big")))
    return _padded(_w.encode_tlv_envelope(records))


class _FakeStreamReadSession(WmsvrMailSession):
    """A read session scripted with whole frames: `(payload, code, extra16, marker)`."""

    def __init__(
        self,
        frames: Sequence[tuple[bytes | None, str | None, int, int | None]],
        acks: Sequence[dict | None] | None = None,
    ) -> None:
        self._frames = list(frames)
        self._acks = list(acks or [])
        self.bodies: list[dict] = []
        self.login_context = cast(Any, None)
        self.session = cast(Any, None)
        self.session_key = b"\x00" * 16
        self.client_id = "test"
        self.sock = cast(Any, None)
        self.peer = cast(Any, None)
        self._pending_read_ack = False

    @staticmethod
    def _entry(entry):
        payload, code, extra16, marker = entry
        reply = {
            "code": code,
            "extra16": extra16,
            "len1": len(payload) + 16 if payload else None,
            "records": None,
            "read_marker": marker,
        }
        meta = {"container": False, "plain": True} if payload else {}
        return payload, meta, reply

    def _request_with_payload(self, method, body):
        self.bodies.append({"method": method, **dict(body)})
        return self._entry(self._frames.pop(0))

    def _recv_payload_frame(self):
        return self._entry(self._frames.pop(0))

    def _drain_read_ack(self):
        return self._acks.pop(0) if self._acks else None


def test_parse_read_frame_marker_reads_the_chunk_position() -> None:
    """Round 113: 1 = first, 0 = middle, 2 = last, absent = single frame."""
    assert parse_read_frame_marker(_read_slice0(READ_MARKER_FIRST)) == READ_MARKER_FIRST
    assert parse_read_frame_marker(_read_slice0(READ_MARKER_MIDDLE)) == READ_MARKER_MIDDLE
    assert parse_read_frame_marker(_read_slice0(READ_MARKER_LAST)) == READ_MARKER_LAST
    assert parse_read_frame_marker(_read_slice0(None)) is None
    assert parse_read_frame_marker(b"") is None


def test_read_message_slice_assembles_the_marker_tagged_frames() -> None:
    """One request, then two follow-on frames: the payload is the whole 131,172 B part."""
    first = b"A" * 65536
    middle = b"B" * 65536
    last = b"C" * 100
    session = _FakeStreamReadSession([
        (first, None, 0x00C8, READ_MARKER_FIRST),
        (middle, None, 0x00C8, READ_MARKER_MIDDLE),
        (last, None, 0x00C8, READ_MARKER_LAST),
    ])

    result = session.read_message_slice("<RemoteId>", part=0)

    assert len(session.bodies) == 1  # follow-on frames are not new requests
    assert result["served"] is True
    assert result["payload"] == first + middle + last
    assert result["length"] == 131172
    assert result["sha256"] == hashlib.sha256(first + middle + last).hexdigest()
    assert result["frames"] == 3
    assert result["chunked"] is True
    assert result["markers"] == [READ_MARKER_FIRST, READ_MARKER_MIDDLE, READ_MARKER_LAST]
    assert result["chunk_lengths"] == [65536, 65536, 100]
    assert result["ack_drained"] is None
    assert result["extra_frames_drained"] == 0


def test_read_message_slice_single_frame_does_not_read_ahead() -> None:
    """A part with no marker is complete: the next scripted frame must stay unread."""
    session = _FakeStreamReadSession([
        (SOURCE_BYTES, None, 0x00C8, None),
        (b"not-read", None, 0x00C8, None),
    ])

    result = session.read_message_slice("<RemoteId>", part=0)

    assert result["served"] is True
    assert result["frames"] == 1
    assert result["chunked"] is False
    assert result["markers"] == [None]
    assert len(session._frames) == 1


def test_read_message_slice_drains_the_empty_ack_after_a_miss() -> None:
    """The ack left behind after `FA_PART_NOT_FOUND` is consumed (r112 desync fix)."""
    ack = {
        "code": None,
        "extra16": 0x00C8,
        "len0": 48,
        "len1": None,
        "payload_len": 0,
        "read_marker": None,
    }
    session = _FakeStreamReadSession(
        [(PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x1388, None)],
        acks=[ack],
    )

    result = session.read_message_slice("<RemoteId>", part=8)

    assert result["served"] is False
    assert result["code"] == "FA_PART_NOT_FOUND"
    assert result["verdict"] == {"code": "FA_PART_NOT_FOUND"}
    assert result["ack_drained"] == ack
    assert result["extra_frames_drained"] == 1


def test_read_message_slice_skips_a_late_empty_ack_before_the_real_reply() -> None:
    """Round 117: an ack later than the peek window must not become the next reply."""
    session = _FakeStreamReadSession([
        (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x1388, None),  # read 1 misses
        (None, None, 0x00C8, None),  # its ack arrives after read 1's peek window
        (SOURCE_BYTES, None, 0x00C8, None),  # read 2's real reply
    ])

    first = session.read_message_slice("<RemoteId>", part=7)
    assert first["ack_drained"] is None
    assert session._pending_read_ack is True

    second = session.read_message_slice("<RemoteId>", part=8)

    assert second["served"] is True
    assert second["payload"] == SOURCE_BYTES
    assert second["frames"] == 1
    assert second["skipped_acks"] == 1
    assert session._pending_read_ack is False


def test_read_message_slice_skips_a_late_ack_and_still_drains_a_miss_ack() -> None:
    """The r117 live shape: miss -> late ack -> next miss -> that miss's timely ack."""
    ack = {
        "code": None,
        "extra16": 0x00C8,
        "len0": 48,
        "len1": None,
        "payload_len": 0,
        "read_marker": None,
    }
    session = _FakeStreamReadSession(
        [
            (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x1388, None),
            (None, None, 0x00C8, None),
            (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x1388, None),
        ],
        acks=[None, ack],
    )

    first = session.read_message_slice("<RemoteId>", part=7)
    assert first["ack_drained"] is None

    second = session.read_message_slice("<RemoteId>", part=8)

    assert second["served"] is False
    assert second["code"] == "FA_PART_NOT_FOUND"
    assert second["skipped_acks"] == 1
    assert second["ack_drained"] == ack
    assert session._pending_read_ack is False


class _ScriptedFrameSession(WmsvrMailSession):
    """A session whose `_recv_frame` is a scripted list of raw reply frames."""

    def __init__(self, frames: list) -> None:
        self._frames = list(frames)
        self.session_key = b"\x00" * 16
        self._pending_read_ack = True

    def _recv_frame(self, *, timeout=None):
        return self._frames.pop(0)


def test_request_reply_skips_a_late_empty_ack() -> None:
    """Round 117: a non-read request (`mbox:compose`) must skip the late ack too."""
    ack = _w.WmsvrD1Frame(
        header=_w.WmsvrD1Header(
            word0=_w.D1_WORD0_HAS_EXTRA16,
            word2=0x0080,
            word4=0x0003,
            extra16=0x00C8,
        )
    )
    real = _w.build_wmsvr_d1_encrypted_frame(
        b'{"code":"S_OK"}',
        session_key=b"\x00" * 16,
        seq=2,
        word2=0x0080,
        word4=0x0003,
    )
    session = _ScriptedFrameSession([ack, real])

    reply = session._parse_reply_skipping_ack(session._recv_frame())

    assert reply["code"] == "S_OK"
    assert session._pending_read_ack is False


def test_read_message_slice_raises_when_a_middle_frame_has_no_marker() -> None:
    """A truncated stream must not be joined into a silently short source."""
    session = _FakeStreamReadSession([
        (b"A" * 65536, None, 0x00C8, READ_MARKER_FIRST),
        (b"B" * 65536, None, 0x00C8, None),
    ])

    with pytest.raises(WmsvrMailError) as excinfo:
        session.read_message_slice("<RemoteId>", part=0)

    assert excinfo.value.code == ERROR_READ_STREAM_INCOMPLETE
    assert excinfo.value.details["frames"] == 2
    assert excinfo.value.details["markers"] == [READ_MARKER_FIRST, None]


def test_read_message_slice_raises_when_a_middle_frame_is_rejected() -> None:
    """A non-S_OK middle frame stops the assembly instead of becoming payload."""
    session = _FakeStreamReadSession([
        (b"A" * 65536, None, 0x00C8, READ_MARKER_FIRST),
        (PART_NOT_FOUND_JSON, "FA_PART_NOT_FOUND", 0x1388, READ_MARKER_MIDDLE),
    ])

    with pytest.raises(WmsvrMailError) as excinfo:
        session.read_message_slice("<RemoteId>", part=0)

    assert excinfo.value.code == ERROR_READ_STREAM_INCOMPLETE
    assert excinfo.value.details["last_code"] == "FA_PART_NOT_FOUND"
    assert excinfo.value.details["frames"] == 2
