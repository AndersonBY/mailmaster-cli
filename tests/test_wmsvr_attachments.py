"""Tests for the private-protocol attachment path (`wzp:uploadAttach`, rounds 84-86).

Everything here is offline: the chunk frame is built and decrypted locally to prove the
shape round 84 established live (metadata as envelope record `0x0103`, body = the raw file
bytes, integer JSON tokens), and the four-step send is exercised against a scripted session.
Round 86 added the multi-packet shape: the reply's `actualSize` is cumulative over advancing
`offset`s, so the tests script cumulative counts and assert the packet plan and the check.
No network and no credentials are involved.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailmaster import wmsvr as _w
from mailmaster.wmsvr_mail import (
    COMPOSE_MAILER_EXT,
    DEFAULT_UPLOAD_CHUNK_SIZE,
    ERROR_NOT_VERIFIED,
    ERROR_UPLOAD_REJECTED,
    METHOD_UPLOAD_ATTACH,
    METHOD_UPLOAD_PREPARE,
    WmsvrAttachment,
    WmsvrMailError,
    WmsvrMailSession,
    build_upload_metadata,
    strip_slice_padding,
    guess_attachment_content_type,
    parse_business_reply,
)

SESSION_KEY = bytes(range(16))
SESSION_TOKEN = "T" * 32


def _session_state() -> _w.WmsvrSession:
    return _w.WmsvrSession(
        token=SESSION_TOKEN,
        route="Coremail:<seed>%<token>%wzp-session-<id>",
        host="10.0.0.1",
        port=8080,
        account_desc="7|<account>",
        ticket="fp-material",
        trace_id="sdid-material",
        device_info='{"masterDI":true}',
        client_id="mailwin|<account>",
    )


def _context() -> _w.WmsvrD1RequestContext:
    return _w.WmsvrD1RequestContext(
        key_version=_w.DEFAULT_D1_KEY_VERSION,
        key_digest16=_w.DEFAULT_D1_FALLBACK_KEY_DIGEST16,
        master_fp="fp-material",
        master_sdid="sdid-material",
        device_info_json='{"masterDI":true}',
        session_key=SESSION_KEY,
        word2=0x0080,
        word4=0x0003,
    )


def test_build_upload_metadata_uses_integer_tokens() -> None:
    """Round 83/84: the server's parser wants integer literals for offset/id/size."""
    metadata = build_upload_metadata(
        compose_id="compose-1",
        file_name="report.bin",
        content_type="application/octet-stream",
        attachment_id=1,
        size=64,
    )
    assert metadata == {
        "offset": 0,
        "composeId": "compose-1",
        "fileName": "report.bin",
        "contentType": "application/octet-stream",
        "attachmentId": 1,
        "size": 64,
    }
    for key in ("offset", "attachmentId", "size"):
        assert isinstance(metadata[key], int) and not isinstance(metadata[key], bool)
    serialized = json.dumps(metadata, separators=(",", ":"))
    assert '"offset":0' in serialized
    assert '"attachmentId":1' in serialized
    assert '"size":64' in serialized
    assert ".0" not in serialized


def test_guess_attachment_content_type() -> None:
    assert guess_attachment_content_type("photo.png") == "image/png"
    assert guess_attachment_content_type("no-suffix") == "application/octet-stream"


def test_attachment_from_path_reads_the_file(tmp_path: Path) -> None:
    path = tmp_path / "note.txt"
    path.write_bytes(b"hello attachment")
    attachment = WmsvrAttachment.from_path(path)
    assert attachment.file_name == "note.txt"
    assert attachment.data == b"hello attachment"
    assert attachment.size == 16
    assert attachment.content_type == "text/plain"


def _tlv_records_end(data: bytes) -> int:
    """Length of the leading run of complete TLV records (a slice is zero/pad padded)."""

    def decode_leb(blob: bytes, offset: int) -> tuple[int, int]:
        result = 0
        shift = 0
        while True:
            value = blob[offset]
            offset += 1
            result |= (value & 0x7F) << shift
            if not value & 0x80:
                return result, offset
            shift += 7

    offset = 0
    while offset + 3 <= len(data):
        tag = int.from_bytes(data[offset : offset + 2], "big")
        length, cursor = decode_leb(data, offset + 2)
        if tag == 0 and length == 0:
            return cursor
        if cursor + length > len(data):
            return offset
        offset = cursor + length
    return offset


def test_envelope_extras_land_between_port_and_account() -> None:
    """The client's header writer puts the class payload before the account record."""
    extra = (0x0103, b'{"probe":1}')
    envelope = _w.build_envelope_with_records(_session_state(), METHOD_UPLOAD_ATTACH, (extra,))
    tags = [tag for tag, _ in _w.decode_tlv_envelope(envelope[: _tlv_records_end(envelope)])]
    assert 0x0103 in tags
    assert tags.index(0x0201) < tags.index(0x0103) < tags.index(0x0016)
    # The runtime tail still follows the account record.
    assert tags.index(0x0016) < tags.index(_w.TAG_CLIENT_ID)


def test_attachment_chunk_carries_metadata_as_record_and_bytes_as_body() -> None:
    """Round 84's live shape, verified on the wire locally: record 0x0103 + raw bytes."""
    payload = bytes(range(64))
    metadata = build_upload_metadata(
        compose_id="compose-1",
        file_name="report.bin",
        content_type="application/octet-stream",
        attachment_id=1,
        size=len(payload),
    )
    metadata_json = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    frame = _w.build_wmsvr_d1_binary_request_frame(
        _context(),
        _session_state(),
        METHOD_UPLOAD_ATTACH,
        payload=payload,
        records=((_w.TAG_UPLOAD_METADATA, metadata_json),),
        seq=1,
    )
    slice0 = _w.decrypt_wmsvr_d1_slice(frame.slice0, SESSION_KEY)
    records = dict(_w.decode_tlv_envelope(slice0[: _tlv_records_end(slice0)]))
    assert records[_w.TAG_METHOD] == METHOD_UPLOAD_ATTACH.encode()
    assert records[_w.TAG_UPLOAD_METADATA] == metadata_json
    assert json.loads(records[_w.TAG_UPLOAD_METADATA].decode())["attachmentId"] == 1
    # The body is the file's bytes alone - no metadata prefix.
    body = _w.decrypt_wmsvr_d1_slice(frame.slice1, SESSION_KEY)
    assert strip_slice_padding(body) == payload
    assert b"composeId" not in body


class _ScriptedSession(WmsvrMailSession):
    """A session whose transport is scripted and whose requests are recorded."""

    def __init__(self, replies: list[dict] | None = None,
                 raw_replies: list[_w.WmsvrD1Frame] | None = None) -> None:
        self._replies = list(replies or [])
        self.raw_replies = list(raw_replies or [])
        self.calls: list[tuple[str, dict]] = []
        self.frames: list = []
        self.session_key = SESSION_KEY

    def request(self, method, body=None):
        self.calls.append((method, dict(body or {})))
        return self._replies.pop(0) if self._replies else {"code": "S_OK", "records": {}}

    def _send_recv(self, frame, *, timeout=None):
        self.frames.append(frame)
        return self.raw_replies.pop(0) if self.raw_replies else frame

    def _business_context(self):
        return _context()

    @property
    def session(self):
        return _session_state()


def _chunk_reply(code: str = "S_OK", actual_size: int = 64, attachment_id: int = 1,
                 total_size: int = 64) -> _w.WmsvrD1Frame:
    """A business reply frame the parser accepts, built with the library's own primitives.

    `size` is the declared total and stays put; `actual_size` is the server's cumulative count,
    which is what round 86 measured over a multi-packet upload.
    """
    payload = json.dumps(
        {
            "attachmentId": attachment_id,
            "fileName": "report.bin",
            "contentType": "application/octet-stream",
            "size": total_size,
            "actualSize": actual_size,
        }
    ).encode("utf-8")
    slice0 = b'{"code":"%s"}' % code.encode("ascii")
    return _w.build_wmsvr_d1_encrypted_frame(
        slice0, slice1_bytes=payload, seq=1, session_key=SESSION_KEY, word2=0x0080, word4=0x0003
    )


def test_parse_chunk_reply_helper_matches_the_parser() -> None:
    """Guard the test helper itself: the scripted reply really parses to those records."""
    reply = parse_business_reply(_chunk_reply(), SESSION_KEY)
    assert reply["code"] == "S_OK"
    assert reply["records"]["actualSize"] == 64


def test_prepare_attachment_reads_the_echoed_id() -> None:
    """The live reply echoes the id as a string; the product needs it as an int."""
    session = _ScriptedSession(
        [{"code": "S_OK", "records": {"attachmentId": "1", "fileName": "report.bin", "size": "64"}}]
    )
    result = session.prepare_attachment(compose_id="compose-1", file_name="report.bin", size=64)
    assert session.calls == [
        (
            METHOD_UPLOAD_PREPARE,
            {"composeId": "compose-1", "attachmentId": 0, "fileName": "report.bin", "size": 64},
        )
    ]
    assert result["attachment_id"] == 1
    assert isinstance(result["attachment_id"], int)
    assert result["size"] == 64


def test_prepare_attachment_requires_an_id() -> None:
    session = _ScriptedSession([{"code": "S_OK", "records": {"fileName": "report.bin"}}])
    with pytest.raises(WmsvrMailError) as excinfo:
        session.prepare_attachment(compose_id="compose-1", file_name="report.bin", size=64)
    assert excinfo.value.code == ERROR_UPLOAD_REJECTED


def test_upload_attachment_reports_completion_from_actual_size() -> None:
    session = _ScriptedSession()
    session._send_recv = lambda frame, timeout=None: _chunk_reply(actual_size=64)  # type: ignore[method-assign]
    result = session.upload_attachment(
        compose_id="compose-1",
        attachment_id=1,
        file_name="report.bin",
        content_type="application/octet-stream",
        data=bytes(64),
    )
    assert result["code"] == "S_OK"
    assert result["actual_size"] == 64
    assert result["completed"] is True
    assert result["metadata"]["attachmentId"] == 1
    assert result["metadata"]["offset"] == 0
    assert len(result["packets"]) == 1


def _frame_metadata(frame) -> dict:
    """Read record 0x0103 back out of a chunk frame - the metadata the server will parse."""
    slice0 = _w.decrypt_wmsvr_d1_slice(frame.slice0, SESSION_KEY)
    records = dict(_w.decode_tlv_envelope(slice0[: _tlv_records_end(slice0)]))
    return json.loads(records[_w.TAG_UPLOAD_METADATA].decode())


def _frame_body(frame) -> dict:
    """The business request's JSON body: it rides slice1 for the compose family."""
    raw = strip_slice_padding(_w.decrypt_wmsvr_d1_slice(frame.slice1, SESSION_KEY))
    return json.loads(raw.decode("utf-8"))


def _business_reply(code: str = "S_OK", records: dict | None = None) -> _w.WmsvrD1Frame:
    """A business reply frame carrying `{"code":...}` in slice0 and the records in slice1."""
    payload = json.dumps(records or {}).encode("utf-8")
    slice0 = b'{"code":"%s"}' % code.encode("ascii")
    return _w.build_wmsvr_d1_encrypted_frame(
        slice0, slice1_bytes=payload, seq=1, session_key=SESSION_KEY, word2=0x0080, word4=0x0003
    )


def _cumulative_script(total: int, lengths: list[int]) -> list[_w.WmsvrD1Frame]:
    """A scripted reply per packet: `actualSize` is cumulative, `size` the declared total."""
    out = []
    sent = 0
    for length in lengths:
        sent += length
        out.append(_chunk_reply(actual_size=sent, total_size=total))
    return out


def test_upload_attachment_splits_large_data_into_offset_packets() -> None:
    """Round 86 measured the wire: several packets, offsets advancing, cumulative `actualSize`."""
    data = bytes(range(256)) * 10  # 2560 B
    session = _ScriptedSession(raw_replies=_cumulative_script(len(data), [1024, 1024, 512]))
    result = session.upload_attachment(
        compose_id="compose-1",
        attachment_id=7,
        file_name="report.bin",
        content_type="application/octet-stream",
        data=data,
        chunk_size=1024,
    )
    assert [p["offset"] for p in result["packets"]] == [0, 1024, 2048]
    assert [p["length"] for p in result["packets"]] == [1024, 1024, 512]
    assert [p["actual_size"] for p in result["packets"]] == [1024, 2048, 2560]
    assert result["sent"] == 2560
    assert result["size"] == 2560
    assert result["chunk_size"] == 1024
    assert result["completed"] is True
    # Every packet is its own frame: metadata offset in record 0x0103, body = that slice alone.
    assert len(session.frames) == 3
    for index, frame in enumerate(session.frames):
        metadata = _frame_metadata(frame)
        assert metadata["offset"] == result["packets"][index]["offset"]
        assert metadata["size"] == 2560
        assert metadata["attachmentId"] == 7
        body = strip_slice_padding(_w.decrypt_wmsvr_d1_slice(frame.slice1, SESSION_KEY))
        assert body == data[result["packets"][index]["offset"]:
                            result["packets"][index]["offset"] + result["packets"][index]["length"]]


def test_upload_attachment_rejects_a_cumulative_count_that_does_not_match() -> None:
    """If the server's running count lags the bytes sent, the upload is already broken."""
    replies = _cumulative_script(2560, [1024, 1024, 512])
    replies[1] = _chunk_reply(actual_size=1024, total_size=2560)  # second packet not applied
    session = _ScriptedSession(raw_replies=replies)
    with pytest.raises(WmsvrMailError) as excinfo:
        session.upload_attachment(
            compose_id="compose-1",
            attachment_id=7,
            file_name="report.bin",
            content_type="application/octet-stream",
            data=bytes(range(256)) * 10,
            chunk_size=1024,
        )
    assert excinfo.value.code == ERROR_UPLOAD_REJECTED
    assert excinfo.value.details["offset"] == 1024
    assert excinfo.value.details["expected_actual_size"] == 2048
    assert excinfo.value.details["actual_size"] == 1024
    # The first packet is kept in the details so the caller can see how far the upload got.
    assert len(excinfo.value.details["packets"]) == 2


def test_upload_attachment_keeps_one_packet_for_small_files() -> None:
    """Below the chunk size nothing changes: the round-84/85 shape stays one packet, offset 0."""
    session = _ScriptedSession(raw_replies=[_chunk_reply(actual_size=64)])
    result = session.upload_attachment(
        compose_id="compose-1",
        attachment_id=1,
        file_name="report.bin",
        content_type="application/octet-stream",
        data=bytes(64),
    )
    assert len(result["packets"]) == 1
    assert result["chunk_size"] == DEFAULT_UPLOAD_CHUNK_SIZE
    assert _frame_metadata(session.frames[0])["offset"] == 0


def test_upload_attachment_raises_on_a_rejected_chunk() -> None:
    """Round 83's `FA_INVALID_PARAMETER` is a rejection, not a silent no-op."""
    session = _ScriptedSession()
    session._send_recv = lambda frame, timeout=None: _chunk_reply(  # type: ignore[method-assign]
        code="FA_INVALID_PARAMETER", actual_size=0
    )
    with pytest.raises(WmsvrMailError) as excinfo:
        session.upload_attachment(
            compose_id="compose-1",
            attachment_id=1,
            file_name="report.bin",
            content_type="application/octet-stream",
            data=bytes(64),
        )
    assert excinfo.value.code == ERROR_UPLOAD_REJECTED
    assert excinfo.value.details["code"] == "FA_INVALID_PARAMETER"


def test_send_mail_with_attachments_runs_the_four_steps() -> None:
    """compose -> prepare -> chunk -> deliver, with the uploaded ids in the delivery."""
    session = _ScriptedSession(
        [{"code": "S_OK", "records": {"id": "compose-1"}}]
    )
    steps: list[str] = []

    def prepare_attachment(*, compose_id, file_name, size):
        steps.append("prepare")
        return {"attachment_id": 1}

    def upload_attachment(*, compose_id, attachment_id, file_name, content_type, data,
                          chunk_size=DEFAULT_UPLOAD_CHUNK_SIZE):
        steps.append("upload")
        assert chunk_size == DEFAULT_UPLOAD_CHUNK_SIZE
        return {"attachment_id": attachment_id, "actual_size": len(data), "completed": True,
                "sent": len(data), "packets": [{"offset": 0, "length": len(data)}]}

    session.prepare_attachment = prepare_attachment  # type: ignore[method-assign]
    session.upload_attachment = upload_attachment  # type: ignore[method-assign]

    result = session.send_mail_with_attachments(
        account="<account>",
        to=["<to>"],
        subject="with attachment",
        text_body="body",
        attachments=[WmsvrAttachment(file_name="report.bin", data=bytes(64))],
    )

    assert steps == ["prepare", "upload"]
    assert [method for method, _ in session.calls] == ["mbox:compose", "mbox:compose"]
    delivered = session.calls[1][1]
    assert delivered["action"] == "deliver"
    assert delivered["attachments"] == [{"id": 1, "deleted": False}]
    assert delivered["xMailerExt"] == COMPOSE_MAILER_EXT
    assert result["attachments"][0]["completed"] is True
    assert result["attachments"][0]["packets"] == 1
    assert result["attachments"][0]["sent"] == 64
    assert result["attachment_entries"] == [{"id": 1, "deleted": False}]


def test_send_mail_with_attachments_verified_requires_full_byte_count() -> None:
    """A chunk the server did not fully acknowledge fails verification before any read-back."""

    def incomplete(**kwargs):
        return {
            "code": "S_OK",
            "saved_sent": {"msid": 1, "mid": "m"},
            "attachments": [{"file_name": "report.bin", "completed": False, "actual_size": 0}],
        }

    session = _ScriptedSession([])
    session.send_mail_with_attachments = incomplete  # type: ignore[method-assign]
    with pytest.raises(WmsvrMailError) as excinfo:
        session.send_mail_with_attachments_verified(
            account="<account>",
            to=["<to>"],
            subject="x",
            text_body="y",
            attachments=[WmsvrAttachment(file_name="report.bin", data=bytes(64))],
        )
    assert excinfo.value.code == ERROR_UPLOAD_REJECTED
    assert excinfo.value.details["state_change_verified"] is False


def test_send_mail_with_attachments_verified_needs_a_resolving_sent_copy() -> None:
    """Delivery accepted but the sent copy id does not resolve -> not verified (round 62 rule)."""

    def accepted(**kwargs):
        return {"code": "S_OK", "saved_sent": {}, "attachments": [{"completed": True}]}

    session = _ScriptedSession([])
    session.send_mail_with_attachments = accepted  # type: ignore[method-assign]
    session.request_lenient = lambda method, body=None: {"code": "S_OK", "records": []}  # type: ignore[method-assign]
    with pytest.raises(WmsvrMailError) as excinfo:
        session.send_mail_with_attachments_verified(
            account="<account>",
            to=["<to>"],
            subject="x",
            text_body="y",
            attachments=[WmsvrAttachment(file_name="report.bin", data=bytes(64))],
        )
    assert excinfo.value.code == ERROR_NOT_VERIFIED


def test_save_draft_with_attachments_uploads_then_saves_with_the_id() -> None:
    """Round 87: a draft with an attachment = the send's upload steps, then `action:"save"`.

    The wire order is compose -> upload:prepare -> wzp:uploadAttach -> save, and only the last
    call carries `attachments`; the entry uses the id the upload bound to the prepared slot.
    """
    # `create_compose` and `prepare_attachment` go through the session's `request` (scripted
    # dicts); the chunk and the save build real frames, so their replies are scripted frames.
    session = _ScriptedSession(
        [
            {"code": "S_OK", "records": {"id": "compose-1"}},
            {"code": "S_OK", "records": {"attachmentId": "1", "fileName": "report.bin",
                                         "size": "64"}},
        ],
        raw_replies=[
            _chunk_reply(actual_size=64),
            _business_reply(records={"draftId": "821:<DraftMid>"}),
        ],
    )
    result = session.save_draft(
        account="<account>",
        to=["<to>"],
        subject="draft with attachment",
        text_body="draft body",
        attachments=[WmsvrAttachment(file_name="report.bin", data=bytes(64))],
    )
    assert len(session.frames) == 2
    chunk_frame, save_frame = session.frames
    saved = _frame_body(save_frame)
    assert saved["action"] == "save"
    assert saved["id"] == "compose-1"
    assert saved["attachments"] == [{"id": 1, "deleted": False}]
    assert result["draft_id"] == "821:<DraftMid>"
    assert result["attachment_entries"] == [{"id": 1, "deleted": False}]
    assert result["attachments"][0]["completed"] is True
    assert result["attachments"][0]["packets"] == 1
    # The chunk really was the r84-shaped one: record 0x0103 with the integer id, bytes as body.
    metadata = _frame_metadata(session.frames[0])
    assert metadata["attachmentId"] == 1
    assert metadata["composeId"] == "compose-1"
    body = strip_slice_padding(_w.decrypt_wmsvr_d1_slice(chunk_frame.slice1, SESSION_KEY))
    assert body == bytes(64)  # the chunk body is the file's bytes alone, never JSON


def test_save_draft_without_attachments_keeps_the_plain_save_body() -> None:
    """No attachments -> no `attachments` key at all (bit-for-bit the round-70 body)."""
    session = _ScriptedSession(
        [{"code": "S_OK", "records": {"id": "compose-1"}}],
        raw_replies=[_business_reply(records={"draftId": "821:<DraftMid>"})],
    )
    result = session.save_draft(
        account="<account>", to=["<to>"], subject="plain draft", text_body="body"
    )
    assert len(session.frames) == 1
    assert "attachments" not in _frame_body(session.frames[0])
    assert result["attachments"] == []
    assert result["attachment_entries"] == []


def test_save_draft_verified_rejects_an_incomplete_upload() -> None:
    """A draft whose upload did not complete is not a verified draft (round 87)."""

    def incomplete(**kwargs):
        return {"code": "S_OK", "draft_id": "821:<DraftMid>",
                "attachments": [{"file_name": "report.bin", "completed": False,
                                 "actual_size": 0}]}

    session = _ScriptedSession([])
    session.save_draft = incomplete  # type: ignore[method-assign]
    with pytest.raises(WmsvrMailError) as excinfo:
        session.save_draft_verified(
            account="<account>",
            to=["<to>"],
            subject="draft with attachment",
            text_body="body",
            attachments=[WmsvrAttachment(file_name="report.bin", data=bytes(64))],
        )
    assert excinfo.value.code == ERROR_UPLOAD_REJECTED
    assert excinfo.value.details["state_change_verified"] is False
    assert excinfo.value.details["upload_incomplete"][0]["completed"] is False
