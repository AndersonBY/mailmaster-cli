"""Round 89: sending a STORED draft (`mbox:restoreDraft` + deliver) - library level.

Round 88 measured the wire shape live: the restore body is `{"id": <draftId>}`, its reply is a
full compose object (a NEW compose id, the draft's attrs and its attachment descriptors), and a
delivery on that restored compose id carries the stored attachment without re-uploading it.
These tests pin the product code to that shape: the request bodies the session builds, the
values it reads back, and the structured errors it raises.
"""
from __future__ import annotations

import json

import pytest

from mailmaster import wmsvr as _w
from mailmaster.wmsvr import WmsvrD1RequestContext, WmsvrSession, build_wmsvr_d1_encrypted_frame
from mailmaster.wmsvr_mail import (
    ERROR_DRAFT_NOT_FOUND,
    ERROR_METHOD_REJECTED,
    ERROR_NOT_VERIFIED,
    METHOD_COMPOSE,
    METHOD_GET_MESSAGE_INFOS,
    METHOD_LIST_MESSAGES,
    METHOD_RESTORE_DRAFT,
    WmsvrMailError,
    WmsvrMailSession,
    strip_slice_padding,
)

SESSION_KEY = bytes(range(16))
DRAFT_ID = "755:<DraftMid>"
RESTORED_COMPOSE_ID = "jLdPFXpRplPGgpdoYOxsfaMZcVUSMpMd"


def _session_state() -> WmsvrSession:
    return WmsvrSession(
        token="token-value",
        route="route-value",
    )


def _context() -> WmsvrD1RequestContext:
    return WmsvrD1RequestContext(
        key_version=401,
        key_digest16=bytes(16),
        master_fp="fp",
        master_sdid="sdid",
        device_info_json="{}",
        session_key=SESSION_KEY,
        word2=0x0080,
        word4=0x0000,
    )


class _DraftSession(WmsvrMailSession):
    """A session whose `request_lenient` is scripted and whose calls are recorded.

    Everything the draft path issues goes through `request_lenient` (the restore, the delivery,
    the info read-back and the folder listing), so one hook covers the whole flow.
    """

    def __init__(self, replies: list[dict] | None = None) -> None:
        self._replies = list(replies or [])
        self.calls: list[tuple[str, dict]] = []
        self.session_key = SESSION_KEY

    def request_lenient(self, method, body=None):
        self.calls.append((method, dict(body or {})))
        return self._replies.pop(0) if self._replies else {"code": "S_OK", "records": {}}

    def _business_context(self):
        return _context()

    @property
    def session(self):
        return _session_state()


def _restore_reply(
    *,
    code: str = "S_OK",
    compose_id: str = RESTORED_COMPOSE_ID,
    subject: str = "draft subject",
    content: str = "draft body",
    to: list[str] | None = None,
    attachments: list[dict] | None = None,
) -> dict:
    records: dict = {
        "id": compose_id,
        "account": "user@163.com",
        "to": ["user@163.com"] if to is None else to,
        "charset": "GBK",
        "subject": subject,
        "content": content,
        "isHtml": False,
        "saveSentCopy": True,
        "deliveryMsgType": 1,
    }
    if attachments is not None:
        records["attachments"] = attachments
    return {"code": code, "records": records}


def _stored_attachment() -> dict:
    return {
        "id": 1,
        "type": "upload",
        "name": "report.bin",
        "contentType": "application/octet-stream",
        "size": 8192,
    }


# --- restore_draft ---------------------------------------------------------

def test_restore_draft_asks_for_the_draft_id_and_parses_the_compose_object() -> None:
    """Round 88's live shape: body `{"id": draftId}`, reply = the draft as a compose object."""
    session = _DraftSession([_restore_reply(attachments=[_stored_attachment()])])
    result = session.restore_draft(DRAFT_ID)

    assert session.calls == [(METHOD_RESTORE_DRAFT, {"id": DRAFT_ID})]
    assert result["compose_id"] == RESTORED_COMPOSE_ID
    assert result["draft_id"] == DRAFT_ID
    assert result["subject"] == "draft subject"
    assert result["content"] == "draft body"
    assert result["to"] == ["user@163.com"]
    assert result["is_html"] is False
    # the descriptor is reported, and its id becomes the delivery's attachment entry
    assert result["attachments"] == [
        {
            "attachment_id": 1,
            "type": "upload",
            "file_name": "report.bin",
            "content_type": "application/octet-stream",
            "size": 8192,
        }
    ]
    assert result["attachment_entries"] == [{"id": 1, "deleted": False}]


def test_restore_draft_reports_a_draft_the_server_does_not_hold() -> None:
    session = _DraftSession([{"code": "FA_MAIL_NOT_FOUND", "records": {}}])
    with pytest.raises(WmsvrMailError) as excinfo:
        session.restore_draft(DRAFT_ID)
    assert excinfo.value.code == ERROR_DRAFT_NOT_FOUND
    assert excinfo.value.details["code"] == "FA_MAIL_NOT_FOUND"


def test_restore_draft_rejects_a_reply_without_a_compose_id() -> None:
    session = _DraftSession([{"code": "S_OK", "records": {"subject": "no id here"}}])
    with pytest.raises(WmsvrMailError) as excinfo:
        session.restore_draft(DRAFT_ID)
    assert excinfo.value.code == ERROR_METHOD_REJECTED


def test_restore_draft_maps_other_rejections_through_the_shared_table() -> None:
    session = _DraftSession([{"code": "FA_INVALID_SESSION", "records": {}}])
    with pytest.raises(WmsvrMailError) as excinfo:
        session.restore_draft(DRAFT_ID)
    assert excinfo.value.code == "wmsvr_session_expired"


# --- send_draft ------------------------------------------------------------

def test_send_draft_delivers_with_the_restored_compose_id_and_the_stored_attachment() -> None:
    """The delivery names the RESTORED compose id and re-uses the draft's attachment entry."""
    session = _DraftSession(
        [
            _restore_reply(attachments=[_stored_attachment()]),
            {"code": "S_OK", "records": {"savedSent": {"msid": 12, "mid": "newMid"},
                                         "deliveryMsgType": 1}},
        ]
    )
    result = session.send_draft(draft_id=DRAFT_ID)

    assert [method for method, _ in session.calls] == [METHOD_RESTORE_DRAFT, METHOD_COMPOSE]
    deliver_body = session.calls[1][1]
    assert deliver_body["action"] == "deliver"
    assert deliver_body["id"] == RESTORED_COMPOSE_ID
    assert deliver_body["attachments"] == [{"id": 1, "deleted": False}]
    # every attribute comes from the draft
    assert deliver_body["attrs"]["to"] == ["user@163.com"]
    assert deliver_body["attrs"]["subject"] == "draft subject"
    assert deliver_body["attrs"]["content"] == "draft body"
    assert deliver_body["attrs"]["isHtml"] is False
    assert result["from_draft"] is True
    assert result["draft_id"] == DRAFT_ID
    assert result["compose_id"] == RESTORED_COMPOSE_ID
    assert result["saved_sent"] == {"msid": 12, "mid": "newMid"}
    # the attachment is reported as the draft's stored one - nothing was uploaded here
    assert result["attachments"] == [
        {
            "attachment_id": 1,
            "type": "upload",
            "file_name": "report.bin",
            "content_type": "application/octet-stream",
            "size": 8192,
        }
    ]


def test_send_draft_omits_the_attachment_key_for_a_plain_draft() -> None:
    session = _DraftSession(
        [_restore_reply(attachments=[]), {"code": "S_OK", "records": {}}]
    )
    session.send_draft(draft_id=DRAFT_ID)
    assert "attachments" not in session.calls[1][1]


def test_send_draft_applies_the_overrides_on_top_of_the_draft() -> None:
    session = _DraftSession(
        [
            _restore_reply(attachments=[_stored_attachment()]),
            {"code": "S_OK", "records": {}},
        ]
    )
    session.send_draft(
        draft_id=DRAFT_ID,
        to=["other@example.com"],
        subject="overridden subject",
        text_body="overridden body",
    )
    attrs = session.calls[1][1]["attrs"]
    assert attrs["to"] == ["other@example.com"]
    assert attrs["subject"] == "overridden subject"
    assert attrs["content"] == "overridden body"
    assert attrs["isHtml"] is False


def test_send_draft_needs_a_recipient_and_a_body() -> None:
    """A draft the client parked without recipients (or without content) cannot be delivered."""
    session = _DraftSession([_restore_reply(to=[])])
    with pytest.raises(ValueError) as excinfo:
        session.send_draft(draft_id=DRAFT_ID)
    assert "recipient" in str(excinfo.value)
    session = _DraftSession([_restore_reply(content="")])
    with pytest.raises(ValueError) as excinfo:
        session.send_draft(draft_id=DRAFT_ID)
    assert "body" in str(excinfo.value)


# --- send_draft_verified ---------------------------------------------------

def test_send_draft_verified_reads_the_sent_copy_back() -> None:
    session = _DraftSession(
        [
            _restore_reply(subject="draft subject", attachments=[_stored_attachment()]),
            {"code": "S_OK", "records": {"savedSent": {"msid": 12, "mid": "newMid"}}},
            {
                "code": "S_OK",
                "records": [
                    {"mid": "12:newMid", "fid": 3, "subject": "draft subject", "size": 12483}
                ],
            },
        ]
    )
    result = session.send_draft_verified(draft_id=DRAFT_ID)

    assert session.calls[2][0] == METHOD_GET_MESSAGE_INFOS
    assert session.calls[2][1]["ids"] == ["12:newMid"]
    # round 89's live acceptance caught the read-back asking for too little: without `size` the
    # report's `sent_size` was always null, so the filter must name it.
    assert "size" in session.calls[2][1]["filter"]
    assert result["sent_id"] == "12:newMid"
    assert result["sent_folder_fid"] == 3
    assert result["sent_size"] == 12483
    assert result["readback_fallback"] is False
    assert result["state_change_verified"] is True


def test_send_draft_verified_falls_back_to_the_sent_folder() -> None:
    """A reply without `savedSent` (e.g. no sent copy requested) falls back to the listing."""
    session = _DraftSession(
        [
            _restore_reply(subject="draft subject"),
            {"code": "S_OK", "records": {}},
            {"code": "S_OK", "records": ["12:newMid"]},
            {"code": "S_OK", "records": [{"mid": "12:newMid", "fid": 3, "subject": "draft subject"}]},
        ]
    )
    result = session.send_draft_verified(draft_id=DRAFT_ID)
    assert session.calls[2][0] == METHOD_LIST_MESSAGES
    assert session.calls[2][1]["fids"] == [3]
    assert result["readback_fallback"] is True
    assert result["sent_id"] == "12:newMid"
    assert result["state_change_verified"] is True


def test_send_draft_verified_raises_when_the_copy_does_not_resolve() -> None:
    session = _DraftSession(
        [
            _restore_reply(subject="draft subject"),
            {"code": "S_OK", "records": {"savedSent": {"msid": 12, "mid": "newMid"}}},
            {"code": "FA_MAIL_NOT_FOUND", "records": []},
            {"code": "S_OK", "records": []},
        ]
    )
    with pytest.raises(WmsvrMailError) as excinfo:
        session.send_draft_verified(draft_id=DRAFT_ID)
    assert excinfo.value.code == ERROR_NOT_VERIFIED
    assert excinfo.value.details["state_change_verified"] is False


# --- find_draft ------------------------------------------------------------

def test_find_draft_resolves_by_subject_and_reports_the_newest_when_blank() -> None:
    listing = ["755:<DraftA>", "755:<DraftB>"]
    infos = [
        {"mid": "755:<DraftA>", "fid": 2, "subject": "other", "size": 690},
        {"mid": "755:<DraftB>", "fid": 2, "subject": "wanted", "size": 12305},
    ]
    session = _DraftSession([{"code": "S_OK", "records": listing}])
    session._replies.append({"code": "S_OK", "records": infos})
    found = session.find_draft(subject="wanted")
    assert found["draft_id"] == "755:<DraftB>"
    assert found["size"] == 12305
    assert found["fallback"] is False

    session = _DraftSession(
        [{"code": "S_OK", "records": listing}, {"code": "S_OK", "records": infos}]
    )
    newest = session.find_draft()
    assert newest["draft_id"] == "755:<DraftA>"
    assert newest["fallback"] is False


def test_find_draft_reports_a_missing_subject_and_an_empty_folder() -> None:
    listing = ["755:<DraftA>"]
    infos = [{"mid": "755:<DraftA>", "fid": 2, "subject": "other", "size": 690}]
    session = _DraftSession(
        [{"code": "S_OK", "records": listing}, {"code": "S_OK", "records": infos}]
    )
    with pytest.raises(WmsvrMailError) as excinfo:
        session.find_draft(subject="wanted")
    assert excinfo.value.code == ERROR_DRAFT_NOT_FOUND

    session = _DraftSession([{"code": "S_OK", "records": []}])
    with pytest.raises(WmsvrMailError) as excinfo:
        session.find_draft(subject="wanted")
    assert excinfo.value.code == ERROR_DRAFT_NOT_FOUND


def test_restore_reply_frame_parses_to_the_same_records() -> None:
    """Guard the shape: a restore reply built as a real frame parses to the same records."""
    payload = json.dumps(
        {
            "id": RESTORED_COMPOSE_ID,
            "account": "user@163.com",
            "to": ["user@163.com"],
            "subject": "draft subject",
            "content": "draft body",
            "attachments": [_stored_attachment()],
        }
    ).encode("utf-8")
    frame = build_wmsvr_d1_encrypted_frame(
        b'{"code":"S_OK"}', slice1_bytes=payload, seq=1, session_key=SESSION_KEY,
        word2=0x0080, word4=0x0003,
    )
    from mailmaster.wmsvr_mail import parse_business_reply

    reply = parse_business_reply(frame, SESSION_KEY)
    assert reply["code"] == "S_OK"
    assert reply["records"]["id"] == RESTORED_COMPOSE_ID
    assert reply["records"]["attachments"][0]["id"] == 1
    # the body the deliver frame carries is the same JSON envelope
    assert strip_slice_padding(_w.decrypt_wmsvr_d1_slice(frame.slice1, SESSION_KEY)) == payload
