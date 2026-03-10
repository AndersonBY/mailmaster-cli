from mailmaster.imap_ops import delete_mail, mark_seen, move_mail
from mailmaster.models import MailRecord


class FakeImap:
    def __init__(self, capabilities=()):
        self.capabilities = capabilities
        self.calls: list[tuple] = []

    def login(self, user: str, password: str):
        self.calls.append(("login", user, password))
        return "OK", [b"logged in"]

    def starttls(self):
        self.calls.append(("starttls",))
        return "OK", [b"tls"]

    def select(self, mailbox: str, readonly: bool = False):
        self.calls.append(("select", mailbox, readonly))
        return "OK", [b"1"]

    def uid(self, command: str, *args: str):
        self.calls.append(("uid", command, *args))
        return "OK", [b"ok"]

    def expunge(self):
        self.calls.append(("expunge",))
        return "OK", [b"expunged"]

    def logout(self):
        self.calls.append(("logout",))
        return "BYE", [b"logout"]


def _record() -> MailRecord:
    return MailRecord(
        local_id=1,
        remote_id="1734",
        mailbox="INBOX",
        subject="Hi",
        summary="",
        sender_name="",
        sender_email="sender@example.com",
        to_list=[],
        cc_list=[],
        reply_to_list=[],
        unread=True,
        starred=False,
        has_attachments=False,
        replied=False,
        forwarded=False,
        received_ts_ms=0,
        orig_ts_ms=0,
        message_id="mid",
        reference_ids="",
    )


def test_mark_seen_read() -> None:
    client = FakeImap()
    mark_seen(client, _record(), seen=True)
    assert ("uid", "STORE", "1734", "+FLAGS.SILENT", "(\\Seen)") in client.calls


def test_mark_seen_unread() -> None:
    client = FakeImap()
    mark_seen(client, _record(), seen=False)
    assert ("uid", "STORE", "1734", "-FLAGS.SILENT", "(\\Seen)") in client.calls


def test_delete_mail() -> None:
    client = FakeImap()
    delete_mail(client, _record())
    assert ("uid", "STORE", "1734", "+FLAGS.SILENT", "(\\Deleted)") in client.calls
    assert ("expunge",) in client.calls


def test_move_mail_with_move_capability() -> None:
    client = FakeImap(capabilities=(b"IMAP4rev1", b"MOVE"))
    move_mail(client, _record(), target_mailbox="Archive")
    assert ("uid", "MOVE", "1734", "Archive") in client.calls


def test_move_mail_copy_fallback() -> None:
    client = FakeImap(capabilities=(b"IMAP4rev1",))
    move_mail(client, _record(), target_mailbox="Archive")
    assert ("uid", "COPY", "1734", "Archive") in client.calls
    assert ("uid", "STORE", "1734", "+FLAGS.SILENT", "(\\Deleted)") in client.calls
