"""Read local MailMaster data without network access or mutations.

Run from a checkout:

    python examples/list_local_mail.py

This example only reads the local SQLite databases. It does not send or modify
anything.
"""

from __future__ import annotations

from mailmaster import MailMaster


def main() -> None:
    mm = MailMaster()
    accounts = mm.get_accounts()
    if not accounts:
        print("No local MailMaster accounts found.")
        return

    print(f"Local accounts: {len(accounts)}")
    for account in accounts:
        print(f"  [{account.id}] {account.email}")

    account = accounts[0]
    access = mm.open_account(account.id)

    mailboxes = access.get_mailboxes()
    print(f"\nMailboxes for {account.email}: {len(mailboxes)}")
    for mailbox in mailboxes[:10]:
        print(f"  [{mailbox.id}] {mailbox.display_name}")

    mails = access.list_mail(limit=5)
    print(f"\nNewest {len(mails)} local mail(s):")
    for mail in mails:
        print(f"  [{mail.local_id}] {mail.subject[:80]}")


if __name__ == "__main__":
    main()
