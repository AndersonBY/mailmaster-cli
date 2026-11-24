"""Send one mail, with a dry-run default.

This example is safe by default: it prints the plan and exits unless `--send`
is passed explicitly.

    python examples/send_mail.py --account me@example.com \
        --to you@example.com --subject "Hello" --body "Hello"

    python examples/send_mail.py --account me@example.com \
        --to you@example.com --subject "Hello" --body "Hello" --send

Use `--transport wmsvr-private` to require the 163/Wmsvr private protocol, or
`--transport smtp` to require SMTP.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from mailmaster import MailMaster


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Account id or email.")
    parser.add_argument("--to", action="append", required=True, help="Recipient; repeatable.")
    parser.add_argument("--subject", default="", help="Subject.")
    parser.add_argument("--body", default="", help="Plain-text body.")
    parser.add_argument("--attach", action="append", type=Path, default=[], help="Attachment; repeatable.")
    parser.add_argument(
        "--transport",
        choices=["auto", "smtp", "wmsvr-private"],
        default="auto",
        help="Transport to use.",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Actually send. Without this flag the script only prints the plan.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    mm = MailMaster()
    access = mm.open_account(args.account)
    capability = access.get_capabilities()
    chosen = access.resolve_send_transport(args.transport, capability=capability)

    print(f"account: {capability.email}")
    print(f"transport: {chosen}")
    print(f"recipients: {len(args.to)}")
    print(f"attachments: {len(args.attach)}")
    print(f"recommended_send_method: {capability.recommended_send_method}")

    if not args.send:
        print("\nDry run. Re-run with --send to transmit.")
        return

    if chosen == "none":
        raise SystemExit(f"transport not available for this account: {args.transport}")

    result = access.send_mail(
        to=args.to,
        subject=args.subject,
        body=args.body,
        attachments=args.attach or None,
        transport=chosen,
    )
    if chosen == "wmsvr-private":
        print(
            "sent:",
            {
                "state_change_verified": result.get("state_change_verified"),
                "readback_fallback": result.get("readback_fallback"),
                "sent_id": result.get("sent_id"),
            },
        )
        return

    print("sent: SMTP")


if __name__ == "__main__":
    main()
