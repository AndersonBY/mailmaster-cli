"""SMTP transport and profile helpers."""
from __future__ import annotations

import base64
import html
import mimetypes
import smtplib
import ssl
from dataclasses import dataclass
from email import encoders
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from .email_renderer import InlineImage, html_to_plain_text, prepare_html_inline_images


@dataclass
class SmtpProfile:
    email: str
    smtp_host: str
    smtp_port: int = 465
    username: str = ""
    password_b64: str = ""
    use_ssl: bool = True
    use_starttls: bool = False
    display_name: str = ""

    @property
    def password(self) -> str:
        if not self.password_b64:
            return ""
        return base64.b64decode(self.password_b64).decode("utf-8")

    @password.setter
    def password(self, value: str) -> None:
        self.password_b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")

    @property
    def effective_username(self) -> str:
        return self.username or self.email


def profile_from_server_config(email: str, config: dict[str, Any]) -> SmtpProfile:
    password = str(config.get("password") or "")
    if not password:
        raise ValueError(f"No decryptable SMTP password for '{email}'.")

    ssl_type = int(config.get("sslType") or 0)
    port = int(config.get("port") or 465)
    return SmtpProfile(
        email=email,
        smtp_host=str(config.get("host") or ""),
        smtp_port=port,
        username=str(config.get("user") or email),
        password_b64=base64.b64encode(password.encode("utf-8")).decode("ascii"),
        use_ssl=ssl_type == 1,
        use_starttls=ssl_type != 1 and port == 587,
    )


KNOWN_SMTP: dict[str, tuple[str, int, bool, bool]] = {
    "163.com": ("smtp.163.com", 465, True, False),
    "126.com": ("smtp.126.com", 465, True, False),
    "yeah.net": ("smtp.yeah.net", 465, True, False),
    "qq.com": ("smtp.qq.com", 465, True, False),
    "foxmail.com": ("smtp.qq.com", 465, True, False),
    "gmail.com": ("smtp.gmail.com", 465, True, False),
    "outlook.com": ("smtp.office365.com", 587, False, True),
    "hotmail.com": ("smtp.office365.com", 587, False, True),
    "live.com": ("smtp.office365.com", 587, False, True),
    "yahoo.com": ("smtp.mail.yahoo.com", 465, True, False),
    "88.com": ("smtp.88.com", 465, True, False),
    "aliyun.com": ("smtp.aliyun.com", 465, True, False),
    "sina.com": ("smtp.sina.com", 465, True, False),
}

_MX_PATTERNS: list[tuple[str, tuple[str, int, bool, bool]]] = [
    (".google.com", ("smtp.gmail.com", 465, True, False)),
    (".googlemail.com", ("smtp.gmail.com", 465, True, False)),
    (".outlook.com", ("smtp.office365.com", 587, False, True)),
    (".protection.outlook.com", ("smtp.office365.com", 587, False, True)),
    (".qq.com", ("smtp.qq.com", 465, True, False)),
    (".mxhichina.com", ("smtp.mxhichina.com", 465, True, False)),
    (".feishu.cn", ("smtp.feishu.cn", 465, True, False)),
    (".zoho.com", ("smtp.zoho.com", 465, True, False)),
    (".mxroute.com", ("mail.mxroute.com", 465, True, False)),
    (".163.com", ("smtp.163.com", 465, True, False)),
    (".netease.com", ("smtp.163.com", 465, True, False)),
    (".yandex.net", ("smtp.yandex.com", 465, True, False)),
    (".secureserver.net", ("smtpout.secureserver.net", 465, True, False)),
]


def guess_smtp_settings(email: str) -> tuple[str, int, bool, bool] | None:
    domain = email.rsplit("@", 1)[-1].lower()
    if domain in KNOWN_SMTP:
        return KNOWN_SMTP[domain]
    return _guess_smtp_from_mx(domain)


def _guess_smtp_from_mx(domain: str) -> tuple[str, int, bool, bool] | None:
    import dns.resolver

    try:
        answers = dns.resolver.resolve(domain, "MX")
    except Exception:
        return None

    for rdata in answers:
        mx_host = str(rdata.exchange).rstrip(".").lower()
        for suffix, settings in _MX_PATTERNS:
            if mx_host.endswith(suffix):
                return settings
    return None


def send_email(
    profile: SmtpProfile,
    *,
    to: list[str],
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    subject: str = "",
    body: str = "",
    html_body: str = "",
    html_base_dir: Path | None = None,
    attachments: list[Path] | None = None,
    inline_images: list[InlineImage] | None = None,
    in_reply_to: str = "",
) -> None:
    msg = MIMEMultipart("mixed")
    related = MIMEMultipart("related")
    alternative = MIMEMultipart("alternative")
    msg.attach(related)
    related.attach(alternative)

    sender = f"{profile.display_name} <{profile.email}>" if profile.display_name else profile.email
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to

    prepared_inline_images: list[InlineImage] = list(inline_images or [])
    if html_body:
        html_body, local_inline_images = prepare_html_inline_images(html_body, base_dir=html_base_dir)
        prepared_inline_images.extend(local_inline_images)

    if html_body and not body:
        body = html_to_plain_text(html_body)

    if body:
        alternative.attach(MIMEText(body, "plain", "utf-8"))
    if html_body:
        alternative.attach(MIMEText(html_body, "html", "utf-8"))
    elif body:
        alternative.attach(MIMEText(f"<html><body><p>{html.escape(body)}</p></body></html>", "html", "utf-8"))

    for image in prepared_inline_images:
        image_bytes = image.content if image.content is not None else (image.path.read_bytes() if image.path is not None else b"")
        main_type, _, sub_type = image.mime_type.partition("/")
        if main_type == "image":
            part = MIMEImage(image_bytes, _subtype=sub_type or None)
        else:
            part = MIMEBase(main_type or "application", sub_type or "octet-stream")
            part.set_payload(image_bytes)
            encoders.encode_base64(part)
        part.add_header("Content-ID", f"<{image.cid}>")
        part.add_header("Content-Disposition", "inline", filename=image.filename)
        related.attach(part)

    for attachment in attachments or []:
        data = attachment.read_bytes()
        mime_type, _ = mimetypes.guess_type(attachment.name)
        main_type, _, sub_type = (mime_type or "application/octet-stream").partition("/")
        part = MIMEBase(main_type or "application", sub_type or "octet-stream")
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment", filename=attachment.name)
        msg.attach(part)

    all_recipients = list(to) + (cc or []) + (bcc or [])

    if profile.use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(profile.smtp_host, profile.smtp_port, context=context) as server:
            server.login(profile.effective_username, profile.password)
            server.sendmail(profile.email, all_recipients, msg.as_string())
    else:
        with smtplib.SMTP(profile.smtp_host, profile.smtp_port) as server:
            if profile.use_starttls:
                server.starttls(context=ssl.create_default_context())
            server.login(profile.effective_username, profile.password)
            server.sendmail(profile.email, all_recipients, msg.as_string())
