import base64
from pathlib import Path
from unittest.mock import MagicMock, patch

from mailmaster.email_renderer import (
    RenderedMarkdownEmail,
    html_to_plain_text,
    prepare_html_inline_images,
    render_markdown_email,
)
from mailmaster.smtp import (
    SmtpProfile,
    guess_smtp_settings,
    profile_from_server_config,
    send_email,
)


def test_smtp_profile_password_encoding() -> None:
    p = SmtpProfile(email="a@b.com", smtp_host="smtp.b.com")
    p.password = "secret123"
    assert p.password == "secret123"
    assert p.password_b64 != "secret123"


def test_smtp_profile_effective_username() -> None:
    p = SmtpProfile(email="a@b.com", smtp_host="smtp.b.com")
    assert p.effective_username == "a@b.com"
    p.username = "custom_user"
    assert p.effective_username == "custom_user"


def test_guess_smtp_settings() -> None:
    result = guess_smtp_settings("user@163.com")
    assert result is not None
    host, port, use_ssl, use_starttls = result
    assert host == "smtp.163.com"
    assert port == 465
    assert use_ssl is True


def test_guess_smtp_settings_mx_fallback() -> None:
    """When domain is not in KNOWN_SMTP, fall back to MX lookup."""
    from mailmaster.smtp import _guess_smtp_from_mx

    # Mock dns.resolver to simulate a Google Workspace domain
    mock_rdata = MagicMock()
    mock_rdata.exchange = "aspmx.l.google.com."
    mock_answers = [mock_rdata]
    with patch("dns.resolver.resolve", return_value=mock_answers):
        result = _guess_smtp_from_mx("custom-domain.com")
    assert result is not None
    assert result[0] == "smtp.gmail.com"

    # Unknown MX should return None
    mock_rdata.exchange = "mail.some-random-host.org."
    with patch("dns.resolver.resolve", return_value=[mock_rdata]):
        assert _guess_smtp_from_mx("random.org") is None

    # DNS failure should return None, not raise
    with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
        assert _guess_smtp_from_mx("nonexistent.invalid") is None


def test_profile_from_server_config() -> None:
    profile = profile_from_server_config(
        "test@example.com",
        {
            "host": "smtp.example.com",
            "port": 465,
            "user": "smtp-user",
            "password": "secret123",
            "sslType": 1,
        },
    )
    assert profile.smtp_host == "smtp.example.com"
    assert profile.smtp_port == 465
    assert profile.effective_username == "smtp-user"
    assert profile.password == "secret123"
    assert profile.use_ssl is True


def test_render_markdown_email() -> None:
    rendered = render_markdown_email("# Title\n\n- one\n- two\n\n**bold**")
    plain = rendered.plain_text
    html = rendered.html

    assert "Title" in plain
    assert "one" in plain
    assert "two" in plain
    assert "<html>" in html
    assert "background:#f3f4f6" in html
    assert "<h1" in html and ">Title</h1>" in html
    assert "<strong>bold</strong>" in html
    assert isinstance(rendered, RenderedMarkdownEmail)


def test_render_markdown_email_with_latex() -> None:
    rendered = render_markdown_email("Inline formula $E=mc^2$ and block:\n\n$$\\int_0^1 x^2 dx$$", latex_mode="mathml")

    assert "mathml-formula" in rendered.html
    assert len(rendered.inline_images) == 0
    assert "[formula]" in rendered.plain_text


def test_render_markdown_email_with_latex_auto_mode() -> None:
    rendered = render_markdown_email("Inline formula $E=mc^2$", latex_mode="auto")
    assert rendered.plain_text


def test_render_markdown_email_with_latex_raw_mode() -> None:
    rendered = render_markdown_email("Inline $E=mc^2$", latex_mode="raw")
    assert "<code" in rendered.html and ">E=mc^2</code>" in rendered.html


def test_html_to_plain_text() -> None:
    text = html_to_plain_text("<html><body><h1>Title</h1><p>Hello <strong>world</strong></p></body></html>")
    assert "Title" in text
    assert "Hello" in text


def test_prepare_html_inline_images(tmp_path: Path) -> None:
    png_data = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wn7n6QAAAAASUVORK5CYII="
    )
    image_path = tmp_path / "tiny.png"
    image_path.write_bytes(png_data)

    html, images = prepare_html_inline_images(f'<p><img src="{image_path.name}" alt="tiny"></p>', base_dir=tmp_path)

    assert "cid:mailmaster-" in html
    assert len(images) == 1
    assert images[0].path == image_path


def test_send_email_with_attachment_and_inline_image(tmp_path: Path) -> None:
    image_path = tmp_path / "tiny.png"
    image_path.write_bytes(
        base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wn7n6QAAAAASUVORK5CYII=")
    )
    attachment_path = tmp_path / "note.txt"
    attachment_path.write_text("hello", encoding="utf-8")

    p = SmtpProfile(email="a@b.com", smtp_host="smtp.b.com", smtp_port=465, use_ssl=True)
    p.password = "pass"

    mock_server = MagicMock()
    with patch("mailmaster.smtp.smtplib.SMTP_SSL") as mock_cls:
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        send_email(
            p,
            to=["r@c.com"],
            subject="Hi",
            html_body=f'<p>img</p><img src="{image_path.name}">',
            html_base_dir=tmp_path,
            attachments=[attachment_path],
        )

        raw_message = mock_server.sendmail.call_args[0][2]
        assert "Content-ID: <mailmaster-" in raw_message
        assert 'filename="note.txt"' in raw_message


def test_send_email_ssl() -> None:
    p = SmtpProfile(email="a@b.com", smtp_host="smtp.b.com", smtp_port=465, use_ssl=True)
    p.password = "pass"

    mock_server = MagicMock()
    with patch("mailmaster.smtp.smtplib.SMTP_SSL") as mock_cls:
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        send_email(p, to=["r@c.com"], subject="Hi", body="Hello")

        mock_cls.assert_called_once()
        mock_server.login.assert_called_once_with("a@b.com", "pass")
        mock_server.sendmail.assert_called_once()
        args = mock_server.sendmail.call_args
        assert args[0][0] == "a@b.com"
        assert args[0][1] == ["r@c.com"]


def test_send_email_starttls() -> None:
    p = SmtpProfile(email="a@b.com", smtp_host="smtp.b.com", smtp_port=587, use_ssl=False, use_starttls=True)
    p.password = "pass"

    mock_server = MagicMock()
    with patch("mailmaster.smtp.smtplib.SMTP") as mock_cls:
        mock_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_cls.return_value.__exit__ = MagicMock(return_value=False)
        send_email(p, to=["r@c.com"], cc=["cc@c.com"], subject="Hi", body="Hello")

        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("a@b.com", "pass")
        args = mock_server.sendmail.call_args
        assert args[0][1] == ["r@c.com", "cc@c.com"]
