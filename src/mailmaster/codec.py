from __future__ import annotations

import re
import zlib

from bs4 import BeautifulSoup


def decode_mail_body(body: bytes | str | None, compress_type: int) -> str:
    if body is None:
        return ""
    raw = body.encode("utf-8", errors="ignore") if isinstance(body, str) else body
    if compress_type == 1:
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            pass
    return raw.decode("utf-8", errors="ignore")


def html_to_text(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
