"""Email body rendering helpers for Markdown/HTML/LaTeX email content."""
from __future__ import annotations

import html
import importlib
import io
import mimetypes
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import latex2mathml.converter
import markdown2
from bs4 import BeautifulSoup


@dataclass
class InlineImage:
    path: Path | None
    cid: str
    mime_type: str
    filename: str
    content: bytes | None = None


@dataclass
class RenderedMarkdownEmail:
    plain_text: str
    html: str
    inline_images: list[InlineImage]


LatexMode = Literal["auto", "mathml", "image", "raw"]


_EMAIL_CONTAINER_STYLE = "margin:0 auto;max-width:860px;padding:24px;color:#24292f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;line-height:1.65;font-size:16px;background:#ffffff;"
_TAG_STYLES = {
    "h1": "font-size:28px;line-height:1.25;margin:0 0 16px;color:#111827;border-bottom:1px solid #e5e7eb;padding-bottom:8px;",
    "h2": "font-size:22px;line-height:1.3;margin:28px 0 12px;color:#111827;",
    "h3": "font-size:18px;line-height:1.35;margin:24px 0 10px;color:#111827;",
    "p": "margin:0 0 14px;",
    "a": "color:#2563eb;text-decoration:none;",
    "blockquote": "margin:16px 0;padding:12px 16px;border-left:4px solid #93c5fd;background:#f8fafc;color:#475569;",
    "hr": "border:none;border-top:1px solid #e5e7eb;margin:24px 0;",
    "ul": "margin:0 0 16px 20px;padding:0;",
    "ol": "margin:0 0 16px 20px;padding:0;",
    "li": "margin:6px 0;",
    "table": "border-collapse:collapse;width:100%;margin:16px 0;font-size:14px;",
    "th": "border:1px solid #d0d7de;padding:8px 10px;background:#f6f8fa;text-align:left;",
    "td": "border:1px solid #d0d7de;padding:8px 10px;vertical-align:top;",
    "pre": "margin:16px 0;padding:14px 16px;background:#0f172a;color:#e2e8f0;border-radius:8px;overflow-x:auto;font-size:13px;line-height:1.55;",
    "code": "font-family:SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;",
}


def _apply_email_html_styles(html_body: str) -> str:
    soup = BeautifulSoup(html_body, "html.parser")

    for tag_name, style in _TAG_STYLES.items():
        for tag in soup.find_all(tag_name):
            existing = tag.get("style", "")
            tag["style"] = f"{existing};{style}" if existing else style

    for tag in soup.find_all("code"):
        if tag.parent and tag.parent.name == "pre":
            tag["style"] = f"{tag.get('style', '')};background:none;color:inherit;padding:0;border-radius:0;".strip(";")
        else:
            tag["style"] = f"{tag.get('style', '')};background:#f6f8fa;color:#b42318;padding:2px 5px;border-radius:4px;font-size:0.95em;".strip(";")

    for checkbox in soup.find_all("input"):
        if checkbox.get("type") == "checkbox":
            checkbox["disabled"] = "disabled"
            checkbox["style"] = "margin-right:8px;"

    body_html = "".join(str(node) for node in soup.contents).strip()
    return (
        "<html><head><meta charset=\"utf-8\"></head>"
        "<body style=\"margin:0;padding:0;background:#f3f4f6;\">"
        f"<div style=\"{_EMAIL_CONTAINER_STYLE}\">{body_html}</div>"
        "</body></html>"
    )


def _resolve_local_image_path(src: str, base_dir: Path | None) -> Path | None:
    if not src or src.startswith(("http://", "https://", "cid:", "data:")):
        return None

    candidate = src
    if src.startswith("file:///"):
        candidate = src[8:]
    elif src.startswith("file://"):
        candidate = src[7:]

    path = Path(candidate)
    if not path.is_absolute() and base_dir is not None:
        path = (base_dir / path).resolve()

    if not path.exists() or not path.is_file():
        return None
    return path


def prepare_html_inline_images(html_body: str, *, base_dir: Path | None = None) -> tuple[str, list[InlineImage]]:
    soup = BeautifulSoup(html_body, "html.parser")
    images: list[InlineImage] = []

    for tag in soup.find_all("img"):
        src = str(tag.get("src") or "").strip()
        path = _resolve_local_image_path(src, base_dir)
        if path is None:
            continue

        mime_type, _ = mimetypes.guess_type(path.name)
        mime_type = mime_type or "application/octet-stream"
        cid = f"mailmaster-{uuid.uuid4().hex}"
        tag["src"] = f"cid:{cid}"
        existing = tag.get("style", "")
        img_style = "max-width:100%;height:auto;border:1px solid #e5e7eb;border-radius:8px;"
        tag["style"] = f"{existing};{img_style}".strip(";") if existing else img_style
        images.append(InlineImage(path=path, cid=cid, mime_type=mime_type, filename=path.name))

    return str(soup), images


def extract_latex_formulas(text: str) -> tuple[str, list[tuple[str, str, bool]]]:
    formulas: list[tuple[str, str, bool]] = []

    def replace_block(match: re.Match[str]) -> str:
        latex = match.group(1).strip()
        placeholder = f"FORMULABLOCK{uuid.uuid4().hex}"
        formulas.append((placeholder, latex, True))
        return placeholder

    def replace_inline(match: re.Match[str]) -> str:
        latex = match.group(1).strip()
        placeholder = f"FORMULAINLINE{uuid.uuid4().hex}"
        formulas.append((placeholder, latex, False))
        return placeholder

    text = re.sub(r"[$][$](.+?)[$][$]", replace_block, text, flags=re.DOTALL)
    text = re.sub(r"(?<![$])[$](?![$])(.+?)(?<![$])[$](?![$])", replace_inline, text, flags=re.DOTALL)
    return text, formulas


def render_latex_to_mathml(latex: str, *, block: bool) -> str:
    mathml = latex2mathml.converter.convert(latex)
    wrapper = "div" if block else "span"
    display = "display:block;margin:16px auto;overflow-x:auto;" if block else "display:inline-block;vertical-align:middle;"
    return f'<{wrapper} class="mathml-formula" data-latex="{html.escape(latex)}" style="{display}">{mathml}</{wrapper}>'


def render_latex_to_inline_image(latex: str, *, block: bool) -> InlineImage:
    try:
        matplotlib = importlib.import_module("matplotlib")
        mathtext = importlib.import_module("matplotlib.mathtext")
    except ImportError as exc:
        raise RuntimeError(
            "LaTeX image rendering requires the optional dependency group `latex-image`. "
            "Install with: `uv sync --extra latex-image` or equivalent extra install."
        ) from exc

    matplotlib.use("Agg")
    expression = f"${latex}$"
    buffer = io.BytesIO()
    mathtext.math_to_image(expression, buffer, dpi=200, format="png")
    return InlineImage(
        path=None,
        cid=f"formula-{uuid.uuid4().hex}",
        mime_type="image/png",
        filename=("formula-block" if block else "formula-inline") + ".png",
        content=buffer.getvalue(),
    )


def has_latex_image_support() -> bool:
    try:
        importlib.import_module("matplotlib")
        importlib.import_module("matplotlib.mathtext")
        return True
    except ImportError:
        return False


def replace_formula_placeholders(html_body: str, formulas: list[tuple[str, str, bool]], *, latex_mode: LatexMode) -> tuple[str, list[InlineImage]]:
    inline_images: list[InlineImage] = []
    rendered_html = html_body
    effective_mode: Literal["mathml", "image", "raw"]
    if latex_mode == "auto":
        effective_mode = "image" if has_latex_image_support() else "raw"
    else:
        effective_mode = latex_mode

    for placeholder, latex, is_block in formulas:
        if effective_mode == "image":
            image = render_latex_to_inline_image(latex, block=is_block)
            style = "display:block;margin:16px auto;max-width:100%;height:auto;" if is_block else "display:inline-block;vertical-align:middle;max-width:100%;height:auto;"
            rendered_html = rendered_html.replace(placeholder, f'<img src="cid:{image.cid}" alt="{html.escape(latex)}" style="{style}">')
            inline_images.append(image)
        elif effective_mode == "mathml":
            rendered_html = rendered_html.replace(placeholder, render_latex_to_mathml(latex, block=is_block))
        else:
            replacement = f'<pre><code>{html.escape(latex)}</code></pre>' if is_block else f'<code>{html.escape(latex)}</code>'
            rendered_html = rendered_html.replace(placeholder, replacement)
    return rendered_html, inline_images


def replace_formula_placeholders_for_plain(html_body: str, formulas: list[tuple[str, str, bool]]) -> str:
    rendered_html = html_body
    for placeholder, latex, is_block in formulas:
        replacement = f'<p>[formula] {html.escape(latex)}</p>' if is_block else f'<code>{html.escape(latex)}</code>'
        rendered_html = rendered_html.replace(placeholder, replacement)
    return rendered_html


def html_to_plain_text(html_body: str) -> str:
    plain = BeautifulSoup(html_body, "html.parser").get_text("\n")
    lines = [line.rstrip() for line in plain.splitlines()]
    normalized: list[str] = []
    previous_blank = False
    for line in lines:
        blank = not line.strip()
        if blank and previous_blank:
            continue
        normalized.append(line)
        previous_blank = blank
    return "\n".join(normalized).strip()


def render_markdown_email(markdown_text: str, *, latex_mode: LatexMode = "auto") -> RenderedMarkdownEmail:
    processed_markdown, formulas = extract_latex_formulas(markdown_text)
    html_body = markdown2.markdown(
        processed_markdown,
        extras=[
            "fenced-code-blocks",
            "tables",
            "strike",
            "task_list",
            "cuddled-lists",
            "break-on-newline",
            "code-friendly",
            "target-blank-links",
        ],
    )
    plain_source_html = replace_formula_placeholders_for_plain(html_body, formulas)
    formula_html, formula_images = replace_formula_placeholders(html_body, formulas, latex_mode=latex_mode)
    styled_html = _apply_email_html_styles(formula_html)
    plain = html_to_plain_text(_apply_email_html_styles(plain_source_html))
    return RenderedMarkdownEmail(plain_text=plain, html=styled_html, inline_images=formula_images)
