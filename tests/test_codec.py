from mailmaster.codec import html_to_text


def test_html_to_text_strips_markup() -> None:
    html = "<html><body><h1>Hello</h1><p>World</p></body></html>"
    assert html_to_text(html) == "Hello\nWorld"

