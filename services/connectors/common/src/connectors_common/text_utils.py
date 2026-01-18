from html.parser import HTMLParser
import logging

try:
    import trafilatura
except Exception:  # pragma: no cover - optional dependency
    trafilatura = None
else:
    logging.getLogger("trafilatura").setLevel(logging.CRITICAL)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self._chunks.append(data)

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"p", "br", "li", "div"}:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"p", "li", "div"}:
            self._chunks.append("\n")

    def get_text(self) -> str:
        text = " ".join(self._chunks)
        lines = [" ".join(part.split()) for part in text.splitlines()]
        return "\n".join(line for line in lines if line)


def html_to_text(value: str) -> str:
    parser = _TextExtractor()
    parser.feed(value or "")
    return parser.get_text()


def extract_main_text(value: str) -> str:
    if trafilatura is None:
        return html_to_text(value)
    if not value:
        return ""
    if "<" not in value:
        return value.strip()
    extracted = trafilatura.extract(value, include_comments=False, include_tables=False)
    return extracted or html_to_text(value)
