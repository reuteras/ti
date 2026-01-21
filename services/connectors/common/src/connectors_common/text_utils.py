from html.parser import HTMLParser
import logging
import re

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
        text = "".join(self._chunks)
        lines = [" ".join(part.split()) for part in text.splitlines()]
        normalized: list[str] = []
        blank_run = 0
        for line in lines:
            if not line:
                blank_run += 1
                if blank_run <= 2:
                    normalized.append("")
                continue
            blank_run = 0
            normalized.append(line)
        return "\n".join(normalized).strip()


_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\\s+(?=[A-Z])")


def format_readable_text(value: str, max_paragraph_chars: int = 700, sentences_per_paragraph: int = 3) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    paragraphs = [part.strip() for part in text.split("\n\n") if part.strip()]
    if not paragraphs:
        return text
    rebuilt: list[str] = []
    for paragraph in paragraphs:
        if len(paragraph) <= max_paragraph_chars:
            rebuilt.append(paragraph)
            continue
        sentences = [part.strip() for part in _SENTENCE_SPLIT.split(paragraph) if part.strip()]
        if len(sentences) <= 1:
            rebuilt.append(paragraph)
            continue
        chunk: list[str] = []
        for sentence in sentences:
            chunk.append(sentence)
            if len(chunk) >= sentences_per_paragraph:
                rebuilt.append(" ".join(chunk))
                rebuilt.append("")
                chunk = []
        if chunk:
            rebuilt.append(" ".join(chunk))
    return "\n\n".join(part for part in rebuilt if part != "").strip()


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


_MARKDOWN_SPECIALS = re.compile(r"([\\\\`*_{}\\[\\]()>#+\\-.!|])")


def escape_markdown(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    return _MARKDOWN_SPECIALS.sub(r"\\\\\\1", text)
