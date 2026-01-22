import hashlib
import re
import unicodedata


_WHITESPACE_RE = re.compile(r"\s+")


def normalize_text(value: str) -> str:
    if not value:
        return ""
    normalized = unicodedata.normalize("NFKC", value)
    normalized = _WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


def content_fingerprint(text: str, max_chars: int = 8000) -> str:
    if not text:
        return ""
    normalized = normalize_text(text)
    if not normalized:
        return ""
    snippet = normalized[:max_chars]
    return hashlib.sha256(snippet.encode("utf-8")).hexdigest()
