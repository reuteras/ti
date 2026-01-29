from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


_TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "ref_src",
}


def canonicalize_url(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value.strip())
    netloc = parsed.netloc.lower()
    path = parsed.path
    if netloc in {"twitter.com", "x.com"}:
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 3 and parts[1] == "status":
            path = f"/{parts[0]}/status/{parts[2]}"
    if netloc == "m.medium.com":
        netloc = "medium.com"
    scheme = parsed.scheme.lower()
    if (scheme == "http" and netloc.endswith(":80")) or (
        scheme == "https" and netloc.endswith(":443")
    ):
        netloc = netloc.rsplit(":", 1)[0]
    if path.endswith("/") and path != "/":
        path = path[:-1]
    parsed = parsed._replace(netloc=netloc, path=path)
    query = [(k, v) for k, v in parse_qsl(parsed.query) if k not in _TRACKING_PARAMS]
    query = sorted(query, key=lambda pair: (pair[0], pair[1]))
    normalized = parsed._replace(
        scheme=scheme,
        netloc=parsed.netloc.lower(),
        query=urlencode(query, doseq=True),
        fragment="",
    )
    return urlunparse(normalized)


def url_hash(value: str) -> str:
    canonical = canonicalize_url(value)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest() if canonical else ""


def normalize_doi(value: str) -> str:
    if not value:
        return ""
    doi = value.strip().lower()
    if doi.startswith("https://doi.org/"):
        doi = doi[len("https://doi.org/") :]
    elif doi.startswith("http://doi.org/"):
        doi = doi[len("http://doi.org/") :]
    elif doi.startswith("doi:"):
        doi = doi[len("doi:") :]
    return doi.strip()
