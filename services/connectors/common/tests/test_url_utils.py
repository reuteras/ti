from connectors_common.url_utils import canonicalize_url, normalize_doi, url_hash


def test_canonicalize_url_strips_trackers_and_ports() -> None:
    url = "https://Example.com:443/path/?utm_source=x&b=2&a=1#section"
    normalized = canonicalize_url(url)
    assert normalized == "https://example.com/path?a=1&b=2"


def test_normalize_doi_formats() -> None:
    assert normalize_doi("10.1234/ABC") == "10.1234/abc"
    assert normalize_doi("https://doi.org/10.1234/ABC") == "10.1234/abc"
    assert normalize_doi("doi:10.1234/ABC") == "10.1234/abc"


def test_url_hash_is_stable() -> None:
    first = url_hash("https://example.com/path/?b=2&a=1")
    second = url_hash("https://example.com/path?a=1&b=2")
    assert first == second
