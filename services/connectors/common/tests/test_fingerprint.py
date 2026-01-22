from connectors_common.fingerprint import content_fingerprint, normalize_text


def test_normalize_text_collapses_whitespace() -> None:
    raw = "Hello\tworld\n\nNext"
    assert normalize_text(raw) == "Hello world Next"


def test_content_fingerprint_is_stable() -> None:
    first = content_fingerprint("Hello   world")
    second = content_fingerprint("Hello world")
    assert first == second
