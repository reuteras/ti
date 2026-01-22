from connectors_common.identity import CandidateIdentity, resolve_canonical_id, store_identity_mappings
from connectors_common.mapping_store import MappingStore


def test_identity_precedence(tmp_path) -> None:
    db_path = tmp_path / "mapping.sqlite"
    store = MappingStore(str(db_path))

    store.upsert_doi("10.1234/abc", "report-doi", "Report")
    store.upsert_url("urlhash", "https://example.com", "report-url", "Report")
    store.upsert_external_id("readwise_doc", "doc-1", "report-ext", "Report")
    store.upsert_content_fp("fp-1", "report-fp", "Report")

    candidate = CandidateIdentity(
        doi="10.1234/ABC",
        urls=["https://example.com"],
        external_ids=[("readwise_doc", "doc-1")],
        content_fp="fp-1",
    )
    match_id, reason = resolve_canonical_id(store, candidate, allow_title_fallback=True)
    assert match_id == "report-doi"
    assert reason == "doi"


def test_store_identity_mappings(tmp_path) -> None:
    db_path = tmp_path / "mapping.sqlite"
    store = MappingStore(str(db_path))

    candidate = CandidateIdentity(
        doi="10.5555/xyz",
        urls=["https://example.com/path"],
        external_ids=[("readwise_doc", "55")],
        content_fp="fp-55",
        title="Example Report",
        published="2024-01-01",
    )
    store_identity_mappings(store, "report-1", "Report", candidate)
    assert store.get_by_doi("10.5555/xyz") == "report-1"
    assert store.get_by_external_id("readwise_doc", "55") == "report-1"
    assert store.get_by_content_fp("fp-55") == "report-1"
