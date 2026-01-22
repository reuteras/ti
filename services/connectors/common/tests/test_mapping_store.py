from connectors_common.mapping_store import MappingStore


def test_mapping_store_round_trip(tmp_path) -> None:
    db_path = tmp_path / "mapping.sqlite"
    store = MappingStore(str(db_path))

    store.upsert_url("hash1", "https://example.com", "report-1", "Report")
    assert store.get_by_url_hash("hash1") == "report-1"

    store.upsert_external_id("readwise_doc", "123", "report-2", "Report")
    assert store.get_by_external_id("readwise_doc", "123") == "report-2"

    store.upsert_doi("10.1234/abc", "report-3", "Report")
    assert store.get_by_doi("10.1234/abc") == "report-3"

    store.upsert_content_fp("fp1", "report-4", "Report")
    assert store.get_by_content_fp("fp1") == "report-4"

    store.upsert_title_fp("title1", "report-5", "Report")
    assert store.get_by_title_fp("title1") == "report-5"
