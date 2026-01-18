import logging
import os
import time
from datetime import datetime, timedelta, timezone

import httpx

from connectors_common.dedup import find_best_match, prepare_candidates
from connectors_common.opencti_client import OpenCTIClient, ReportInput
from connectors_common.enrichment import apply_label_rules, source_confidence, source_labels
from connectors_common.extractors import extract_cves, extract_iocs
from connectors_common.state_store import StateStore
from connectors_common.llm import summarize_text
from connectors_common.text_utils import extract_main_text
from connectors_common.url_utils import canonicalize_url, url_hash

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger(__name__)


def fetch_items(api_key: str, library_type: str, library_id: str, since_version: str | None) -> tuple[list[dict], str | None]:
    base_url = f"https://api.zotero.org/{library_type}s/{library_id}/items"
    headers = {"Zotero-API-Key": api_key}
    params = {"limit": 50}
    if since_version:
        params["since"] = since_version
    with httpx.Client(timeout=30) as client:
        response = client.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        items = response.json()
        last_version = response.headers.get("Last-Modified-Version")
    return items, last_version


def fetch_approved_tags(briefing_url: str) -> set[str]:
    url = f"{briefing_url.rstrip('/')}/zotero/tags/approved.json"
    payload = None
    for attempt in range(3):
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(url)
                response.raise_for_status()
                payload = response.json()
                break
        except Exception as exc:
            if attempt == 2:
                logger.warning("zotero_tag_filter_unavailable error=%s", exc)
            time.sleep(2)
    if payload is None:
        return set()
    try:
        return {str(tag) for tag in payload if str(tag).strip()}
    except Exception:
        return set()


def fetch_approved_collections(briefing_url: str) -> set[str]:
    url = f"{briefing_url.rstrip('/')}/zotero/collections/approved.json"
    payload = None
    for attempt in range(3):
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(url)
                response.raise_for_status()
                payload = response.json()
                break
        except Exception as exc:
            if attempt == 2:
                logger.warning("zotero_collection_filter_unavailable error=%s", exc)
            time.sleep(2)
    if payload is None:
        return set()
    try:
        return {str(collection_id) for collection_id in payload if str(collection_id).strip()}
    except Exception:
        return set()


def main() -> None:
    api_key = os.getenv("ZOTERO_API_KEY", "")
    library_id = os.getenv("ZOTERO_LIBRARY_ID", "")
    library_type = os.getenv("ZOTERO_LIBRARY_TYPE", "user")
    opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
    use_connector_token = os.getenv("OPENCTI_USE_CONNECTOR_TOKEN", "").lower() == "true"
    opencti_token = ""
    if use_connector_token:
        opencti_token = os.getenv("OPENCTI_TOKEN", "")
    if not opencti_token:
        opencti_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
    fallback_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN", "")
    briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
    interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "600"))
    dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_ZOTERO", "7"))
    dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_ZOTERO", "0.85"))

    if not api_key or not library_id:
        logger.warning("zotero_not_configured")

    state = StateStore("/data/state.json")
    client = OpenCTIClient(opencti_url, opencti_token, fallback_token=fallback_token)

    while True:
        try:
            since_version = state.get("last_version")
            approved_tags = fetch_approved_tags(briefing_url)
            approved_collections = fetch_approved_collections(briefing_url)
            if not approved_tags and not approved_collections:
                logger.info("zotero_no_approved_filters")
                time.sleep(interval)
                continue
            recent_reports = client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=dedup_days))
            candidates = prepare_candidates(recent_reports)
            items, last_version = fetch_items(api_key, library_type, library_id, since_version) if api_key and library_id else ([], None)
            for item in items:
                data = item.get("data", {})
                tag_values = set()
                for tag in data.get("tags") or []:
                    if isinstance(tag, dict):
                        tag_value = tag.get("tag")
                    else:
                        tag_value = tag
                    if isinstance(tag_value, str) and tag_value.strip():
                        tag_values.add(tag_value.strip())
                collection_values = {str(cid) for cid in data.get("collections") or [] if str(cid).strip()}
                if approved_tags or approved_collections:
                    if not (tag_values.intersection(approved_tags) or collection_values.intersection(approved_collections)):
                        continue
                source_url = canonicalize_url(data.get("url") or "")
                url_digest = url_hash(source_url)
                if url_digest and not state.remember_hash("zotero", url_digest):
                    logger.info(
                        "report_skipped source=zotero reason=duplicate_hash title=%s",
                        data.get("title") or "Zotero item",
                    )
                    continue
                if source_url and client.report_exists_by_external_reference(source_url):
                    logger.info(
                        "report_skipped source=zotero reason=existing_external_reference title=%s",
                        data.get("title") or "Zotero item",
                    )
                    continue

                text = extract_main_text(data.get("abstractNote") or "")
                summary = summarize_text(text)
                if summary:
                    text = f"{text}\n\nSummary:\n{summary}"
                cves = extract_cves(text)
                iocs = extract_iocs(text)
                labels = ["source:zotero"] + source_labels("zotero")
                labels += [f"cve:{cve}" for cve in cves]
                labels += [f"ioc:url" for _ in iocs["urls"]]
                labels += [f"ioc:domain" for _ in iocs["domains"]]
                labels += apply_label_rules(text)
                labels = sorted({label for label in labels if label})

                creators = data.get("creators") or []
                author = None
                if creators:
                    author = creators[0].get("name")
                report = ReportInput(
                    title=data.get("title") or "Zotero item",
                    description=text,
                    published=data.get("date"),
                    source_name="zotero",
                    source_url=source_url or None,
                    author=author,
                    labels=labels,
                    confidence=source_confidence("zotero"),
                    external_id=url_digest or None,
                )
                duplicate = find_best_match(report.title, candidates, dedup_threshold)
                if duplicate:
                    new_conf = report.confidence or 0
                    old_conf = duplicate.confidence or 0
                    if source_url and new_conf < old_conf:
                        client.add_external_reference_to_report(
                            duplicate.report_id,
                            report.source_name,
                            source_url,
                            report.external_id,
                        )
                        logger.info(
                            "report_skipped source=zotero reason=lower_confidence_duplicate title=%s",
                            report.title,
                        )
                        continue

                report_id = client.create_report(report)
                if report_id:
                    logger.info("report_created source=zotero id=%s title=%s", report_id, report.title)
                    if duplicate:
                        client.create_relationship(report_id, duplicate.report_id, "related-to")
                    for cve in cves:
                        vuln_id = client.create_vulnerability(cve)
                        if vuln_id:
                            client.create_relationship(report_id, vuln_id, "related-to")
                    for url in iocs["urls"]:
                        obs_id = client.create_observable("Url", url)
                        if obs_id:
                            client.create_relationship(report_id, obs_id, "related-to")
                    for domain in iocs["domains"]:
                        obs_id = client.create_observable("Domain-Name", domain)
                        if obs_id:
                            client.create_relationship(report_id, obs_id, "related-to")
                    for ip in iocs["ipv4"]:
                        obs_id = client.create_observable("IPv4-Addr", ip)
                        if obs_id:
                            client.create_relationship(report_id, obs_id, "related-to")
                else:
                    logger.info("report_skipped source=zotero reason=create_failed title=%s", report.title)
            if last_version and last_version != since_version:
                state.set("last_version", last_version)
            logger.info("zotero_run_completed items=%s", len(items))
        except Exception as exc:
            logger.exception("zotero_run_failed error=%s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
