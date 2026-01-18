import logging
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
from dateutil.parser import isoparse

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


def _normalize_base_url(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    if base_url.endswith("/v1"):
        return base_url[:-3]
    return base_url


def fetch_entries(base_url: str, token: str, offset: int, limit: int) -> list[dict]:
    url = f"{_normalize_base_url(base_url)}/v1/entries"
    headers = {"X-Auth-Token": token}
    params = {"limit": limit, "offset": offset, "order": "published_at", "direction": "desc"}
    with httpx.Client(timeout=30) as client:
        response = client.get(url, headers=headers, params=params)
        response.raise_for_status()
        payload = response.json()
    return payload.get("entries", [])


def fetch_approved_feed_ids(briefing_url: str) -> set[int]:
    url = f"{briefing_url.rstrip('/')}/miniflux/feeds/approved.json"
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
                logger.warning("miniflux_feed_filter_unavailable error=%s", exc)
            time.sleep(2)
    if payload is None:
        return set()
    try:
        return {int(feed_id) for feed_id in payload}
    except Exception:
        return set()




def main() -> None:
    base_url = os.getenv("MINIFLUX_URL", "")
    token = os.getenv("MINIFLUX_TOKEN", "")
    opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
    use_connector_token = os.getenv("OPENCTI_USE_CONNECTOR_TOKEN", "").lower() == "true"
    opencti_token = ""
    if use_connector_token:
        opencti_token = os.getenv("OPENCTI_TOKEN", "")
    if not opencti_token:
        opencti_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
    fallback_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN", "")
    interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "600"))
    lookback_days = int(os.getenv("MINIFLUX_INITIAL_LOOKBACK_DAYS", "31"))
    briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
    dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_MINIFLUX", "7"))
    dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_MINIFLUX", "0.85"))

    if not base_url or not token:
        logger.warning("miniflux_not_configured")

    state = StateStore("/data/state.json")
    client = OpenCTIClient(opencti_url, opencti_token, fallback_token=fallback_token)

    while True:
        try:
            approved_feed_ids = fetch_approved_feed_ids(briefing_url)
            if not approved_feed_ids:
                logger.info("miniflux_no_approved_feeds")
                time.sleep(interval)
                continue

            last_id = int(state.get("last_entry_id", 0) or 0)
            last_published_raw = state.get("last_published_at")
            if last_published_raw:
                cutoff_dt = isoparse(last_published_raw)
            else:
                cutoff_dt = datetime.now(timezone.utc) - timedelta(days=lookback_days)

            recent_reports = client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=dedup_days))
            candidates = prepare_candidates(recent_reports)

            max_published_dt = cutoff_dt
            max_entry_id = last_id
            offset = 0
            limit = 100
            total_entries = 0

            while True:
                entries = fetch_entries(base_url, token, offset, limit) if base_url and token else []
                if not entries:
                    break
                total_entries += len(entries)
                reached_cutoff = False
                for entry in entries:
                    entry_id = int(entry.get("id", 0) or 0)
                    feed_id = int(entry.get("feed_id", 0) or 0)
                    if feed_id not in approved_feed_ids:
                        continue
                    published = entry.get("published_at") or entry.get("updated_at") or entry.get("created_at")
                    if not published:
                        published_dt = datetime.now(timezone.utc)
                    else:
                        published_dt = isoparse(published)

                    if published_dt < cutoff_dt or (
                        published_dt == cutoff_dt and entry_id <= last_id
                    ):
                        reached_cutoff = True
                        continue

                    source_url = canonicalize_url(entry.get("url") or "")
                    url_digest = url_hash(source_url)
                    if url_digest and not state.remember_hash("miniflux", url_digest):
                        continue
                    if source_url and client.report_exists_by_external_reference(source_url):
                        continue

                    text = extract_main_text(entry.get("content") or "")
                    summary = summarize_text(text)
                    if summary:
                        text = f"{text}\n\nSummary:\n{summary}"
                    cves = extract_cves(text)
                    iocs = extract_iocs(text)
                    labels = ["source:miniflux"] + source_labels("miniflux")
                    labels += [f"cve:{cve}" for cve in cves]
                    labels += [f"ioc:url" for _ in iocs["urls"]]
                    labels += [f"ioc:domain" for _ in iocs["domains"]]
                    labels += apply_label_rules(text)
                    labels = sorted({label for label in labels if label})

                    report = ReportInput(
                        title=entry.get("title") or "Miniflux entry",
                        description=text,
                        published=published_dt.isoformat(),
                        source_name="miniflux",
                        source_url=source_url or None,
                        labels=labels,
                        confidence=source_confidence("miniflux"),
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
                                "report_skipped source=miniflux reason=lower_confidence_duplicate title=%s",
                                report.title,
                            )
                            continue

                    report_id = client.create_report(report)
                    if report_id:
                        logger.info("report_created source=miniflux id=%s title=%s", report_id, report.title)
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
                        logger.info("report_skipped source=miniflux reason=create_failed title=%s", report.title)
                    if published_dt > max_published_dt or (
                        published_dt == max_published_dt and entry_id > max_entry_id
                    ):
                        max_published_dt = published_dt
                        max_entry_id = entry_id

                if reached_cutoff:
                    break
                offset += limit

            if max_entry_id != last_id or max_published_dt != cutoff_dt:
                state.set("last_entry_id", max_entry_id)
                state.set("last_published_at", max_published_dt.isoformat())
            logger.info("miniflux_run_completed entries=%s", total_entries)
        except Exception as exc:
            logger.exception("miniflux_run_failed error=%s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
