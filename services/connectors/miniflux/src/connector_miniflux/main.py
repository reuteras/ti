import hashlib
import logging
import os
import time
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from dateutil.parser import isoparse
from pycti import OpenCTIConnectorHelper

from connectors_common.dedup import find_best_match, prepare_candidates
from connectors_common.fingerprint import content_fingerprint
from connectors_common.identity import CandidateIdentity, resolve_canonical_id, store_identity_mappings
from connectors_common.mapping_store import MappingStore
from connectors_common.opencti_client import OpenCTIClient, ReportInput
from connectors_common.enrichment import source_confidence, source_labels
from connectors_common.state_store import StateStore
from connectors_common.denylist import filter_values
from connectors_common.text_utils import extract_main_text, format_readable_text
from connectors_common.url_utils import canonicalize_url, url_hash
from connectors_common.work import WorkTracker

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger(__name__)


def _split_authors(value: str | None) -> list[str]:
    if not value:
        return []
    parts = [part.strip() for part in re.split(r"[;,]", value) if part.strip()]
    candidates = parts or [value.strip()]
    return filter_values(candidates, "persons")


def _select_opencti_token() -> str:
    return os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")


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


def _text_too_short(value: str, min_chars: int = 120, min_words: int = 15) -> bool:
    text = (value or "").strip()
    if len(text) < min_chars:
        return True
    words = [part for part in text.split() if part]
    return len(words) < min_words


def _fetch_source_text(url: str) -> str:
    if not url:
        return ""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; OpenCTI Miniflux Connector)"}
    try:
        with httpx.Client(timeout=20, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                return ""
            return response.text or ""
    except Exception:
        return ""


def _author_key(prefix: str, feed_id: int | None, source_url: str, name: str) -> str:
    if feed_id:
        return f"{prefix}:{feed_id}"
    host = urlparse(source_url or "").netloc.lower()
    if host:
        return f"{prefix}:{host}"
    if name:
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        return f"{prefix}:unknown:{digest}"
    return ""

def _derive_org_name(feed_title: str, source_url: str) -> str:
    raw = (feed_title or "").strip()
    separators = [" - ", " | ", " — ", " – ", ": "]
    for sep in separators:
        if sep in raw:
            raw = raw.split(sep, 1)[0].strip()
            break
    lowered = raw.lower()
    suffixes = [
        "security blog",
        "research blog",
        "blog",
        "news",
        "updates",
        "security",
        "threat research",
    ]
    for suffix in suffixes:
        if lowered.endswith(suffix):
            raw = raw[: -len(suffix)].strip(" -–—|:")
            break
    if raw:
        return raw
    host = urlparse(source_url or "").netloc
    if host:
        return host.split(":")[0]
    return ""



class MinifluxConnector:
    def __init__(self) -> None:
        self.base_url = os.getenv("MINIFLUX_URL", "")
        self.token = os.getenv("MINIFLUX_API_KEY", "")
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
        opencti_token = _select_opencti_token()
        if not opencti_token:
            raise RuntimeError("miniflux_missing_token")

        connector_id = os.getenv("CONNECTOR_ID", "").strip()
        if not connector_id:
            raise RuntimeError("miniflux_missing_connector_id")
        connector_name = os.getenv("CONNECTOR_NAME", "Miniflux")
        connector_type = os.getenv("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
        connector_scope = os.getenv("CONNECTOR_SCOPE", "miniflux")
        connector_log_level = os.getenv("CONNECTOR_LOG_LEVEL", "info")

        def _build_helper(token: str) -> OpenCTIConnectorHelper:
            config = {
                "opencti": {"url": opencti_url, "token": token},
                "connector": {
                    "id": connector_id,
                    "type": connector_type,
                    "name": connector_name,
                    "scope": connector_scope,
                    "log_level": connector_log_level,
                },
            }
            return OpenCTIConnectorHelper(config)

        self.helper = _build_helper(opencti_token)
        self.fallback_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN", "")
        self.interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "600"))
        self.lookback_days = int(os.getenv("MINIFLUX_INITIAL_LOOKBACK_DAYS", "31"))
        self.briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
        self.dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_MINIFLUX", "7"))
        self.dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_MINIFLUX", "0.85"))
        self.state = StateStore("/data/state.json")
        mapping_path = os.getenv("TI_MAPPING_DB", "/data/mapping/ti-mapping.sqlite")
        self.mapping = MappingStore(mapping_path)
        self.allow_title_fallback = os.getenv("TI_ALLOW_TITLE_FALLBACK", "false").lower() == "true"
        self.store_html_note = os.getenv("STORE_HTML_NOTE", "false").lower() == "true"
        default_confidence = os.getenv("TI_CONFIDENCE_IMPORT", "").strip()
        self.default_confidence = int(default_confidence) if default_confidence else None
        self.client = OpenCTIClient(opencti_url, opencti_token, fallback_token=self.fallback_token)

    def _resolve_author(self, key: str, name: str, identity_type: str) -> str | None:
        if not key or not name:
            return None
        map_key = f"author_id:{key}"
        author_id = self.state.get(map_key)
        if author_id:
            self.client.update_identity_name(author_id, name)
            return author_id
        author_id = self.client.create_identity(name, identity_type=identity_type)
        if author_id:
            self.state.set(map_key, author_id)
        return author_id

    def _run(self) -> None:
        if not self.base_url or not self.token:
            logger.warning("miniflux_not_configured")
            return

        work = WorkTracker(self.helper, "Miniflux import")
        approved_feed_ids = fetch_approved_feed_ids(self.briefing_url)
        if not approved_feed_ids:
            logger.info("miniflux_no_approved_feeds")
            work.done("No approved feeds")
            return
        work.log(f"approved_feeds={len(approved_feed_ids)}")

        last_id = int(self.state.get("last_entry_id", 0) or 0)
        last_published_raw = self.state.get("last_published_at")
        if last_published_raw:
            cutoff_dt = isoparse(last_published_raw)
        else:
            cutoff_dt = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)

        recent_reports = self.client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=self.dedup_days))
        candidates = prepare_candidates(recent_reports)

        max_published_dt = cutoff_dt
        max_entry_id = last_id
        offset = 0
        limit = 100
        total_entries = 0
        processed_entries = 0

        while True:
            entries = fetch_entries(self.base_url, self.token, offset, limit)
            if not entries:
                break
            total_entries += len(entries)
            reached_cutoff = False
            for entry in entries:
                processed_entries += 1
                if processed_entries % 50 == 0:
                    work.progress(None, f"processed_entries={processed_entries}")
                entry_id = int(entry.get("id", 0) or 0)
                feed_id = int(entry.get("feed_id", 0) or 0)
                if feed_id not in approved_feed_ids:
                    continue
                published = entry.get("published_at") or entry.get("updated_at") or entry.get("created_at")
                if not published:
                    published_dt = datetime.now(timezone.utc)
                else:
                    published_dt = isoparse(published)

                if published_dt < cutoff_dt or (published_dt == cutoff_dt and entry_id <= last_id):
                    reached_cutoff = True
                    continue

                source_url = canonicalize_url(entry.get("url") or "")
                url_digest = url_hash(source_url)

                content_html = entry.get("content") or ""
                summary_html = entry.get("summary") or ""
                base_html = content_html or summary_html
                text = extract_main_text(base_html)
                if _text_too_short(text):
                    source_html = _fetch_source_text(source_url)
                    if source_html:
                        text = extract_main_text(source_html)
                text = format_readable_text(text)
                if _text_too_short(text):
                    text = "No data from source."
                content_fp = content_fingerprint(text)
                labels = ["source:miniflux"] + source_labels("miniflux")
                feed_title = ""
                feed_meta = entry.get("feed") or {}
                if isinstance(feed_meta, dict):
                    feed_title = feed_meta.get("title") or ""
                    feed_url = canonicalize_url(feed_meta.get("feed_url") or "")
                    site_url = canonicalize_url(feed_meta.get("site_url") or "")
                else:
                    feed_url = ""
                    site_url = ""
                if not feed_title:
                    feed_title = entry.get("feed_title") or ""
                author_name = (entry.get("author") or "").strip()
                author_ids: list[str] = []
                authors = _split_authors(author_name)
                author_id = None
                if authors:
                    author_name = "; ".join(authors)
                    primary = authors[0]
                    author_key = _author_key("miniflux", feed_id, source_url, primary)
                    author_id = self._resolve_author(author_key, primary, "Individual")
                    if author_id:
                        author_ids.append(author_id)
                    for name in authors[1:]:
                        extra_key = _author_key("miniflux", feed_id, source_url, name)
                        extra_id = self._resolve_author(extra_key, name, "Individual")
                        if extra_id:
                            author_ids.append(extra_id)
                org_name = _derive_org_name(feed_title, source_url)
                org_id = None
                if org_name:
                    org_key = _author_key("miniflux-org", feed_id, source_url, org_name)
                    org_id = self._resolve_author(org_key, org_name, "Organization")

                confidence = source_confidence("miniflux")
                if confidence is None:
                    confidence = self.default_confidence
                report = ReportInput(
                    title=entry.get("title") or "Miniflux entry",
                    description=text,
                    published=published_dt.isoformat(),
                    source_name="miniflux",
                    source_url=source_url or None,
                    author=author_name or None,
                    created_by_id=author_id,
                    labels=labels,
                    confidence=confidence,
                    external_id=url_digest or None,
                )
                external_ids: list[tuple[str, str]] = []
                guid = entry.get("guid")
                if guid:
                    external_ids.append(("rss_guid", str(guid)))
                if entry_id:
                    external_ids.append(("miniflux_entry", str(entry_id)))
                candidate = CandidateIdentity(
                    urls=[source_url] if source_url else [],
                    external_ids=external_ids,
                    content_fp=content_fp or None,
                    title=report.title,
                    published=published_dt.isoformat(),
                )
                report_id, match_reason = resolve_canonical_id(
                    self.mapping,
                    candidate,
                    allow_title_fallback=self.allow_title_fallback,
                )
                if not report_id and self.allow_title_fallback:
                    duplicate = find_best_match(report.title, candidates, self.dedup_threshold)
                    if duplicate:
                        report_id = duplicate.report_id
                        match_reason = "title_similarity"
                if not report_id:
                    report_id = self.client.create_report(report)
                if report_id:
                    logger.info(
                        "report_upserted source=miniflux id=%s title=%s match=%s",
                        report_id,
                        report.title,
                        match_reason or "created",
                    )
                    existing_url_owner = self.mapping.get_by_url_hash(url_digest)
                    store_identity_mappings(self.mapping, report_id, "Report", candidate)
                    should_add_ref = True
                    if url_digest:
                        should_add_ref = self.state.remember_hash(
                            "external_ref",
                            f"{report_id}:{url_digest}",
                        )
                    if source_url and existing_url_owner is None and should_add_ref:
                        self.client.add_external_reference_to_report(
                            report_id,
                            "miniflux",
                            source_url,
                            url_digest or None,
                        )
                    if source_url and entry_id:
                        should_add_entry_ref = self.state.remember_hash(
                            "external_ref",
                            f"{report_id}:entry:{entry_id}",
                        )
                        if should_add_entry_ref:
                            self.client.add_external_reference_to_report(
                                report_id,
                                "miniflux_entry",
                                source_url,
                                str(entry_id),
                            )
                    if feed_url:
                        should_add_feed_ref = self.state.remember_hash(
                            "external_ref",
                            f"{report_id}:feed:{feed_id}:{feed_url}",
                        )
                        if should_add_feed_ref:
                            self.client.add_external_reference_to_report(
                                report_id,
                                "miniflux_feed",
                                feed_url,
                                str(feed_id) if feed_id else None,
                            )
                    if site_url and not feed_url:
                        should_add_site_ref = self.state.remember_hash(
                            "external_ref",
                            f"{report_id}:site:{site_url}",
                        )
                        if should_add_site_ref:
                            self.client.add_external_reference_to_report(
                                report_id,
                                "miniflux_site",
                                site_url,
                                None,
                            )
                    for author_id in author_ids:
                        self.client.create_relationship(report_id, author_id, "related-to")
                    if org_id:
                        self.client.create_relationship(report_id, org_id, "related-to")
                    if self.store_html_note:
                        html_note = content_html or summary_html
                        if html_note:
                            note_body = f"Miniflux HTML\n\n{html_note}"
                            self.client.create_note(
                                note_body,
                                object_refs=[report_id],
                                labels=["source:miniflux", "html"],
                            )
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
            self.state.set("last_entry_id", max_entry_id)
            self.state.set("last_published_at", max_published_dt.isoformat())
        logger.info("miniflux_run_completed entries=%s", total_entries)
        work.done(f"entries={total_entries}")

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)


def main() -> None:
    try:
        connector = MinifluxConnector()
    except Exception as exc:
        logger.warning("miniflux_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
