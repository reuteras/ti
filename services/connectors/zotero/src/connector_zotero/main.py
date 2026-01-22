import hashlib
import logging
import os
import time
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone

import httpx
from dateutil import parser as date_parser
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
from connectors_common.url_utils import canonicalize_url, normalize_doi, url_hash
from connectors_common.work import WorkTracker

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s<>\"]+")


def _clean_url(value: str) -> str:
    if not value:
        return ""
    return value.strip(".,;:!?)}]>'\"")


def _extract_urls(text: str) -> set[str]:
    if not text:
        return set()
    urls = {_clean_url(match) for match in _URL_RE.findall(text)}
    return {url for url in urls if url}


def _split_authors(value: str | None) -> list[str]:
    if not value:
        return []
    parts = [part.strip() for part in re.split(r"[;,]", value) if part.strip()]
    candidates = parts or [value.strip()]
    return filter_values(candidates, "persons")


def _select_opencti_token() -> str:
    return os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")


def _author_key(prefix: str, source_url: str, name: str) -> str:
    host = urlparse(source_url or "").netloc.lower()
    if host:
        return f"{prefix}:{host}"
    if name:
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        return f"{prefix}:unknown:{digest}"
    return ""


def _parse_zotero_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = date_parser.parse(value)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


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


class ZoteroConnector:
    def __init__(self) -> None:
        self.api_key = os.getenv("ZOTERO_API_KEY", "")
        self.library_id = os.getenv("ZOTERO_LIBRARY_ID", "")
        self.library_type = os.getenv("ZOTERO_LIBRARY_TYPE", "user")
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
        opencti_token = _select_opencti_token()
        if not opencti_token:
            raise RuntimeError("zotero_missing_token")

        connector_id = os.getenv("CONNECTOR_ID", "").strip()
        if not connector_id:
            raise RuntimeError("zotero_missing_connector_id")
        connector_name = os.getenv("CONNECTOR_NAME", "Zotero")
        connector_type = os.getenv("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
        connector_scope = os.getenv("CONNECTOR_SCOPE", "zotero")
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
        self.briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
        self.interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "600"))
        self.dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_ZOTERO", "7"))
        self.dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_ZOTERO", "0.85"))
        self.state = StateStore("/data/state.json")
        mapping_path = os.getenv("TI_MAPPING_DB", "/data/mapping/ti-mapping.sqlite")
        self.mapping = MappingStore(mapping_path)
        self.allow_title_fallback = os.getenv("TI_ALLOW_TITLE_FALLBACK", "false").lower() == "true"
        self.zotero_lookback_days = int(os.getenv("TI_ZOTERO_LOOKBACK_DAYS", "30"))
        link_strategy = os.getenv("TI_LINK_STRATEGY", "none").lower()
        self.link_strategy = link_strategy if link_strategy in {"report", "reference_only", "none"} else "none"
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
        if not self.api_key or not self.library_id:
            logger.warning("zotero_not_configured")
            return
        work = WorkTracker(self.helper, "Zotero import")
        since_version = self.state.get("last_version")
        cutoff_dt = None
        if not since_version and self.zotero_lookback_days > 0:
            cutoff_dt = datetime.now(timezone.utc) - timedelta(days=self.zotero_lookback_days)
        approved_tags = fetch_approved_tags(self.briefing_url)
        approved_collections = fetch_approved_collections(self.briefing_url)
        if not approved_tags and not approved_collections:
            logger.info("zotero_no_approved_filters")
            work.done("No approved filters")
            return
        recent_reports = self.client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=self.dedup_days))
        candidates = prepare_candidates(recent_reports)
        items, last_version = fetch_items(self.api_key, self.library_type, self.library_id, since_version)
        total_items = len(items)
        work.log(f"items={total_items}")
        annotations = []
        last_progress = -1
        for idx, item in enumerate(items, start=1):
            if total_items:
                percent = int((idx / total_items) * 100)
                if percent >= last_progress + 5:
                    work.progress(percent, f"processed_items={idx}/{total_items}")
                    last_progress = percent
            data = item.get("data", {})
            if data.get("itemType") == "annotation":
                annotations.append(item)
                continue
            if cutoff_dt:
                date_value = data.get("dateModified") or data.get("dateAdded") or data.get("date")
                parsed = _parse_zotero_date(date_value)
                if parsed and parsed < cutoff_dt:
                    continue
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

            text = extract_main_text(data.get("abstractNote") or "")
            text = format_readable_text(text)
            content_fp = content_fingerprint(text)
            labels = ["source:zotero"] + source_labels("zotero")

            creators = data.get("creators") or []
            author = None
            if creators:
                primary = creators[0]
                if isinstance(primary, dict):
                    author = primary.get("name")
                    if not author:
                        first = primary.get("firstName") or ""
                        last = primary.get("lastName") or ""
                        author = f"{first} {last}".strip()
            author_ids: list[str] = []
            authors = _split_authors(author)
            author_id = None
            if authors:
                author = "; ".join(authors)
                primary = authors[0]
                author_key = _author_key("zotero", source_url, primary)
                author_id = self._resolve_author(author_key, primary, "Individual")
                if author_id:
                    author_ids.append(author_id)
                for name in authors[1:]:
                    extra_key = _author_key("zotero", source_url, name)
                    extra_id = self._resolve_author(extra_key, name, "Individual")
                    if extra_id:
                        author_ids.append(extra_id)
            title = data.get("title") or "Zotero item"
            published = data.get("date")
            item_key = item.get("key") or data.get("key")
            external_ids: list[tuple[str, str]] = []
            if item_key:
                external_ids.append(("zotero_item", str(item_key)))
            doi = normalize_doi(data.get("DOI") or data.get("doi") or "")
            url_candidates = [source_url] if source_url else []
            if doi:
                url_candidates.append(f"https://doi.org/{doi}")
            confidence = source_confidence("zotero")
            if confidence is None:
                confidence = self.default_confidence
            candidate = CandidateIdentity(
                doi=doi or None,
                urls=url_candidates,
                external_ids=external_ids,
                content_fp=content_fp or None,
                title=title,
                published=published,
            )
            report_id, match_reason = resolve_canonical_id(
                self.mapping,
                candidate,
                allow_title_fallback=self.allow_title_fallback,
            )
            if not report_id and self.allow_title_fallback:
                duplicate = find_best_match(title, candidates, self.dedup_threshold)
                if duplicate:
                    report_id = duplicate.report_id
                    match_reason = "title_similarity"
            if not report_id:
                report = ReportInput(
                    title=title,
                    description=text,
                    published=published,
                    source_name="zotero",
                    source_url=source_url or None,
                    author=author or None,
                    created_by_id=author_id,
                    labels=labels,
                    confidence=confidence,
                    external_id=url_digest or None,
                )
                report_id = self.client.create_report(report)
            if report_id:
                logger.info(
                    "report_upserted source=zotero id=%s title=%s match=%s",
                    report_id,
                    title,
                    match_reason or "created",
                )
                existing_url_owner = self.mapping.get_by_url_hash(url_digest)
                existing_doi_owner = self.mapping.get_by_doi(doi) if doi else None
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
                        "zotero",
                        source_url,
                        url_digest or None,
                    )
                should_add_doi = True
                if doi:
                    should_add_doi = self.state.remember_hash(
                        "external_ref",
                        f"{report_id}:doi:{doi}",
                    )
                if doi and existing_doi_owner is None and should_add_doi:
                    doi_url = f"https://doi.org/{doi}"
                    self.client.add_external_reference_to_report(
                        report_id,
                        "doi",
                        doi_url,
                        doi,
                    )
                for author_id in author_ids:
                    self.client.create_relationship(report_id, author_id, "related-to")
            else:
                logger.info("report_skipped source=zotero reason=create_failed title=%s", title)
        for item in annotations:
            data = item.get("data", {})
            parent_key = data.get("parentItem")
            if not parent_key:
                continue
            report_id = self.mapping.get_by_external_id("zotero_item", str(parent_key))
            if not report_id:
                continue
            annotation_text = (data.get("annotationText") or "").strip()
            annotation_comment = (data.get("annotationComment") or "").strip()
            page_label = data.get("annotationPageLabel")
            annotation_key = item.get("key") or data.get("key")
            if annotation_key:
                external_id = f"{parent_key}:{annotation_key}"
            else:
                fingerprint = f"{parent_key}:{page_label or ''}:{annotation_text.lower()[:200]}"
                external_id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
            existing_note = self.mapping.get_by_external_id("zotero_annot", external_id)
            if existing_note:
                continue
            lines = []
            if annotation_text:
                lines.append(annotation_text)
            if annotation_comment:
                lines.append(f"Note: {annotation_comment}")
            if page_label:
                lines.append(f"Page: {page_label}")
            if parent_key:
                lines.append(f"Source: zotero:{parent_key}")
            content = "\n".join(lines)
            if not content:
                continue
            note_id = self.client.create_note(
                content,
                object_refs=[report_id],
                labels=["source:zotero"],
            )
            if note_id and external_id:
                self.mapping.upsert_external_id("zotero_annot", external_id, note_id, "Note")
            self._handle_extracted_links(report_id, annotation_text, annotation_comment)
        if last_version and last_version != since_version:
            self.state.set("last_version", last_version)
        logger.info("zotero_run_completed items=%s", len(items))
        work.done(f"items={len(items)}")

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)

    def _handle_extracted_links(self, report_id: str, annotation_text: str, annotation_comment: str) -> None:
        if self.link_strategy == "none":
            return
        urls = set()
        urls.update(_extract_urls(annotation_text or ""))
        urls.update(_extract_urls(annotation_comment or ""))
        if not urls:
            return
        linked_ids: set[str] = set()
        for raw_url in urls:
            canonical = canonicalize_url(raw_url)
            if not canonical:
                continue
            digest = url_hash(canonical)
            if not digest:
                continue
            existing_id = self.mapping.get_by_url_hash(digest)
            if existing_id:
                if existing_id != report_id and existing_id not in linked_ids:
                    self.client.create_relationship(report_id, existing_id, "related-to")
                    linked_ids.add(existing_id)
                continue
            if self.link_strategy == "reference_only":
                should_add_ref = self.state.remember_hash(
                    "external_ref",
                    f"{report_id}:{digest}",
                )
                if should_add_ref:
                    self.client.add_external_reference_to_report(report_id, "zotero", canonical, digest)
                continue
            if self.link_strategy == "report":
                linked_id = self._resolve_or_create_linked_report(canonical)
                if linked_id and linked_id != report_id and linked_id not in linked_ids:
                    self.client.create_relationship(report_id, linked_id, "related-to")
                    linked_ids.add(linked_id)

    def _resolve_or_create_linked_report(self, url: str) -> str | None:
        candidate = CandidateIdentity(urls=[url])
        report_id, _ = resolve_canonical_id(self.mapping, candidate, allow_title_fallback=False)
        if report_id:
            return report_id
        title = url
        confidence = source_confidence("zotero")
        if confidence is None:
            confidence = self.default_confidence
        report = ReportInput(
            title=title,
            description="Referenced link from Zotero annotation.",
            published=None,
            source_name="zotero-link",
            source_url=url,
            labels=["source:zotero"],
            confidence=confidence,
        )
        report_id = self.client.create_report(report)
        if report_id:
            store_identity_mappings(self.mapping, report_id, "Report", candidate)
        return report_id


def main() -> None:
    try:
        connector = ZoteroConnector()
    except Exception as exc:
        logger.warning("zotero_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
