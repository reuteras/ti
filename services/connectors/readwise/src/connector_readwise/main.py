import hashlib
import logging
import os
import time
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone

import httpx
from dateutil.parser import isoparse
from pycti import OpenCTIConnectorHelper
from typing import Any

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


def fetch_documents(token: str, updated_after: str | None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"withHtmlContent": True}
    if updated_after:
        params["updatedAfter"] = updated_after
    documents: list[dict[str, Any]] = []
    next_cursor: str | None = None
    headers = {"Authorization": f"Token {token}"}
    with httpx.Client(timeout=30) as client:
        while True:
            if next_cursor:
                params["pageCursor"] = next_cursor
            response = client.get("https://readwise.io/api/v3/list/", params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
            documents.extend(payload.get("results", []))
            next_cursor = payload.get("nextPageCursor")
            if not next_cursor:
                break
    return documents


def _doc_value(doc: Any, key: str, default: Any = None) -> Any:
    if isinstance(doc, dict):
        return doc.get(key, default)
    return getattr(doc, key, default)


def _collect_tags(doc: Any) -> set[str]:
    tags: set[str] = set()
    doc_tags = _doc_value(doc, "tags")
    if isinstance(doc_tags, dict):
        for key, tag in doc_tags.items():
            name = getattr(tag, "name", None) or key
            if isinstance(name, str) and name.strip():
                tags.add(name.strip())
    elif isinstance(doc_tags, list):
        for name in doc_tags:
            if isinstance(name, str) and name.strip():
                tags.add(name.strip())
    return tags


def _published_from_doc(doc: Any) -> str | None:
    published = _doc_value(doc, "published_date")
    if isinstance(published, (int, float)):
        return datetime.fromtimestamp(published, tz=timezone.utc).isoformat()
    if isinstance(published, str) and published.strip():
        return published.strip()
    updated_at = _doc_value(doc, "updated_at")
    return updated_at if isinstance(updated_at, str) else None


def fetch_approved_tags(briefing_url: str) -> set[str]:
    url = f"{briefing_url.rstrip('/')}/readwise/tags/approved.json"
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
                logger.warning("readwise_tag_filter_unavailable error=%s", exc)
            time.sleep(2)
    if payload is None:
        return set()
    try:
        return {str(tag) for tag in payload if str(tag).strip()}
    except Exception:
        return set()


class ReadwiseConnector:
    def __init__(self) -> None:
        self.token = os.getenv("READWISE_API_KEY", "")
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
        opencti_token = _select_opencti_token()
        if not opencti_token:
            raise RuntimeError("readwise_missing_token")

        connector_id = os.getenv("CONNECTOR_ID", "").strip()
        if not connector_id:
            raise RuntimeError("readwise_missing_connector_id")
        connector_name = os.getenv("CONNECTOR_NAME", "Readwise")
        connector_type = os.getenv("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
        connector_scope = os.getenv("CONNECTOR_SCOPE", "readwise")
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
        self.dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_READWISE", "7"))
        self.dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_READWISE", "0.85"))
        self.briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
        self.state = StateStore("/data/state.json")
        mapping_path = os.getenv("TI_MAPPING_DB", "/data/mapping/ti-mapping.sqlite")
        self.mapping = MappingStore(mapping_path)
        self.allow_title_fallback = os.getenv("TI_ALLOW_TITLE_FALLBACK", "false").lower() == "true"
        self.readwise_lookback_days = int(os.getenv("TI_READWISE_LOOKBACK_DAYS", "14"))
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
        if not self.token:
            logger.warning("readwise_not_configured")
            return
        work = WorkTracker(self.helper, "Readwise import")
        updated_after = self.state.get("updated_after")
        if not updated_after and self.readwise_lookback_days > 0:
            updated_after = (datetime.now(timezone.utc) - timedelta(days=self.readwise_lookback_days)).isoformat()
        approved_tags = fetch_approved_tags(self.briefing_url)
        if not approved_tags:
            logger.info("readwise_no_approved_tags")
            work.done("No approved tags")
            return
        recent_reports = self.client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=self.dedup_days))
        candidates = prepare_candidates(recent_reports)
        documents = fetch_documents(self.token, updated_after)
        total_documents = len(documents)
        work.log(f"documents={total_documents}")
        max_seen_dt = isoparse(updated_after) if updated_after else None
        tag_cache: dict[str, set[str]] = {}
        for doc in documents:
            doc_tags = _collect_tags(doc)
            doc_id = _doc_value(doc, "id")
            if doc_tags and doc_id:
                tag_cache[str(doc_id)] = doc_tags
        last_progress = -1
        for idx, doc in enumerate(documents, start=1):
            if total_documents:
                percent = int((idx / total_documents) * 100)
                if percent >= last_progress + 5:
                    work.progress(percent, f"processed_documents={idx}/{total_documents}")
                    last_progress = percent
            updated_at = _doc_value(doc, "updated_at")
            updated_iso = isoparse(updated_at).isoformat() if updated_at else None
            doc_tags = _collect_tags(doc)
            parent_id = _doc_value(doc, "parent_id")
            if not doc_tags and parent_id:
                doc_tags = tag_cache.get(str(parent_id), set())
            if not doc_tags.intersection(approved_tags):
                logger.info(
                    "report_skipped source=readwise reason=tag_not_approved title=%s",
                    _doc_value(doc, "title") or "Readwise document",
                )
                continue

            raw_url = _doc_value(doc, "source_url") or _doc_value(doc, "url") or ""
            source_url = canonicalize_url(raw_url)
            url_digest = url_hash(source_url)

            category = (_doc_value(doc, "category") or "").lower()
            doc_id = _doc_value(doc, "id")
            full_text_input = (
                _doc_value(doc, "html_content")
                or _doc_value(doc, "htmlContent")
                or _doc_value(doc, "content")
                or ""
            )
            text_input = full_text_input or _doc_value(doc, "summary") or _doc_value(doc, "notes") or ""
            summary_text = _doc_value(doc, "summary") or ""
            text = extract_main_text(text_input)
            text = format_readable_text(text)
            full_text = ""
            if full_text_input:
                full_text = format_readable_text(extract_main_text(full_text_input))
            content_fp = content_fingerprint(text)
            labels = ["source:readwise"] + source_labels("readwise")
            author_name = (_doc_value(doc, "author") or "").strip()
            author_ids: list[str] = []
            authors = _split_authors(author_name)
            author_id = None
            if authors:
                author_name = "; ".join(authors)
                primary = authors[0]
                author_key = _author_key("readwise", source_url, primary)
                author_id = self._resolve_author(author_key, primary, "Individual")
                if author_id:
                    author_ids.append(author_id)
                for name in authors[1:]:
                    extra_key = _author_key("readwise", source_url, name)
                    extra_id = self._resolve_author(extra_key, name, "Individual")
                    if extra_id:
                        author_ids.append(extra_id)

            title = _doc_value(doc, "title") or "Readwise document"
            published = _published_from_doc(doc)
            external_ids: list[tuple[str, str]] = []
            if doc_id is not None:
                external_ids.append(("readwise_doc", str(doc_id)))

            if category in {"highlight", "note"} and parent_id:
                parent_report_id = self.mapping.get_by_external_id("readwise_doc", str(parent_id))
                if not parent_report_id:
                    logger.warning(
                        "readwise_parent_missing category=%s parent_id=%s title=%s",
                        category,
                        parent_id,
                        title,
                    )
                    continue
                if doc_id is not None:
                    existing_note = self.mapping.get_by_external_id("readwise_doc_note", str(doc_id))
                    if existing_note:
                        continue
                note_lines = []
                if title and title != "Readwise document":
                    note_lines.append(title)
                if text:
                    note_lines.append(text)
                if source_url:
                    note_lines.append(f"Source: {source_url}")
                note_content = "\n\n".join(line for line in note_lines if line)
                if not note_content:
                    continue
                note_id = self.client.create_note(
                    note_content,
                    object_refs=[parent_report_id],
                    labels=["source:readwise", f"readwise:{category}"],
                )
                if note_id and doc_id is not None:
                    self.mapping.upsert_external_id(
                        "readwise_doc_note",
                        str(doc_id),
                        note_id,
                        "Note",
                    )
                continue
            url_candidates = [source_url] if source_url else []
            confidence = source_confidence("readwise")
            if confidence is None:
                confidence = self.default_confidence
            candidate = CandidateIdentity(
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
            created_new = False
            if not report_id:
                report = ReportInput(
                    title=title,
                    description=text,
                    published=published,
                    source_name="readwise",
                    source_url=source_url or None,
                    author=author_name or None,
                    created_by_id=author_id,
                    labels=labels,
                    confidence=confidence,
                    external_id=url_digest or None,
                )
                report_id = self.client.create_report(report)
                created_new = report_id is not None
            if report_id:
                logger.info(
                    "report_upserted source=readwise id=%s title=%s match=%s",
                    report_id,
                    title,
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
                        "readwise",
                        source_url,
                        url_digest or None,
                    )
                for author_id in author_ids:
                    self.client.create_relationship(report_id, author_id, "related-to")
                if full_text:
                    existing_description = None
                    if not created_new:
                        existing_description = self.client.get_report_description(report_id)
                    if created_new:
                        existing_description = text
                    if existing_description is None:
                        existing_description = ""
                    existing_value = existing_description.strip()
                    full_value = full_text.strip()
                    if full_value and full_value != existing_value and len(full_value) > len(existing_value) + 200:
                        self.client.update_report_description(report_id, full_value)
                if summary_text and doc_id is not None:
                    summary_value = format_readable_text(extract_main_text(summary_text))
                    if summary_value:
                        external_id = f"{doc_id}:summary"
                        existing_note = self.mapping.get_by_external_id("readwise_summary", external_id)
                        if not existing_note:
                            note_id = self.client.create_note(
                                f"Readwise summary\n\n{summary_value}",
                                object_refs=[report_id],
                                labels=["summary", "source:readwise"],
                            )
                            if note_id:
                                self.mapping.upsert_external_id(
                                    "readwise_summary",
                                    external_id,
                                    note_id,
                                    "Note",
                                )
                highlights = getattr(doc, "highlights", None) or []
                self._handle_extracted_links(report_id, text_input, highlights)
                for highlight in highlights:
                    highlight_id = _doc_value(highlight, "id")
                    if highlight_id is None:
                        continue
                    external_id = str(highlight_id)
                    existing_note = self.mapping.get_by_external_id("readwise_highlight", external_id)
                    if existing_note:
                        continue
                    excerpt = _doc_value(highlight, "text") or ""
                    note_text = (_doc_value(highlight, "note") or "").strip()
                    location = _doc_value(highlight, "location")
                    location_type = _doc_value(highlight, "location_type")
                    lines = []
                    if excerpt:
                        lines.append(excerpt.strip())
                    if note_text:
                        lines.append(f"Note: {note_text}")
                    if location is not None:
                        lines.append(f"Location: {location}")
                    if location_type:
                        lines.append(f"Location type: {location_type}")
                    if source_url:
                        lines.append(f"Source: {source_url}")
                    content = "\n".join(line for line in lines if line)
                    if not content:
                        continue
                    note_id = self.client.create_note(
                        content,
                        object_refs=[report_id],
                        labels=["source:readwise"],
                    )
                    if note_id:
                        self.mapping.upsert_external_id(
                            "readwise_highlight",
                            external_id,
                            note_id,
                            "Note",
                        )
            else:
                logger.info("report_skipped source=readwise reason=create_failed title=%s", title)
            if updated_iso:
                updated_dt = isoparse(updated_iso)
                if not max_seen_dt or updated_dt > max_seen_dt:
                    max_seen_dt = updated_dt
        if max_seen_dt:
            self.state.set("updated_after", max_seen_dt.isoformat())
        logger.info("readwise_run_completed documents=%s", len(documents))
        work.done(f"documents={len(documents)}")

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)

    def _handle_extracted_links(self, report_id: str, text_input: str, highlights: list) -> None:
        if self.link_strategy == "none":
            return
        urls = set()
        urls.update(_extract_urls(text_input or ""))
        for highlight in highlights or []:
            urls.update(_extract_urls(_doc_value(highlight, "text") or ""))
            urls.update(_extract_urls(_doc_value(highlight, "note") or ""))
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
                    self.client.add_external_reference_to_report(report_id, "readwise", canonical, digest)
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
        confidence = source_confidence("readwise")
        if confidence is None:
            confidence = self.default_confidence
        report = ReportInput(
            title=title,
            description="Referenced link from Readwise.",
            published=None,
            source_name="readwise-link",
            source_url=url,
            labels=["source:readwise"],
            confidence=confidence,
        )
        report_id = self.client.create_report(report)
        if report_id:
            store_identity_mappings(self.mapping, report_id, "Report", candidate)
        return report_id


def main() -> None:
    try:
        connector = ReadwiseConnector()
    except Exception as exc:
        logger.warning("readwise_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
