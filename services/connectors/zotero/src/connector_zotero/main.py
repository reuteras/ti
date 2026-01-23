import hashlib
import logging
import os
import time
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from dateutil import parser as date_parser
from pycti import OpenCTIConnectorHelper
from pyzotero import zotero, zotero_errors

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


def fetch_items(client: zotero.Zotero, since_version: str | None) -> tuple[list[dict], str | None, int]:
    first_page = client.items(limit=50, since=since_version)
    items = list(first_page)
    page_count = 1
    for page in client.iterfollow():
        if not page:
            break
        items.extend(page)
        page_count += 1
    last_version = getattr(client, "last_modified_version", None)
    logger.info("zotero_items pages=%s items=%s", page_count, len(items))
    return items, last_version, page_count


def fetch_item_by_key(client: zotero.Zotero, item_key: str) -> dict | None:
    if not item_key:
        return None
    try:
        return client.item(item_key)
    except zotero_errors.ResourceNotFound:
        return None


def fetch_fulltext_changes(
    api_key: str, library_type: str, library_id: str, since_version: str | None
) -> tuple[list[str], str | None, int]:
    base_url = f"https://api.zotero.org/{library_type}s/{library_id}/fulltext"
    headers = {"Zotero-API-Key": api_key}
    params = {}
    if since_version:
        params["since"] = since_version
    keys: list[str] = []
    last_version: str | None = None
    page_count = 0
    with httpx.Client(timeout=30) as client:
        next_url = base_url
        next_params = params
        while next_url:
            response = client.get(next_url, headers=headers, params=next_params)
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict):
                keys.extend([key for key in payload.keys() if isinstance(key, str)])
            last_version = response.headers.get("Last-Modified-Version") or last_version
            next_link = response.links.get("next")
            next_url = next_link.get("url") if next_link else None
            next_params = None
            page_count += 1
    logger.info("zotero_fulltext_changes pages=%s keys=%s", page_count, len(keys))
    return keys, last_version, page_count


def fetch_attachment_fulltext(
    api_key: str, library_type: str, library_id: str, item_key: str
) -> dict[str, Any] | None:
    if not item_key:
        return None
    base_url = f"https://api.zotero.org/{library_type}s/{library_id}/items/{item_key}/fulltext"
    headers = {"Zotero-API-Key": api_key}
    with httpx.Client(timeout=30) as client:
        response = client.get(base_url, headers=headers)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        return None
    return payload


def normalize_fulltext(text: str) -> str:
    if not text:
        return ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip() for line in normalized.split("\n"))
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized


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
        self.note_max_chars = int(os.getenv("NOTE_MAX_CHARS", "150000"))
        self.client = OpenCTIClient(opencti_url, opencti_token, fallback_token=self.fallback_token)
        self.zotero = (
            zotero.Zotero(self.library_id, self.library_type, self.api_key)
            if self.api_key and self.library_id
            else None
        )

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

    def _extract_tags_and_collections(self, data: dict) -> tuple[set[str], set[str]]:
        tag_values = set()
        for tag in data.get("tags") or []:
            if isinstance(tag, dict):
                tag_value = tag.get("tag")
            else:
                tag_value = tag
            if isinstance(tag_value, str) and tag_value.strip():
                tag_values.add(tag_value.strip())
        collection_values = {str(cid) for cid in data.get("collections") or [] if str(cid).strip()}
        return tag_values, collection_values

    def _allowed_item(
        self, data: dict, approved_tags: set[str], approved_collections: set[str]
    ) -> bool:
        if not approved_tags and not approved_collections:
            return True
        tag_values, collection_values = self._extract_tags_and_collections(data)
        return bool(tag_values.intersection(approved_tags) or collection_values.intersection(approved_collections))

    def _upsert_report(
        self,
        data: dict,
        item_key: str | None,
        candidates: list[dict],
        approved_tags: set[str],
        approved_collections: set[str],
        cutoff_dt: datetime | None,
    ) -> str | None:
        if cutoff_dt:
            date_value = data.get("dateModified") or data.get("dateAdded") or data.get("date")
            parsed = _parse_zotero_date(date_value)
            if parsed and parsed < cutoff_dt:
                return None
        if not self._allowed_item(data, approved_tags, approved_collections):
            return None

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
        return report_id

    def _build_note_chunks(self, title: str, metadata: str, content: str) -> list[tuple[str, str]]:
        if not content:
            return []
        prefix = f"{metadata}\n\n"
        max_chars = max(1000, self.note_max_chars)
        chunks: list[str] = []
        for start in range(0, len(content), max_chars):
            chunks.append(content[start : start + max_chars])
        total = len(chunks)
        results = []
        for idx, chunk in enumerate(chunks, start=1):
            suffix = f" (part {idx}/{total})" if total > 1 else ""
            results.append((f"{title}{suffix}", f"{prefix}{chunk}"))
        return results

    def _run(self) -> None:
        if not self.api_key or not self.library_id:
            logger.warning("zotero_not_configured")
            return
        work = WorkTracker(self.helper, "Zotero import")
        since_version = self.state.get("last_version")
        since_fulltext_version = self.state.get("last_fulltext_version")
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
        if not self.zotero:
            logger.warning("zotero_not_configured")
            work.done("Zotero not configured")
            return
        items, last_version, item_pages = fetch_items(self.zotero, since_version)
        total_items = len(items)
        work.log(f"items={total_items} pages={item_pages}")
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
            item_key = item.get("key") or data.get("key")
            self._upsert_report(data, item_key, candidates, approved_tags, approved_collections, cutoff_dt)
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
        self._process_fulltext(
            approved_tags,
            approved_collections,
            candidates,
            since_fulltext_version,
        )
        if last_version and last_version != since_version:
            self.state.set("last_version", last_version)
        logger.info("zotero_run_completed items=%s", len(items))
        work.done(f"items={len(items)}")

    def _process_fulltext(
        self,
        approved_tags: set[str],
        approved_collections: set[str],
        candidates: list[dict],
        since_fulltext_version: str | None,
    ) -> None:
        if not self.zotero:
            return
        pending = self.state.get("zotero_fulltext_pending", [])
        if not isinstance(pending, list):
            pending = []
        try:
            changed_keys, last_version, fulltext_pages = fetch_fulltext_changes(
                self.api_key,
                self.library_type,
                self.library_id,
                since_fulltext_version,
            )
        except Exception as exc:
            logger.warning("zotero_fulltext_list_failed error=%s", exc)
            return
        logger.info("zotero_fulltext_pages pages=%s keys=%s", fulltext_pages, len(changed_keys))
        keys = list(dict.fromkeys([*pending, *changed_keys]))
        if not keys:
            if last_version and last_version != since_fulltext_version:
                self.state.set("last_fulltext_version", last_version)
            return
        remaining_pending: list[str] = []
        for attachment_key in keys:
            attachment = fetch_item_by_key(self.zotero, attachment_key)
            if not attachment:
                continue
            data = attachment.get("data", {})
            if data.get("itemType") != "attachment":
                continue
            parent_key = data.get("parentItem")
            if not parent_key:
                continue
            fulltext_payload = fetch_attachment_fulltext(
                self.api_key,
                self.library_type,
                self.library_id,
                attachment_key,
            )
            if fulltext_payload is None:
                remaining_pending.append(attachment_key)
                continue
            content = fulltext_payload.get("content") or ""
            normalized = normalize_fulltext(content)
            if not normalized.strip():
                continue
            content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if not self.state.remember_hash("zotero_fulltext", f"{attachment_key}:{content_hash}"):
                continue

            report_id = self.mapping.get_by_external_id("zotero_item", str(parent_key))
            if not report_id:
                parent_item = fetch_item_by_key(self.zotero, parent_key)
                if not parent_item:
                    continue
                parent_data = parent_item.get("data", {})
                report_id = self._upsert_report(
                    parent_data,
                    parent_key,
                    candidates,
                    approved_tags,
                    approved_collections,
                    cutoff_dt=None,
                )
            if not report_id:
                continue

            attachment_title = data.get("title") or data.get("filename") or f"Attachment {attachment_key}"
            artifact_id = self.client.create_artifact(
                content_hash,
                name=attachment_title,
                url=None,
                mime_type=None,
                additional_names=[f"zotero:{attachment_key}", f"zotero_parent:{parent_key}"],
            )
            if artifact_id:
                self.client.create_relationship(report_id, artifact_id, "related-to")

            doi = normalize_doi((data.get("DOI") or data.get("doi") or ""))
            source_url = canonicalize_url(data.get("url") or "")
            metadata = "\n".join(
                [
                    f"zotero_attachment_key: {attachment_key}",
                    f"zotero_parent_key: {parent_key}",
                    f"doi: {doi}" if doi else "doi:",
                    f"url: {source_url}" if source_url else "url:",
                    f"indexed_pages: {fulltext_payload.get('indexedPages')}",
                    f"total_pages: {fulltext_payload.get('totalPages')}",
                    f"retrieved_at: {datetime.now(timezone.utc).isoformat()}",
                    f"content_sha256: {content_hash}",
                ]
            )
            note_title = f"Zotero fulltext: {attachment_title}"
            chunks = self._build_note_chunks(note_title, metadata, normalized)
            for title, note_content in chunks:
                note_id = self.client.create_note(
                    f"{title}\n{note_content}",
                    object_refs=[ref for ref in [report_id, artifact_id] if ref],
                    labels=["source:zotero"],
                )
                if note_id:
                    self.mapping.upsert_external_id(
                        "zotero_fulltext",
                        f"{attachment_key}:{content_hash}:{title}",
                        note_id,
                        "Note",
                    )
        if remaining_pending:
            self.state.set("zotero_fulltext_pending", remaining_pending)
        else:
            self.state.set("zotero_fulltext_pending", [])
        if last_version and last_version != since_fulltext_version:
            self.state.set("last_fulltext_version", last_version)

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
