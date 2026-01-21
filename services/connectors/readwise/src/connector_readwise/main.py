import logging
import os
import time
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone

import httpx
from dateutil.parser import isoparse
from pycti import OpenCTIConnectorHelper
from readwise.api import ReadwiseReader

from connectors_common.dedup import find_best_match, prepare_candidates
from connectors_common.opencti_client import OpenCTIClient, ReportInput
from connectors_common.enrichment import apply_label_rules, source_confidence, source_labels
from connectors_common.extractors import extract_cves, extract_label_entities, extract_iocs
from connectors_common.state_store import StateStore
from connectors_common.llm import summarize_text
from connectors_common.text_utils import extract_main_text
from connectors_common.url_utils import canonicalize_url, url_hash

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger(__name__)

def _select_opencti_token() -> str:
    use_connector_token = os.getenv("OPENCTI_USE_CONNECTOR_TOKEN", "").lower() == "true"
    connector_token = os.getenv("OPENCTI_TOKEN", "")
    if use_connector_token and connector_token and connector_token != "changeme":
        return connector_token
    return os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")


def _author_key(prefix: str, source_url: str, name: str) -> str:
    host = urlparse(source_url or "").netloc.lower()
    if host:
        return f"{prefix}:{host}"
    if name:
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        return f"{prefix}:unknown:{digest}"
    return ""


def fetch_documents(token: str, updated_after: str | None) -> list:
    reader = ReadwiseReader(token=token)
    updated_dt = isoparse(updated_after) if updated_after else None
    return reader.get_documents(updated_after=updated_dt, withHtmlContent=True)


def _collect_tags(doc) -> set[str]:
    tags: set[str] = set()
    doc_tags = getattr(doc, "tags", None)
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


def _published_from_doc(doc) -> str | None:
    published = getattr(doc, "published_date", None)
    if isinstance(published, (int, float)):
        return datetime.fromtimestamp(published, tz=timezone.utc).isoformat()
    if isinstance(published, str) and published.strip():
        return published.strip()
    updated_at = getattr(doc, "updated_at", None)
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
        self.token = os.getenv("READWISE_TOKEN", "")
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
        use_connector_token = os.getenv("OPENCTI_USE_CONNECTOR_TOKEN", "").lower() == "true"
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

        try:
            self.helper = _build_helper(opencti_token)
        except Exception as exc:
            if use_connector_token and admin_token and opencti_token != admin_token:
                logger.warning("readwise_connector_token_invalid_fallback error=%s", exc)
                opencti_token = admin_token
                self.helper = _build_helper(opencti_token)
            else:
                raise
        self.fallback_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN", "")
        self.interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "600"))
        self.dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_READWISE", "7"))
        self.dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_READWISE", "0.85"))
        self.briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
        self.state = StateStore("/data/state.json")
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
        updated_after = self.state.get("updated_after")
        approved_tags = fetch_approved_tags(self.briefing_url)
        if not approved_tags:
            logger.info("readwise_no_approved_tags")
            return
        recent_reports = self.client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=self.dedup_days))
        candidates = prepare_candidates(recent_reports)
        documents = fetch_documents(self.token, updated_after)
        max_seen_dt = isoparse(updated_after) if updated_after else None
        tag_cache: dict[str, set[str]] = {}
        for doc in documents:
            doc_tags = _collect_tags(doc)
            if doc_tags and getattr(doc, "id", None):
                tag_cache[doc.id] = doc_tags
        for doc in documents:
            updated_at = getattr(doc, "updated_at", None)
            updated_iso = isoparse(updated_at).isoformat() if updated_at else None
            doc_tags = _collect_tags(doc)
            if not doc_tags and getattr(doc, "parent_id", None):
                doc_tags = tag_cache.get(doc.parent_id, set())
            if not doc_tags.intersection(approved_tags):
                logger.info(
                    "report_skipped source=readwise reason=tag_not_approved title=%s",
                    getattr(doc, "title", None) or "Readwise document",
                )
                continue

            source_url = canonicalize_url(
                getattr(doc, "source_url", None) or getattr(doc, "url", None) or ""
            )
            url_digest = url_hash(source_url)
            if url_digest and not self.state.remember_hash("readwise", url_digest):
                logger.info(
                    "report_skipped source=readwise reason=duplicate_hash title=%s",
                    getattr(doc, "title", None) or "Readwise document",
                )
                continue
            if source_url and self.client.report_exists_by_external_reference(source_url):
                logger.info(
                    "report_skipped source=readwise reason=existing_external_reference title=%s",
                    getattr(doc, "title", None) or "Readwise document",
                )
                continue

            text_input = (
                getattr(doc, "content", None)
                or getattr(doc, "summary", None)
                or getattr(doc, "notes", None)
                or ""
            )
            text = extract_main_text(text_input)
            summary = summarize_text(text)
            if summary:
                text = f"{text}\n\nSummary:\n{summary}"
            cves = extract_cves(text)
            iocs = extract_iocs(text)
            labels = ["source:readwise"] + source_labels("readwise")
            labels += [f"cve:{cve}" for cve in cves]
            labels += [f"ioc:url" for _ in iocs["urls"]]
            labels += [f"ioc:domain" for _ in iocs["domains"]]
            labels += apply_label_rules(text)
            labels = sorted({label for label in labels if label})
            label_entities = extract_label_entities(labels)
            cves = sorted(set(cves).union(label_entities["cves"]))
            iocs["urls"] = sorted(set(iocs["urls"]).union(label_entities["urls"]))
            iocs["domains"] = sorted(set(iocs["domains"]).union(label_entities["domains"]))
            iocs["ipv4"] = sorted(set(iocs["ipv4"]).union(label_entities["ipv4"]))
            author_name = (getattr(doc, "author", None) or "").strip()
            author_id = None
            if author_name:
                author_key = _author_key("readwise", source_url, author_name)
                author_id = self._resolve_author(author_key, author_name, "Individual")

            report = ReportInput(
                title=getattr(doc, "title", None) or "Readwise document",
                description=text,
                published=_published_from_doc(doc),
                source_name="readwise",
                source_url=source_url or None,
                author=author_name or None,
                created_by_id=author_id,
                labels=labels,
                confidence=source_confidence("readwise"),
                external_id=url_digest or None,
            )
            duplicate = find_best_match(report.title, candidates, self.dedup_threshold)
            if duplicate:
                new_conf = report.confidence or 0
                old_conf = duplicate.confidence or 0
                if source_url and new_conf < old_conf:
                    self.client.add_external_reference_to_report(
                        duplicate.report_id,
                        report.source_name,
                        source_url,
                        report.external_id,
                    )
                    logger.info(
                        "report_skipped source=readwise reason=lower_confidence_duplicate title=%s",
                        report.title,
                    )
                    continue

            report_id = self.client.create_report(report)
            if report_id:
                logger.info("report_created source=readwise id=%s title=%s", report_id, report.title)
                if duplicate:
                    self.client.create_relationship(report_id, duplicate.report_id, "related-to")
                for cve in cves:
                    vuln_id = self.client.create_vulnerability(cve)
                    if vuln_id:
                        self.client.create_relationship(report_id, vuln_id, "related-to")
                for url in iocs["urls"]:
                    obs_id = self.client.create_observable("Url", url)
                    if obs_id:
                        self.client.create_relationship(report_id, obs_id, "related-to")
                for domain in iocs["domains"]:
                    obs_id = self.client.create_observable("Domain-Name", domain)
                    if obs_id:
                        self.client.create_relationship(report_id, obs_id, "related-to")
                for ip in iocs["ipv4"]:
                    obs_id = self.client.create_observable("IPv4-Addr", ip)
                    if obs_id:
                        self.client.create_relationship(report_id, obs_id, "related-to")
                for name in label_entities["malware"]:
                    malware_id = self.client.create_malware(name)
                    if malware_id:
                        self.client.create_relationship(report_id, malware_id, "related-to")
                for name in label_entities["tools"]:
                    tool_id = self.client.create_tool(name)
                    if tool_id:
                        self.client.create_relationship(report_id, tool_id, "related-to")
                for name in label_entities["threat_actors"]:
                    actor_id = self.client.create_threat_actor(name)
                    if actor_id:
                        self.client.create_relationship(report_id, actor_id, "related-to")
                for name in label_entities["attack_patterns"]:
                    attack_id = self.client.create_attack_pattern(name)
                    if attack_id:
                        self.client.create_relationship(report_id, attack_id, "related-to")
            else:
                logger.info("report_skipped source=readwise reason=create_failed title=%s", report.title)
            if updated_iso:
                updated_dt = isoparse(updated_iso)
                if not max_seen_dt or updated_dt > max_seen_dt:
                    max_seen_dt = updated_dt
        if max_seen_dt:
            self.state.set("updated_after", max_seen_dt.isoformat())
        logger.info("readwise_run_completed documents=%s", len(documents))

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)


def main() -> None:
    try:
        connector = ReadwiseConnector()
    except Exception as exc:
        logger.warning("readwise_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
