import logging
import os
import time
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone

import httpx
from pycti import OpenCTIConnectorHelper

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
        use_connector_token = os.getenv("OPENCTI_USE_CONNECTOR_TOKEN", "").lower() == "true"
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

        try:
            self.helper = _build_helper(opencti_token)
        except Exception as exc:
            if use_connector_token and admin_token and opencti_token != admin_token:
                logger.warning("zotero_connector_token_invalid_fallback error=%s", exc)
                opencti_token = admin_token
                self.helper = _build_helper(opencti_token)
            else:
                raise
        self.fallback_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN", "")
        self.briefing_url = os.getenv("BRIEFING_SERVICE_URL", "http://briefing:8088")
        self.interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "600"))
        self.dedup_days = int(os.getenv("DEDUP_LOOKBACK_DAYS_ZOTERO", "7"))
        self.dedup_threshold = float(os.getenv("DEDUP_SIMILARITY_ZOTERO", "0.85"))
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
        if not self.api_key or not self.library_id:
            logger.warning("zotero_not_configured")
            return
        since_version = self.state.get("last_version")
        approved_tags = fetch_approved_tags(self.briefing_url)
        approved_collections = fetch_approved_collections(self.briefing_url)
        if not approved_tags and not approved_collections:
            logger.info("zotero_no_approved_filters")
            return
        recent_reports = self.client.list_reports_since(datetime.now(timezone.utc) - timedelta(days=self.dedup_days))
        candidates = prepare_candidates(recent_reports)
        items, last_version = fetch_items(self.api_key, self.library_type, self.library_id, since_version)
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
            if url_digest and not self.state.remember_hash("zotero", url_digest):
                logger.info(
                    "report_skipped source=zotero reason=duplicate_hash title=%s",
                    data.get("title") or "Zotero item",
                )
                continue
            if source_url and self.client.report_exists_by_external_reference(source_url):
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
            label_entities = extract_label_entities(labels)
            cves = sorted(set(cves).union(label_entities["cves"]))
            iocs["urls"] = sorted(set(iocs["urls"]).union(label_entities["urls"]))
            iocs["domains"] = sorted(set(iocs["domains"]).union(label_entities["domains"]))
            iocs["ipv4"] = sorted(set(iocs["ipv4"]).union(label_entities["ipv4"]))

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
            author_id = None
            if author:
                author_key = _author_key("zotero", source_url, author)
                author_id = self._resolve_author(author_key, author, "Individual")
            report = ReportInput(
                title=data.get("title") or "Zotero item",
                description=text,
                published=data.get("date"),
                source_name="zotero",
                source_url=source_url or None,
                author=author or None,
                created_by_id=author_id,
                labels=labels,
                confidence=source_confidence("zotero"),
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
                        "report_skipped source=zotero reason=lower_confidence_duplicate title=%s",
                        report.title,
                    )
                    continue

            report_id = self.client.create_report(report)
            if report_id:
                logger.info("report_created source=zotero id=%s title=%s", report_id, report.title)
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
                logger.info("report_skipped source=zotero reason=create_failed title=%s", report.title)
        if last_version and last_version != since_version:
            self.state.set("last_version", last_version)
        logger.info("zotero_run_completed items=%s", len(items))

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)


def main() -> None:
    try:
        connector = ZoteroConnector()
    except Exception as exc:
        logger.warning("zotero_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
