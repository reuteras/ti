import hashlib
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from dateutil.parser import isoparse
from pycti import OpenCTIConnectorHelper

from connectors_common.extractors import (
    extract_attack_patterns,
    extract_cves,
    extract_iocs,
    extract_sigma_rules,
    extract_snort_rules,
    extract_yara_rules,
)
from connectors_common.llm import extract_entities, summarize_text
from connectors_common.opencti_client import OpenCTIClient
from connectors_common.state_store import StateStore
from connectors_common.work import WorkTracker

logging.basicConfig(level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s")
logger = logging.getLogger(__name__)

_PERSON_TITLES = {
    "mr",
    "mrs",
    "ms",
    "miss",
    "dr",
    "prof",
    "sir",
    "madam",
    "lord",
    "lady",
    "capt",
    "cpt",
    "col",
    "gen",
    "sgt",
    "lt",
    "cmdr",
    "officer",
    "chief",
    "agent",
    "analyst",
}


def _select_opencti_token() -> str:
    return os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")


def _observable_type_for_ip(value: str) -> str:
    return "IPv6-Addr" if ":" in value else "IPv4-Addr"


def _seen_key(prefix: str, entity_id: str, value: str) -> str:
    raw = f"{prefix}:{entity_id}:{value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _collect_object_refs(note: dict) -> list[str]:
    refs = []
    objects = note.get("objects") or note.get("objectRefs")
    if isinstance(objects, dict):
        edges = objects.get("edges", [])
        for edge in edges:
            node = edge.get("node", {})
            ref_id = node.get("id")
            if ref_id:
                refs.append(ref_id)
    elif isinstance(objects, list):
        for item in objects:
            if not isinstance(item, dict):
                continue
            ref_id = item.get("id")
            if ref_id:
                refs.append(ref_id)
    return refs


def _collect_labels(node: dict) -> set[str]:
    labels = set()
    object_labels = node.get("objectLabel")
    if isinstance(object_labels, dict):
        edges = object_labels.get("edges", [])
        for edge in edges:
            value = edge.get("node", {}).get("value")
            if value:
                labels.add(str(value).strip().lower())
    elif isinstance(object_labels, list):
        for item in object_labels:
            if not isinstance(item, dict):
                continue
            value = item.get("value")
            if value:
                labels.add(str(value).strip().lower())
    return labels


def _is_valid_person(name: str) -> bool:
    if not name:
        return False
    cleaned = " ".join(name.replace(",", " ").split())
    parts = [part.strip(".") for part in cleaned.split() if part.strip(".")]
    if len(parts) < 2:
        return False
    first = parts[0].lower()
    if first in _PERSON_TITLES and len(parts) >= 2:
        return True
    non_title_parts = [part for part in parts if part.lower() not in _PERSON_TITLES]
    return len(non_title_parts) >= 2


class EnrichTextConnector:
    def __init__(self) -> None:
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        admin_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
        opencti_token = _select_opencti_token()
        if not opencti_token:
            raise RuntimeError("enrich_missing_token")

        connector_id = os.getenv("CONNECTOR_ID", "").strip()
        if not connector_id:
            raise RuntimeError("enrich_missing_connector_id")
        connector_name = os.getenv("CONNECTOR_NAME", "Enrich Text")
        connector_type = os.getenv("CONNECTOR_TYPE", "INTERNAL_ENRICHMENT")
        connector_scope = os.getenv("CONNECTOR_SCOPE", "text-enrichment")
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
        self.fallback_token = admin_token
        self.interval = int(os.getenv("CONNECTOR_RUN_INTERVAL_SECONDS", "900"))
        self.lookback_days = int(os.getenv("ENRICH_LOOKBACK_DAYS", "7"))
        sources = os.getenv("TI_ENRICH_SOURCES", "miniflux,readwise,zotero")
        self.allowed_sources = {part.strip().lower() for part in sources.split(",") if part.strip()}
        self.state = StateStore("/data/state.json")
        self.client = OpenCTIClient(opencti_url, opencti_token, fallback_token=self.fallback_token)

    def _enrich_text(self, entity_id: str, text: str, state_prefix: str) -> None:
        if not text:
            return
        summary_enabled = os.getenv("ENRICHMENT_SUMMARY_ENABLED", "false").lower() == "true"
        if state_prefix == "report" and summary_enabled:
            summary = summarize_text(text[:12000])
            if summary:
                digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()
                seen_key = _seen_key(state_prefix, entity_id, f"summary:{digest}")
                if self.state.remember_hash("enrich", seen_key):
                    self.client.create_note(
                        f"Summary\n\n{summary}",
                        object_refs=[entity_id],
                        labels=["summary", "source:enrich-text"],
                    )
        cves = extract_cves(text)
        iocs = extract_iocs(text)
        entities = extract_entities(text)
        attack_patterns = extract_attack_patterns(text)
        yara_rules = extract_yara_rules(text)
        sigma_rules = extract_sigma_rules(text)
        snort_rules = extract_snort_rules(text)
        for cve in cves:
            seen_key = _seen_key(state_prefix, entity_id, f"cve:{cve}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            vuln_id = self.client.create_vulnerability(cve)
            if vuln_id:
                self.client.create_relationship(entity_id, vuln_id, "related-to")
        for url in iocs["urls"]:
            seen_key = _seen_key(state_prefix, entity_id, f"url:{url}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            obs_id = self.client.create_observable("Url", url)
            if obs_id:
                self.client.create_relationship(entity_id, obs_id, "related-to")
        for domain in iocs["domains"]:
            seen_key = _seen_key(state_prefix, entity_id, f"domain:{domain}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            obs_id = self.client.create_observable("Domain-Name", domain)
            if obs_id:
                self.client.create_relationship(entity_id, obs_id, "related-to")
        for ip in iocs["ipv4"]:
            seen_key = _seen_key(state_prefix, entity_id, f"ip:{ip}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            obs_id = self.client.create_observable(_observable_type_for_ip(ip), ip)
            if obs_id:
                self.client.create_relationship(entity_id, obs_id, "related-to")
        for asn in iocs["asns"]:
            seen_key = _seen_key(state_prefix, entity_id, f"asn:{asn}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            obs_id = self.client.create_observable("Autonomous-System", asn)
            if obs_id:
                self.client.create_relationship(entity_id, obs_id, "related-to")
        for sha256 in iocs.get("sha256", []):
            seen_key = _seen_key(state_prefix, entity_id, f"sha256:{sha256}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            file_id = self.client.create_file_hash("SHA-256", sha256)
            if file_id:
                self.client.create_relationship(entity_id, file_id, "related-to")
        for sha1 in iocs.get("sha1", []):
            seen_key = _seen_key(state_prefix, entity_id, f"sha1:{sha1}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            file_id = self.client.create_file_hash("SHA-1", sha1)
            if file_id:
                self.client.create_relationship(entity_id, file_id, "related-to")
        for md5 in iocs.get("md5", []):
            seen_key = _seen_key(state_prefix, entity_id, f"md5:{md5}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            file_id = self.client.create_file_hash("MD5", md5)
            if file_id:
                self.client.create_relationship(entity_id, file_id, "related-to")
        for country in iocs["countries"]:
            seen_key = _seen_key(state_prefix, entity_id, f"country:{country}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            country_id = self.client.create_country(country)
            if country_id:
                self.client.create_relationship(entity_id, country_id, "related-to")
        for person in entities.get("persons", []):
            if not _is_valid_person(person):
                continue
            seen_key = _seen_key(state_prefix, entity_id, f"person:{person}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            person_id = self.client.create_identity(person, "Individual")
            if person_id:
                self.client.create_relationship(entity_id, person_id, "related-to")
        for org in entities.get("organizations", []):
            seen_key = _seen_key(state_prefix, entity_id, f"org:{org}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            org_id = self.client.create_identity(org, "Organization")
            if org_id:
                self.client.create_relationship(entity_id, org_id, "related-to")
        for product in entities.get("products", []):
            seen_key = _seen_key(state_prefix, entity_id, f"product:{product}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            product_id = self.client.create_software(product)
            if product_id:
                self.client.create_relationship(entity_id, product_id, "related-to")
        for country in entities.get("countries", []):
            seen_key = _seen_key(state_prefix, entity_id, f"entity-country:{country}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            country_id = self.client.create_country(country)
            if country_id:
                self.client.create_relationship(entity_id, country_id, "related-to")
        for technique in attack_patterns:
            seen_key = _seen_key(state_prefix, entity_id, f"attack:{technique}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            attack_id = self.client.create_attack_pattern(technique)
            if attack_id:
                self.client.create_relationship(entity_id, attack_id, "related-to")
        self._add_rule_notes(entity_id, state_prefix, "yara", yara_rules)
        self._add_rule_notes(entity_id, state_prefix, "sigma", sigma_rules)
        self._add_rule_notes(entity_id, state_prefix, "snort", snort_rules)

    def _should_enrich(self, labels: set[str]) -> bool:
        if "all" in self.allowed_sources:
            return True
        for label in labels:
            if label.startswith("source:") and label.split(":", 1)[1] in self.allowed_sources:
                return True
        return False

    def _add_rule_notes(self, entity_id: str, state_prefix: str, rule_type: str, rules: list[str]) -> None:
        if not rules:
            return
        for idx, rule in enumerate(rules, start=1):
            rule_text = rule.strip()
            if not rule_text:
                continue
            digest = hashlib.sha256(rule_text.encode("utf-8")).hexdigest()
            seen_key = _seen_key(state_prefix, entity_id, f"{rule_type}:{digest}")
            if not self.state.remember_hash("enrich", seen_key):
                continue
            title = f"{rule_type.upper()} rule {idx}"
            content = f"{title}\n\n{rule_text}"
            self.client.create_note(
                content,
                object_refs=[entity_id],
                labels=[f"rule:{rule_type}", "source:enrich-text"],
            )

    def _run(self) -> None:
        last_run = self.state.get("last_run")
        if last_run:
            since = isoparse(last_run)
        else:
            since = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)

        work = WorkTracker(self.helper, "Enrich Text")
        reports = self.client.list_reports_since(since)
        notes = self.client.list_notes_since(since)
        total_items = len(reports) + len(notes)
        work.log(f"reports={len(reports)} notes={len(notes)}")
        processed = 0
        last_progress = -1
        for report in reports:
            report_id = report.get("id")
            if not report_id:
                continue
            labels = _collect_labels(report)
            if self.allowed_sources and not self._should_enrich(labels):
                continue
            text = report.get("description") or ""
            self._enrich_text(report_id, text, "report")
            processed += 1
            if total_items:
                percent = int((processed / total_items) * 100)
                if percent >= last_progress + 5:
                    work.progress(percent, f"processed={processed}/{total_items}")
                    last_progress = percent

        for note in notes:
            note_id = note.get("id")
            if not note_id:
                continue
            labels = _collect_labels(note)
            if self.allowed_sources and not self._should_enrich(labels):
                continue
            text = note.get("content") or ""
            self._enrich_text(note_id, text, "note")
            for ref_id in _collect_object_refs(note):
                self._enrich_text(ref_id, text, "note-ref")
            processed += 1
            if total_items:
                percent = int((processed / total_items) * 100)
                if percent >= last_progress + 5:
                    work.progress(percent, f"processed={processed}/{total_items}")
                    last_progress = percent

        self.state.set("last_run", datetime.now(timezone.utc).isoformat())
        logger.info("enrich_run_completed reports=%s notes=%s", len(reports), len(notes))
        work.done(f"processed={processed}")

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)


def main() -> None:
    try:
        connector = EnrichTextConnector()
    except Exception as exc:
        logger.warning("enrich_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
