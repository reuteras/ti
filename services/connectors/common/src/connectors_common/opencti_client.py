import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from dateutil import parser as date_parser

from connectors_common.text_utils import escape_markdown

logger = logging.getLogger(__name__)


@dataclass
class ReportInput:
    title: str
    description: str
    published: str | None
    source_name: str
    source_url: str | None
    author: str | None = None
    created_by_id: str | None = None
    labels: list[str] | None = None
    confidence: int | None = None
    external_id: str | None = None


def _is_auth_required(exc: Exception) -> bool:
    if isinstance(exc, RuntimeError) and exc.args:
        errors = exc.args[0]
        if isinstance(errors, list):
            for error in errors:
                code = error.get("extensions", {}).get("code")
                message = (error.get("message") or "").lower()
                if code == "AUTH_REQUIRED":
                    return True
                if "cant identify" in message or "can not identify" in message:
                    return True
    msg = str(exc).lower()
    return "auth_required" in msg or "cant identify" in msg or "can not identify" in msg


def _is_es_overloaded(exc: Exception) -> bool:
    msg = str(exc).lower()
    return (
        "es_rejected_execution_exception" in msg
        or "statuscode': 429" in msg
        or "statuscode\": 429" in msg
        or "find direct ids fail" in msg
    )


class OpenCTIClient:
    def __init__(self, base_url: str, admin_token: str, fallback_token: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token
        self.fallback_token = fallback_token or ""
        self._external_refs_supported = True
        self._observables_supported = True
        self._software_supported = True
        self._country_supported = True
        self._label_cache: dict[str, str] = {}

    def _post_with_token(self, token: str, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}/graphql"
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        payload = {"query": query, "variables": variables}
        with httpx.Client(timeout=30) as client:
            response = client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            body = response.json()
            if "errors" in body:
                raise RuntimeError(body["errors"])
            return body.get("data", {})

    def _post(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._post_with_token(self.admin_token, query, variables)
        except Exception as exc:
            if self.fallback_token and self.fallback_token != self.admin_token and _is_auth_required(exc):
                return self._post_with_token(self.fallback_token, query, variables)
            raise

    def report_exists_by_external_reference(self, url: str) -> bool:
        if not self.admin_token or not url:
            return False
        # Disabled for now due to schema differences in filter types.
        return False

    def list_reports_since(self, since: datetime) -> list[dict[str, Any]]:
        if not self.admin_token:
            return []
        query = """
        query Reports($from: Any!) {
          reports(
            filters: {mode: and, filterGroups: [], filters: [{key: "created_at", values: [$from], operator: gt}]}
            first: 200
            orderBy: created_at
            orderMode: desc
          ) {
            edges {
              node {
                id
                name
                confidence
                created_at
                description
                objectLabel { value }
                externalReferences {
                  edges { node { url source_name external_id } }
                }
              }
            }
          }
        }
        """
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                data = self._post(query, {"from": since.isoformat()})
                break
            except Exception as exc:
                last_error = exc
                if _is_es_overloaded(exc):
                    if attempt < 2:
                        time.sleep(2**attempt)
                        continue
                    logger.warning("opencti_report_list_skipped_es_overloaded")
                    return []
                logger.warning("opencti_report_list_failed error=%s", exc)
                return []
        else:
            if last_error:
                logger.warning("opencti_report_list_failed error=%s", last_error)
            return []
        reports = []
        for edge in data.get("reports", {}).get("edges", []):
            node = edge.get("node", {})
            reports.append(node)
        return reports

    def list_notes_since(self, since: datetime) -> list[dict[str, Any]]:
        if not self.admin_token:
            return []
        query = """
        query Notes($from: Any!) {
          notes(
            filters: {mode: and, filterGroups: [], filters: [{key: "created_at", values: [$from], operator: gt}]}
            first: 200
            orderBy: created_at
            orderMode: desc
          ) {
            edges {
              node {
                id
                content
                created_at
                objectLabel { value }
                objects {
                  edges {
                    node {
                      ... on BasicObject {
                        id
                        entity_type
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                data = self._post(query, {"from": since.isoformat()})
                break
            except Exception as exc:
                last_error = exc
                if _is_es_overloaded(exc):
                    if attempt < 2:
                        time.sleep(2**attempt)
                        continue
                    logger.warning("opencti_note_list_skipped_es_overloaded")
                    return []
                logger.warning("opencti_note_list_failed error=%s", exc)
                return []
        else:
            if last_error:
                logger.warning("opencti_note_list_failed error=%s", last_error)
            return []
        notes = []
        for edge in data.get("notes", {}).get("edges", []):
            node = edge.get("node", {})
            notes.append(node)
        return notes

    def add_external_reference_to_report(self, report_id: str, source_name: str, url: str, external_id: str | None) -> None:
        if not self.admin_token or not report_id or not url:
            return
        if not self._external_refs_supported:
            return
        external_ref_id = self._create_external_reference(source_name, url, external_id)
        if not external_ref_id:
            return
        patch = [{"key": "externalReferences", "operation": "add", "value": [external_ref_id]}]
        mutations = [
            """
            mutation ReportEdit($id: ID!, $input: [EditInput]!) {
              reportEdit(id: $id) {
                fieldPatch(input: $input) { id }
              }
            }
            """,
            """
            mutation StixEdit($id: ID!, $input: [EditInput]!) {
              stixDomainObjectEdit(id: $id) {
                fieldPatch(input: $input) { id }
              }
            }
            """,
        ]
        for mutation in mutations:
            try:
                self._post(mutation, {"id": report_id, "input": patch})
                return
            except Exception as exc:
                if "externalReferences" in str(exc):
                    self._external_refs_supported = False
                    return
                continue

    def _create_external_reference(self, source_name: str, url: str, external_id: str | None) -> str | None:
        if not self.admin_token:
            return None
        mutation = """
        mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
          externalReferenceAdd(input: $input) { id }
        }
        """
        payload = {"source_name": source_name, "url": url, "external_id": external_id}
        try:
            data = self._post(mutation, {"input": payload})
            return data.get("externalReferenceAdd", {}).get("id")
        except Exception as exc:
            logger.warning("opencti_external_reference_add_failed error=%s", exc)
            return None

    def create_vulnerability(self, name: str) -> str | None:
        if not self.admin_token:
            return None
        mutation = """
        mutation VulnerabilityAdd($input: VulnerabilityAddInput!) {
          vulnerabilityAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            logger.warning("opencti_vulnerability_add_failed error=%s", exc)
            return None
        return data.get("vulnerabilityAdd", {}).get("id")

    def _find_entity_id(self, list_field: str, name: str) -> str | None:
        query = f"""
        query EntityByName($name: Any!) {{
          {list_field}(
            filters: {{mode: and, filterGroups: [], filters: [{{key: "name", values: [$name]}}]}}
            first: 1
          ) {{
            edges {{ node {{ id }} }}
          }}
        }}
        """
        try:
            data = self._post(query, {"name": name})
        except Exception as exc:
            logger.warning("opencti_entity_find_failed error=%s", exc)
            return None
        edges = data.get(list_field, {}).get("edges", [])
        if edges:
            return edges[0].get("node", {}).get("id")
        return None

    def create_malware(self, name: str) -> str | None:
        if not self.admin_token:
            return None
        existing = self._find_entity_id("malwares", name)
        if existing:
            return existing
        mutation = """
        mutation MalwareAdd($input: MalwareAddInput!) {
          malwareAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            logger.warning("opencti_malware_add_failed error=%s", exc)
            return None
        return data.get("malwareAdd", {}).get("id")

    def create_identity(self, name: str, identity_type: str = "Individual") -> str | None:
        if not self.admin_token:
            return None
        existing = self._find_entity_id("identities", name)
        if existing:
            return existing
        mutation = """
        mutation IdentityAdd($input: IdentityAddInput!) {
          identityAdd(input: $input) { id }
        }
        """
        payload = {"name": name, "type": identity_type}
        try:
            data = self._post(mutation, {"input": payload})
        except Exception as exc:
            logger.warning("opencti_identity_add_failed error=%s", exc)
            return None
        return data.get("identityAdd", {}).get("id")

    def update_identity_name(self, identity_id: str, name: str) -> None:
        if not self.admin_token or not identity_id or not name:
            return
        mutation = """
        mutation IdentityEdit($id: ID!, $input: [EditInput]!) {
          stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) { id }
          }
        }
        """
        payload = [{"key": "name", "value": [name]}]
        try:
            self._post(mutation, {"id": identity_id, "input": payload})
        except Exception as exc:
            logger.warning("opencti_identity_update_failed error=%s", exc)

    def create_software(self, name: str) -> str | None:
        if not self.admin_token or not self._software_supported:
            return None
        query = """
        query SoftwareByName($name: Any!) {
          stixCoreObjects(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "entity_type", values: ["Software"]},
                {key: "name", values: [$name]}
              ]
            }
            first: 1
          ) {
            edges { node { id } }
          }
        }
        """
        try:
            data = self._post(query, {"name": name})
            edges = data.get("stixCoreObjects", {}).get("edges", [])
            if edges:
                return edges[0].get("node", {}).get("id")
        except Exception as exc:
            if "stixCoreObjects" in str(exc) or "GRAPHQL_VALIDATION_FAILED" in str(exc):
                self._software_supported = False
                logger.warning("opencti_software_disabled")
                return None
            logger.warning("opencti_software_find_failed error=%s", exc)
            return None

        mutation = """
        mutation SoftwareAdd($input: SoftwareAddInput!) {
          softwareAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            if "softwareAdd" in str(exc) or "GRAPHQL_VALIDATION_FAILED" in str(exc):
                self._software_supported = False
                logger.warning("opencti_software_disabled")
                return None
            logger.warning("opencti_software_add_failed error=%s", exc)
            return None
        return data.get("softwareAdd", {}).get("id")

    def create_country(self, name: str) -> str | None:
        if not self.admin_token or not self._country_supported:
            return None
        query = """
        query CountryByName($name: Any!) {
          stixCoreObjects(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "entity_type", values: ["Country"]},
                {key: "name", values: [$name]}
              ]
            }
            first: 1
          ) {
            edges { node { id } }
          }
        }
        """
        try:
            data = self._post(query, {"name": name})
            edges = data.get("stixCoreObjects", {}).get("edges", [])
            if edges:
                return edges[0].get("node", {}).get("id")
        except Exception as exc:
            if "stixCoreObjects" in str(exc) or "GRAPHQL_VALIDATION_FAILED" in str(exc):
                self._country_supported = False
                logger.warning("opencti_country_disabled")
                return None
            logger.warning("opencti_country_find_failed error=%s", exc)
            return None

        mutation = """
        mutation CountryAdd($input: CountryAddInput!) {
          countryAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            if "countryAdd" in str(exc) or "GRAPHQL_VALIDATION_FAILED" in str(exc):
                self._country_supported = False
                logger.warning("opencti_country_disabled")
                return None
            logger.warning("opencti_country_add_failed error=%s", exc)
            return None
        return data.get("countryAdd", {}).get("id")

    def create_tool(self, name: str) -> str | None:
        if not self.admin_token:
            return None
        existing = self._find_entity_id("tools", name)
        if existing:
            return existing
        mutation = """
        mutation ToolAdd($input: ToolAddInput!) {
          toolAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            logger.warning("opencti_tool_add_failed error=%s", exc)
            return None
        return data.get("toolAdd", {}).get("id")

    def create_threat_actor(self, name: str) -> str | None:
        if not self.admin_token:
            return None
        existing = self._find_entity_id("threatActors", name)
        if existing:
            return existing
        mutation = """
        mutation ThreatActorAdd($input: ThreatActorAddInput!) {
          threatActorAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            logger.warning("opencti_threat_actor_add_failed error=%s", exc)
            return None
        return data.get("threatActorAdd", {}).get("id")

    def create_attack_pattern(self, name: str) -> str | None:
        if not self.admin_token:
            return None
        existing = self._find_entity_id("attackPatterns", name)
        if existing:
            return existing
        mutation = """
        mutation AttackPatternAdd($input: AttackPatternAddInput!) {
          attackPatternAdd(input: $input) { id }
        }
        """
        try:
            data = self._post(mutation, {"input": {"name": name}})
        except Exception as exc:
            logger.warning("opencti_attack_pattern_add_failed error=%s", exc)
            return None
        return data.get("attackPatternAdd", {}).get("id")

    def create_observable(self, obs_type: str, value: str) -> str | None:
        if not self.admin_token:
            return None
        if not self._observables_supported:
            return None
        normalized = obs_type.replace("-", "")
        field_map = {
            "IPv4Addr": "IPv4Addr",
            "IPv6Addr": "IPv6Addr",
            "DomainName": "DomainName",
            "Url": "Url",
            "AutonomousSystem": "AutonomousSystem",
        }
        field = field_map.get(normalized)
        if field:
            input_mutation = f"""
            mutation ObservableAdd($input: {field}AddInput!) {{
              stixCyberObservableAdd({field}: $input) {{ id }}
            }}
            """
            try:
                data = self._post(input_mutation, {"input": {"value": value}})
                return data.get("stixCyberObservableAdd", {}).get("id")
            except Exception as exc:
                logger.warning("opencti_observable_add_failed error=%s", exc)
                return None

        legacy_mutation = """
        mutation ObservableAdd($type: String!, $value: String!) {
          stixCyberObservableAdd(type: $type, value: $value) { id }
        }
        """
        try:
            data = self._post(legacy_mutation, {"type": obs_type, "value": value})
        except Exception as exc:
            if "Unknown argument" in str(exc) or "stixCyberObservableAdd" in str(exc):
                self._observables_supported = False
                logger.warning("opencti_observable_add_disabled")
                return None
            logger.warning("opencti_observable_add_failed error=%s", exc)
            return None
        return data.get("stixCyberObservableAdd", {}).get("id")

    def create_relationship(self, from_id: str, to_id: str, rel_type: str) -> None:
        if not self.admin_token:
            return
        mutation = """
        mutation RelationAdd($input: StixCoreRelationshipAddInput!) {
          stixCoreRelationshipAdd(input: $input) { id }
        }
        """
        payload = {"fromId": from_id, "toId": to_id, "relationship_type": rel_type}
        try:
            self._post(mutation, {"input": payload})
        except Exception as exc:
            logger.warning("opencti_relationship_add_failed error=%s", exc)

    def create_note(
        self,
        content: str,
        object_refs: list[str] | None = None,
        created_by_id: str | None = None,
        labels: list[str] | None = None,
        confidence: int | None = None,
    ) -> str | None:
        if not self.admin_token or not content:
            return None
        mutation = """
        mutation NoteAdd($input: NoteAddInput!) {
          noteAdd(input: $input) { id }
        }
        """
        payload: dict[str, Any] = {"content": escape_markdown(content.strip())}
        if object_refs:
            payload["objectRefs"] = object_refs
        if created_by_id:
            payload["createdBy"] = created_by_id
        if confidence is not None:
            payload["confidence"] = confidence
        if labels:
            label_ids = self._ensure_label_ids(labels)
            if label_ids:
                payload["objectLabel"] = label_ids
        try:
            data = self._post(mutation, {"input": payload})
            return data.get("noteAdd", {}).get("id")
        except Exception as exc:
            logger.warning("opencti_note_add_failed error=%s", exc)
            return None

    def create_report(self, report: ReportInput) -> str | None:
        if not self.admin_token:
            logger.warning("opencti_token_missing")
            return None
        mutation = """
        mutation ReportAdd($input: ReportAddInput!) {
          reportAdd(input: $input) {
            id
          }
        }
        """
        description_lines = [escape_markdown(report.description.strip())] if report.description else []
        if report.author:
            description_lines.append(f"Author: {escape_markdown(report.author)}")
        if report.source_url:
            description_lines.append(f"Source: {escape_markdown(report.source_url)}")
        description = "\n\n".join(line for line in description_lines if line)
        normalized_published = _normalize_published(report.published)
        if not normalized_published:
            normalized_published = datetime.now(timezone.utc).isoformat()
        input_payload: dict[str, Any] = {
            "name": report.title,
            "description": description,
            "report_types": ["threat-report"],
        }
        input_payload["published"] = normalized_published
        if report.confidence is not None:
            input_payload["confidence"] = report.confidence
        created_by_id = getattr(report, "created_by_id", None)
        if created_by_id:
            input_payload["createdBy"] = created_by_id
        elif report.author:
            author_id = self.create_identity(report.author)
            if author_id:
                input_payload["createdBy"] = author_id
        if report.labels:
            label_ids = self._ensure_label_ids(report.labels)
            if label_ids:
                input_payload["objectLabel"] = label_ids
        # External references are added after creation to avoid schema mismatches.
        try:
            data = self._post(mutation, {"input": input_payload})
        except RuntimeError as exc:
            logger.warning("opencti_report_add_retry error=%s", exc)
            input_payload.pop("externalReferences", None)
            input_payload.pop("objectLabel", None)
            try:
                data = self._post(mutation, {"input": input_payload})
            except Exception as retry_exc:
                logger.exception("opencti_report_add_failed error=%s", retry_exc)
                return None
        except Exception as exc:
            logger.exception("opencti_report_add_failed error=%s", exc)
            return None
        report_id = data.get("reportAdd", {}).get("id")
        if report_id and report.source_url and self._external_refs_supported:
            self.add_external_reference_to_report(
                report_id, report.source_name, report.source_url, report.external_id
            )
        return report_id

    def _ensure_label_ids(self, labels: list[str]) -> list[str]:
        label_ids: list[str] = []
        for value in labels:
            label = value.strip()
            if not label:
                continue
            cached = self._label_cache.get(label)
            if cached:
                label_ids.append(cached)
                continue
            mutation = """
            mutation LabelAdd($input: LabelAddInput!) {
              labelAdd(input: $input) { id value }
            }
            """
            payload = {"value": label, "update": True}
            try:
                data = self._post(mutation, {"input": payload})
                node = data.get("labelAdd") or {}
                label_id = node.get("id")
                if label_id:
                    self._label_cache[label] = label_id
                    label_ids.append(label_id)
            except Exception as exc:
                logger.warning("opencti_label_add_failed label=%s error=%s", label, exc)
        return label_ids


def _normalize_published(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    now = datetime.now(timezone.utc)
    if "T" in raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return min(parsed, now).isoformat()
        except ValueError:
            pass
    if re.match(r"^\d{4}-\d{2}-\d{2}$", raw):
        parsed = datetime.fromisoformat(f"{raw}T00:00:00+00:00")
        return min(parsed, now).isoformat()
    if re.match(r"^\d{4}-\d{2}$", raw):
        parsed = datetime.fromisoformat(f"{raw}-01T00:00:00+00:00")
        return min(parsed, now).isoformat()
    if re.match(r"^\d{4}$", raw):
        parsed = datetime.fromisoformat(f"{raw}-01-01T00:00:00+00:00")
        return min(parsed, now).isoformat()
    if re.match(r"^\d{2}/\d{4}$", raw):
        month, year = raw.split("/")
        parsed = datetime.fromisoformat(f"{year}-{month}-01T00:00:00+00:00")
        return min(parsed, now).isoformat()
    try:
        parsed = date_parser.parse(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return min(parsed, now).isoformat()
    except Exception:
        return None
