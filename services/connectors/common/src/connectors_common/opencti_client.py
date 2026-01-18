import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)


@dataclass
class ReportInput:
    title: str
    description: str
    published: str | None
    source_name: str
    source_url: str | None
    author: str | None = None
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

    def add_external_reference_to_report(self, report_id: str, source_name: str, url: str, external_id: str | None) -> None:
        if not self.admin_token or not report_id or not url:
            return
        if not self._external_refs_supported:
            return
        mutations = [
            (
                """
                mutation ReportEdit($id: ID!, $input: ExternalReferenceAddInput!) {
                  reportEdit(id: $id) {
                    externalReferencesAdd(input: $input) { id }
                  }
                }
                """,
                "reportEdit",
            ),
            (
                """
                mutation StixEdit($id: ID!, $input: ExternalReferenceAddInput!) {
                  stixDomainObjectEdit(id: $id) {
                    externalReferencesAdd(input: $input) { id }
                  }
                }
                """,
                "stixDomainObjectEdit",
            ),
        ]
        payload = {"source_name": source_name, "url": url, "external_id": external_id}
        for mutation, _ in mutations:
            try:
                self._post(mutation, {"id": report_id, "input": payload})
                return
            except Exception as exc:
                if "externalReferencesAdd" in str(exc):
                    self._external_refs_supported = False
                    return
                continue

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

    def create_observable(self, obs_type: str, value: str) -> str | None:
        if not self.admin_token:
            return None
        if not self._observables_supported:
            return None
        mutation = """
        mutation ObservableAdd($type: String!, $value: String!) {
          stixCyberObservableAdd(type: $type, value: $value) { id }
        }
        """
        try:
            data = self._post(mutation, {"type": obs_type, "value": value})
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
        description_lines = [report.description.strip()] if report.description else []
        if report.author:
            description_lines.append(f"Author: {report.author}")
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
        if report.labels:
            input_payload["objectLabel"] = report.labels
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
