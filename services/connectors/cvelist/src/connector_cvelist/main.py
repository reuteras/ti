import csv
import gzip
import json
import logging
import re
import os
import subprocess
import time
from datetime import timezone
from pathlib import Path
from typing import Any, Iterable, Optional, TypedDict

import httpx
import ipaddress
from dateutil import parser as date_parser
from pycti import OpenCTIConnectorHelper

from connectors_common.state_store import StateStore
from connectors_common.connector_state import ConnectorState
from connectors_common.work import WorkTracker

logging.basicConfig(
    level=logging.INFO, format="time=%(asctime)s level=%(levelname)s msg=%(message)s"
)
logger = logging.getLogger("connector_cvelist")

EPSS_DEFAULT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_DEFAULT_REFRESH_SECONDS = 24 * 60 * 60


def _select_opencti_token() -> str:
    return os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv(
        "OPENCTI_ADMIN_TOKEN", ""
    )


def _run_git(args: list[str], repo_path: Path | None = None) -> str:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git", *args],
        cwd=str(repo_path) if repo_path else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or "git command failed"
        )
    return result.stdout.strip()


def _ensure_repo(repo_url: str, branch: str, repo_path: Path) -> None:
    if repo_path.exists():
        _run_git(["fetch", "origin", branch], repo_path)
        _run_git(["reset", "--hard", f"origin/{branch}"], repo_path)
        return
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    _run_git(["clone", "--branch", branch, repo_url, str(repo_path)])


def _get_head_commit(repo_path: Path) -> str:
    return _run_git(["rev-parse", "HEAD"], repo_path)


def _changed_files(repo_path: Path, previous: str, current: str) -> list[str]:
    try:
        diff = _run_git(
            ["diff", "--name-only", previous, current, "--", "cves"], repo_path
        )
    except Exception as exc:
        logger.warning("cvelist_diff_failed error=%s", exc)
        return []
    return [line for line in diff.splitlines() if line.strip()]


def _iter_cve_files(repo_path: Path, changed: list[str] | None) -> Iterable[Path]:
    if changed is None:
        for path in repo_path.joinpath("cves").rglob("*.json"):
            yield path
        return
    for rel in changed:
        if not rel.endswith(".json"):
            continue
        if not rel.startswith("cves/"):
            continue
        yield repo_path / rel


class CveExtract(TypedDict):
    cve_id: str
    description: str | None
    references: list[str]
    fields: dict[str, Any]
    software: list[str]
    epss: dict[str, float]


def _summarize_affected(affected: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    software_names: list[str] = []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        vendor = (entry.get("vendor") or "").strip()
        product = (entry.get("product") or "").strip()
        if vendor or product:
            if vendor and product:
                if vendor.lower() in product.lower():
                    software_name = product
                else:
                    software_name = f"{vendor} {product}"
            else:
                software_name = vendor or product
            software_names.append(software_name)
        versions = entry.get("versions") or []
        version_parts: list[str] = []
        for version in versions:
            if not isinstance(version, dict):
                continue
            status = (version.get("status") or "").strip()
            version_label = (version.get("version") or "").strip()
            less_than = version.get("lessThan")
            less_than_eq = version.get("lessThanOrEqual")
            greater_than = version.get("greaterThan")
            greater_than_eq = version.get("greaterThanOrEqual")
            if less_than_eq:
                version_label = f"{version_label} to {less_than_eq}"
            elif less_than:
                version_label = f"{version_label} to <{less_than}"
            if greater_than_eq:
                version_label = f">={greater_than_eq} {version_label}".strip()
            elif greater_than:
                version_label = f">{greater_than} {version_label}".strip()
            if status:
                version_label = f"{version_label} ({status})".strip()
            if version_label:
                version_parts.append(version_label)
        bits = []
        if vendor:
            bits.append(f"Vendor: {vendor}")
        if product:
            bits.append(f"Product: {product}")
        if version_parts:
            bits.append(f"Versions: {', '.join(version_parts)}")
        if bits:
            lines.append("; ".join(bits))
    return lines, sorted({name for name in software_names if name})


def _ensure_epss_file(path: Path, url: str, refresh_seconds: int) -> bool:
    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age < refresh_seconds:
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    with httpx.stream("GET", url, timeout=60, follow_redirects=True) as response:
        response.raise_for_status()
        with tmp_path.open("wb") as handle:
            for chunk in response.iter_bytes():
                if chunk:
                    handle.write(chunk)
    tmp_path.replace(path)
    return True


def _load_epss_scores(path: Path) -> dict[str, dict[str, float]]:
    if not path.exists():
        return {}
    scores: dict[str, dict[str, float]] = {}
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                cve_id = (row.get("cve") or "").strip()
                if not cve_id:
                    continue
                try:
                    epss_score = float(row.get("epss") or 0.0)
                except ValueError:
                    epss_score = 0.0
                try:
                    epss_percentile = float(row.get("percentile") or 0.0)
                except ValueError:
                    epss_percentile = 0.0
                scores[cve_id] = {
                    "x_opencti_epss_score": epss_score,
                    "x_opencti_epss_percentile": epss_percentile,
                }
    except Exception as exc:
        logger.warning("cvelist_epss_load_failed error=%s", exc)
    return scores


def _cvss_score_to_opencti(score: Any) -> int | None:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value <= 10:
        value = value * 10
    value = max(0, min(100, round(value)))
    return int(value)


def _is_cvss4_vector_error(exc: Exception) -> bool:
    message = str(exc)
    return "valid CVSS4 vector" in message or "CVSS4" in message


def _strip_cvss4_fields(fields: dict[str, Any]) -> bool:
    removed = False
    for key in list(fields.keys()):
        if key.startswith("x_opencti_cvss_v4_"):
            fields.pop(key, None)
            removed = True
    if removed:
        fields.pop("x_opencti_score", None)
    return removed


def _normalize_opencti_date(value: str) -> str | None:
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        parsed = date_parser.isoparse(cleaned)
    except (ValueError, TypeError):
        try:
            parsed = date_parser.parse(cleaned)
        except (ValueError, TypeError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat()


def _extract_cvss(containers: Iterable[dict[str, Any]]) -> dict[str, Any]:
    for container in containers:
        metrics = container.get("metrics") if isinstance(container, dict) else None
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV3_1", "cvssV3_0"):
                cvss = metric.get(key)
                if isinstance(cvss, dict):
                    return {
                        "x_opencti_cvss_vector_string": cvss.get("vectorString"),
                        "x_opencti_cvss_base_score": cvss.get("baseScore"),
                        "x_opencti_cvss_base_severity": cvss.get("baseSeverity"),
                        "x_opencti_score": _cvss_score_to_opencti(
                            cvss.get("baseScore")
                        ),
                        "x_opencti_cvss_attack_vector": cvss.get("attackVector"),
                        "x_opencti_cvss_attack_complexity": cvss.get(
                            "attackComplexity"
                        ),
                        "x_opencti_cvss_privileges_required": cvss.get(
                            "privilegesRequired"
                        ),
                        "x_opencti_cvss_user_interaction": cvss.get("userInteraction"),
                        "x_opencti_cvss_scope": cvss.get("scope"),
                        "x_opencti_cvss_confidentiality_impact": cvss.get(
                            "confidentialityImpact"
                        ),
                        "x_opencti_cvss_integrity_impact": cvss.get("integrityImpact"),
                        "x_opencti_cvss_availability_impact": cvss.get(
                            "availabilityImpact"
                        ),
                    }
            cvss4 = metric.get("cvssV4_0")
            if isinstance(cvss4, dict):
                fields: dict[str, Any] = {
                    "x_opencti_cvss_v4_vector_string": cvss4.get("vectorString"),
                    "x_opencti_cvss_v4_base_score": cvss4.get("baseScore"),
                    "x_opencti_cvss_v4_base_severity": cvss4.get("baseSeverity"),
                    "x_opencti_score": _cvss_score_to_opencti(cvss4.get("baseScore")),
                }
                for key, field in (
                    ("attackVector", "x_opencti_cvss_v4_attack_vector"),
                    ("attackComplexity", "x_opencti_cvss_v4_attack_complexity"),
                    ("attackRequirements", "x_opencti_cvss_v4_attack_requirements"),
                    ("privilegesRequired", "x_opencti_cvss_v4_privileges_required"),
                    ("userInteraction", "x_opencti_cvss_v4_user_interaction"),
                    (
                        "confidentialityImpact",
                        "x_opencti_cvss_v4_confidentiality_impact_v",
                    ),
                    ("integrityImpact", "x_opencti_cvss_v4_integrity_impact_v"),
                    ("availabilityImpact", "x_opencti_cvss_v4_availability_impact_v"),
                    (
                        "subConfidentialityImpact",
                        "x_opencti_cvss_v4_confidentiality_impact_s",
                    ),
                    ("subIntegrityImpact", "x_opencti_cvss_v4_integrity_impact_s"),
                    (
                        "subAvailabilityImpact",
                        "x_opencti_cvss_v4_availability_impact_s",
                    ),
                    ("exploitMaturity", "x_opencti_cvss_v4_exploit_maturity"),
                ):
                    value = cvss4.get(key)
                    if value is not None:
                        fields[field] = value
                return fields
    return {}


def _extract_cwe(containers: Iterable[dict[str, Any]]) -> list[str]:
    cwes: set[str] = set()
    for container in containers:
        problem_types = (
            container.get("problemTypes") if isinstance(container, dict) else None
        )
        if not isinstance(problem_types, list):
            continue
        for problem in problem_types:
            descriptions = (
                problem.get("descriptions") if isinstance(problem, dict) else None
            )
            if not isinstance(descriptions, list):
                continue
            for desc in descriptions:
                if not isinstance(desc, dict):
                    continue
                cwe_id = desc.get("cweId") or desc.get("cwe_id") or ""
                if isinstance(cwe_id, str) and cwe_id.strip():
                    cwes.add(cwe_id.strip())
    return sorted(cwes)


def _extract_cve(
    payload: dict[str, Any], epss_scores: dict[str, dict[str, float]]
) -> Optional[CveExtract]:
    if not isinstance(payload, dict):
        return None
    meta = payload.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    description = None
    references: list[str] = []
    containers = payload.get("containers", {})
    container_items: list[dict[str, Any]] = []
    if isinstance(containers, dict):
        container_items = [
            item for item in containers.values() if isinstance(item, dict)
        ]
    elif isinstance(containers, list):
        container_items = [item for item in containers if isinstance(item, dict)]
    for container in container_items:
        for item in (
            container.get("descriptions", []) if isinstance(container, dict) else []
        ):
            if item.get("lang", "").lower() == "en":
                description = item.get("value")
                break
        for ref in (
            container.get("references", []) if isinstance(container, dict) else []
        ):
            url = ref.get("url")
            if isinstance(url, str) and url.strip():
                references.append(url.strip())
        if description:
            break
    if not description:
        for container in container_items:
            for item in (
                container.get("descriptions", []) if isinstance(container, dict) else []
            ):
                value = item.get("value")
                if isinstance(value, str) and value.strip():
                    description = value.strip()
                    break
            if description:
                break

    fields: dict[str, Any] = {}
    fields.update(_extract_cvss(container_items))
    cwes = _extract_cwe(container_items)
    if cwes:
        fields["x_opencti_cwe"] = cwes
    date_published = meta.get("datePublished")
    if isinstance(date_published, str) and date_published.strip():
        normalized = _normalize_opencti_date(date_published)
        if normalized:
            fields["x_opencti_first_seen_active"] = normalized

    affected = []
    for container in container_items:
        items = container.get("affected") if isinstance(container, dict) else None
        if isinstance(items, list):
            affected.extend([item for item in items if isinstance(item, dict)])
    affected_lines, software_names = _summarize_affected(affected)
    if affected_lines:
        extra = "\n".join(f"- {line}" for line in affected_lines)
        if description:
            description = f"{description}\n\nAffected:\n{extra}"
        else:
            description = f"Affected:\n{extra}"

    return {
        "cve_id": cve_id,
        "description": description,
        "references": sorted(set(references)),
        "fields": fields,
        "software": software_names,
        "epss": epss_scores.get(cve_id, {}),
    }


class OpenCTIClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.client = httpx.Client(timeout=30)
        self._external_refs_supported = True
        self._observables_supported = True
        self._software_supported = True
        self._software_checked = False

    def close(self) -> None:
        self.client.close()

    def _post(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        response = self.client.post(
            f"{self.base_url}/graphql",
            json={"query": query, "variables": variables},
            headers=headers,
        )
        response.raise_for_status()
        payload = response.json()
        if "errors" in payload:
            raise RuntimeError(payload["errors"])
        return payload.get("data", {})

    def find_vulnerability_id(self, name: str) -> str | None:
        query = """
        query VulnerabilityByName($name: Any!) {
          vulnerabilities(
            filters: {mode: and, filterGroups: [], filters: [{key: "name", values: [$name]}]}
            first: 1
          ) {
            edges { node { id } }
          }
        }
        """
        data = self._post(query, {"name": name})
        edges = data.get("vulnerabilities", {}).get("edges", [])
        if edges:
            return edges[0].get("node", {}).get("id")
        return None

    def find_software_id(self, name: str) -> str | None:
        if not self._software_supported:
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
        except Exception as exc:
            if "stixCoreObjects" in str(exc) or "GRAPHQL_VALIDATION_FAILED" in str(exc):
                self._software_supported = False
                logger.warning("cvelist_software_disabled")
                return None
            raise
        edges = data.get("stixCoreObjects", {}).get("edges", [])
        if edges:
            return edges[0].get("node", {}).get("id")
        return None

    def create_vulnerability(
        self, name: str, description: str | None, fields: dict[str, Any] | None = None
    ) -> str | None:
        mutation = """
        mutation VulnerabilityAdd($input: VulnerabilityAddInput!) {
          vulnerabilityAdd(input: $input) { id }
        }
        """
        input_payload: dict[str, Any] = {"name": name}
        if description:
            input_payload["description"] = description
        if fields:
            for key, value in fields.items():
                if value is None:
                    continue
                input_payload[key] = value
        try:
            data = self._post(mutation, {"input": input_payload})
        except Exception as exc:
            if _is_cvss4_vector_error(exc) and _strip_cvss4_fields(input_payload):
                data = self._post(mutation, {"input": input_payload})
            else:
                raise
        return data.get("vulnerabilityAdd", {}).get("id")

    def create_software(self, name: str) -> str | None:
        if not self._software_supported:
            return None
        if not self._software_checked:
            self._software_checked = True
        mutation = """
        mutation SoftwareAdd($type: String!, $Software: SoftwareAddInput) {
          stixCyberObservableAdd(type: $type, Software: $Software) { id }
        }
        """
        try:
            data = self._post(
                mutation, {"type": "Software", "Software": {"name": name}}
            )
        except Exception as exc:
            if (
                "softwareAdd" in str(exc)
                or "stixCyberObservableAdd" in str(exc)
                or "GRAPHQL_VALIDATION_FAILED" in str(exc)
            ):
                self._software_supported = False
                logger.warning("cvelist_software_disabled")
                return None
            raise
        return data.get("stixCyberObservableAdd", {}).get("id")

    def update_description(self, vuln_id: str, description: str) -> None:
        mutation = """
        mutation VulnerabilityEdit($id: ID!, $input: [EditInput]!) {
          stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) { id }
          }
        }
        """
        payload = [{"key": "description", "value": [description]}]
        self._post(mutation, {"id": vuln_id, "input": payload})

    def update_fields(self, vuln_id: str, fields: dict[str, Any]) -> None:
        if not fields:
            return
        mutation = """
        mutation VulnerabilityEdit($id: ID!, $input: [EditInput]!) {
          stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) { id }
          }
        }
        """

        def _build_inputs(payload: dict[str, Any]) -> list[dict[str, Any]]:
            inputs: list[dict[str, Any]] = []
            for key, value in payload.items():
                if value is None:
                    continue
                if isinstance(value, list):
                    values = [str(item) for item in value if str(item).strip()]
                    if not values:
                        continue
                    inputs.append({"key": key, "value": values})
                else:
                    values = [str(value)]
                    inputs.append({"key": key, "value": values})
            return inputs

        inputs = _build_inputs(fields)
        if not inputs:
            return
        try:
            self._post(mutation, {"id": vuln_id, "input": inputs})
        except Exception as exc:
            if _is_cvss4_vector_error(exc) and _strip_cvss4_fields(fields):
                retry_inputs = _build_inputs(fields)
                if retry_inputs:
                    self._post(mutation, {"id": vuln_id, "input": retry_inputs})
            else:
                raise

    def add_external_reference(self, vuln_id: str, source_name: str, url: str) -> None:
        if not self._external_refs_supported:
            self._add_reference_observable(vuln_id, url)
            return
        create_mutation = """
        mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
          externalReferenceAdd(input: $input) { id }
        }
        """
        patch_mutation = """
        mutation VulnerabilityEdit($id: ID!, $input: [EditInput]!) {
          stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) { id }
          }
        }
        """
        payload = {"source_name": source_name, "url": url}
        try:
            data = self._post(create_mutation, {"input": payload})
            ext_id = data.get("externalReferenceAdd", {}).get("id")
            if not ext_id:
                return
            patch = [
                {"key": "externalReferences", "operation": "add", "value": [ext_id]}
            ]
            self._post(patch_mutation, {"id": vuln_id, "input": patch})
        except Exception as exc:
            if "externalReferences" in str(exc) or "externalReferenceAdd" in str(exc):
                self._external_refs_supported = False
                logger.warning("cvelist_external_refs_disabled")
                self._add_reference_observable(vuln_id, url)
                return
            raise

    def _add_reference_observable(self, vuln_id: str, url: str) -> None:
        obs_id = self.create_observable("Url", url)
        if obs_id:
            self.create_relationship(vuln_id, obs_id, "related-to")

    def create_observable(self, obs_type: str, value: str) -> str | None:
        if not self._observables_supported:
            return None
        normalized_value = (value or "").strip()
        normalized_type = obs_type
        if normalized_type in {"IPv4-Addr", "IPv6-Addr"}:
            candidate = normalized_value
            if candidate.startswith("[") and "]" in candidate:
                candidate = candidate[1 : candidate.index("]")]
            if normalized_type == "IPv4-Addr" and ":" in candidate:
                candidate = candidate.split(":", 1)[0]
            try:
                ip_addr = ipaddress.ip_address(candidate)
                normalized_type = "IPv4-Addr" if ip_addr.version == 4 else "IPv6-Addr"
                normalized_value = ip_addr.compressed
            except ValueError:
                normalized_value = value

        if normalized_type in {"Domain-Name", "DomainName"}:
            normalized_value = normalized_value.rstrip(".")
            if not re.match(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,}$", normalized_value):
                logger.warning(
                    "cvelist_observable_add_skipped type=%s value=%s",
                    normalized_type,
                    normalized_value,
                )
                return None

        field_map = {
            "IPv4-Addr": "IPv4Addr",
            "IPv6-Addr": "IPv6Addr",
            "Domain-Name": "DomainName",
            "DomainName": "DomainName",
            "Url": "Url",
            "Autonomous-System": "AutonomousSystem",
            "AutonomousSystem": "AutonomousSystem",
        }
        field = field_map.get(normalized_type)
        if not field:
            logger.warning("cvelist_observable_add_skipped type=%s", normalized_type)
            return None

        input_payload: dict[str, Any] = {"value": normalized_value}
        if field == "AutonomousSystem":
            raw = normalized_value.upper().lstrip("AS")
            try:
                input_payload = {"number": int(raw)}
            except ValueError:
                logger.warning(
                    "cvelist_observable_add_skipped type=%s value=%s",
                    normalized_type,
                    normalized_value,
                )
                return None

        mutation = f"""
        mutation ObservableAdd($type: String!, ${field}: {field}AddInput) {{
          stixCyberObservableAdd(type: $type, {field}: ${field}) {{ id }}
        }}
        """
        try:
            data = self._post(mutation, {"type": normalized_type, field: input_payload})
        except Exception as exc:
            message = str(exc)
            if (
                "Unknown argument" in message
                or "Cannot query field" in message
                or "GRAPHQL_VALIDATION_FAILED" in message
            ):
                self._observables_supported = False
                logger.warning("cvelist_observable_add_disabled")
                return None
            if "Observable is not correctly formatted" in message:
                logger.warning("cvelist_observable_add_failed error=%s", exc)
                return None
            logger.warning("cvelist_observable_add_failed error=%s", exc)
            return None
        return data.get("stixCyberObservableAdd", {}).get("id")

    def create_relationship(self, from_id: str, to_id: str, rel_type: str) -> None:
        mutation = """
        mutation RelationAdd($input: StixCoreRelationshipAddInput!) {
          stixCoreRelationshipAdd(input: $input) { id }
        }
        """
        payload = {"fromId": from_id, "toId": to_id, "relationship_type": rel_type}
        try:
            self._post(mutation, {"input": payload})
        except Exception as exc:
            logger.warning("cvelist_relationship_add_failed error=%s", exc)


def _process_cve_file(
    client: OpenCTIClient, path: Path, epss_scores: dict[str, dict[str, float]]
) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("cvelist_parse_failed file=%s error=%s", path, exc)
        return

    payloads: list[dict[str, Any]]
    if isinstance(payload, list):
        logger.info("cvelist_list_payload file=%s items=%s", path, len(payload))
        payloads = [item for item in payload if isinstance(item, dict)]
    else:
        payloads = [payload] if isinstance(payload, dict) else []

    for item in payloads:
        extracted = _extract_cve(item, epss_scores)
        if not extracted:
            continue
        cve_id = extracted["cve_id"]
        description = extracted["description"]
        references = extracted["references"]
        fields = dict(extracted["fields"])
        epss_fields = extracted["epss"]
        if epss_fields:
            fields.update(epss_fields)
        software_names = extracted["software"]

        vuln_id = client.find_vulnerability_id(cve_id)
        created = False
        if not vuln_id:
            try:
                vuln_id = client.create_vulnerability(cve_id, description, fields)
                created = True
            except Exception as exc:
                logger.warning("cvelist_create_failed cve_id=%s error=%s", cve_id, exc)
                continue

        if vuln_id:
            update_fields = dict(fields)
            if description:
                update_fields["description"] = description
            if update_fields:
                try:
                    client.update_fields(vuln_id, update_fields)
                except Exception as exc:
                    logger.warning(
                        "cvelist_update_failed cve_id=%s error=%s", cve_id, exc
                    )

        for url in references:
            try:
                client.add_external_reference(vuln_id, "cvelistv5", url)
            except Exception as exc:
                logger.warning(
                    "cvelist_reference_failed cve_id=%s url=%s error=%s",
                    cve_id,
                    url,
                    exc,
                )
                continue

        for name in software_names:
            try:
                software_id = client.find_software_id(name)
                if not software_id:
                    software_id = client.create_software(name)
                if software_id:
                    client.create_relationship(vuln_id, software_id, "related-to")
            except Exception as exc:
                logger.warning(
                    "cvelist_software_link_failed cve_id=%s software=%s error=%s",
                    cve_id,
                    name,
                    exc,
                )

        logger.info("cvelist_processed cve_id=%s created=%s", cve_id, created)


class CveListConnector:
    def __init__(self) -> None:
        opencti_url = os.getenv("OPENCTI_URL", "http://opencti:8080")
        os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
        opencti_token = _select_opencti_token()
        if not opencti_token:
            raise RuntimeError("cvelist_missing_token")

        connector_id = os.getenv("CONNECTOR_ID", "").strip()
        if not connector_id:
            raise RuntimeError("cvelist_missing_connector_id")
        connector_name = os.getenv("CONNECTOR_NAME", "CVE List V5")
        connector_type = os.getenv("CONNECTOR_TYPE", "EXTERNAL_IMPORT")
        connector_scope = os.getenv("CONNECTOR_SCOPE", "vulnerability")
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
        self.repo_url = os.getenv(
            "CVELIST_REPO_URL", "https://github.com/CVEProject/cvelistV5.git"
        )
        self.branch = os.getenv("CVELIST_BRANCH", "main")
        self.interval = int(
            os.getenv(
                "CONNECTOR_RUN_INTERVAL_SECONDS",
                os.getenv("CVELIST_RUN_INTERVAL_SECONDS", "3600"),
            )
        )
        self.repo_path = Path("/data/cvelistV5")
        self.state = StateStore("/data/state.json")
        self.client = OpenCTIClient(opencti_url, opencti_token)
        self.epss_url = os.getenv("CVELIST_EPSS_URL", EPSS_DEFAULT_URL)
        self.epss_refresh_seconds = int(
            os.getenv("CVELIST_EPSS_REFRESH_SECONDS", str(EPSS_DEFAULT_REFRESH_SECONDS))
        )
        self.epss_path = Path("/data/epss/epss_scores-current.csv.gz")

    def _run(self) -> None:
        run_state = ConnectorState(self.helper, "CVE List V5")
        run_state.start()
        metrics = {
            "files_total": 0,
            "files_processed": 0,
            "epss_refreshed": 0,
        }
        work = WorkTracker(self.helper, "CVE List V5 import")
        try:
            refreshed = _ensure_epss_file(
                self.epss_path, self.epss_url, self.epss_refresh_seconds
            )
            if refreshed:
                logger.info("cvelist_epss_refreshed")
                metrics["epss_refreshed"] = 1
            epss_scores = _load_epss_scores(self.epss_path)
            _ensure_repo(self.repo_url, self.branch, self.repo_path)
            head = _get_head_commit(self.repo_path)
            last_commit = self.state.get("last_commit")
            if last_commit == head:
                logger.info("cvelist_no_changes")
                work.done("No changes")
                metrics["cursor_last_commit"] = head
                run_state.skipped("no_changes", **metrics)
                return
            changed = None
            if last_commit:
                changed = _changed_files(self.repo_path, last_commit, head)
                if not changed:
                    logger.info("cvelist_no_changed_files")
                    self.state.set("last_commit", head)
                    work.done("No changed files")
                    metrics["cursor_last_commit"] = head
                    run_state.skipped("no_changed_files", **metrics)
                    return
            total_files = len(changed) if changed is not None else 0
            metrics["files_total"] = total_files
            if total_files:
                work.log(f"files={total_files}")
            count = 0
            last_progress = -1
            for path in _iter_cve_files(self.repo_path, changed):
                _process_cve_file(self.client, path, epss_scores)
                count += 1
                if total_files:
                    percent = int((count / total_files) * 100)
                    if percent >= last_progress + 5:
                        work.progress(percent, f"processed_files={count}/{total_files}")
                        last_progress = percent
                elif count % 100 == 0:
                    work.progress(None, f"processed_files={count}")
            logger.info("cvelist_run_complete count=%s", count)
            self.state.set("last_commit", head)
            metrics["cursor_last_commit"] = head
            work.done(f"files={count}")
            metrics["files_processed"] = count
            run_state.success(**metrics)
        except Exception as exc:
            logger.warning("cvelist_run_failed error=%s", exc)
            work.done("Run failed")
            run_state.failure(str(exc), **metrics)

    def run(self) -> None:
        if hasattr(self.helper, "schedule"):
            self.helper.schedule(self._run, self.interval)
            return
        while True:
            self._run()
            time.sleep(self.interval)


def main() -> None:
    try:
        connector = CveListConnector()
    except Exception as exc:
        logger.warning("cvelist_startup_failed error=%s", exc)
        return
    connector.run()


if __name__ == "__main__":
    main()
