import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OpenCTIReport:
    title: str
    description: str
    created_at: str
    source_url: str
    cves: list[str]
    observables: list[str]


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


class OpenCTIClient:
    def __init__(
        self, base_url: str, admin_token: str, fallback_token: str | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token
        self.fallback_token = fallback_token or ""

    def _post_with_token(
        self, token: str, query: str, variables: dict[str, Any]
    ) -> dict[str, Any]:
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
            if (
                self.fallback_token
                and self.fallback_token != self.admin_token
                and _is_auth_required(exc)
            ):
                return self._post_with_token(self.fallback_token, query, variables)
            raise

    def reports_since(self, since: datetime) -> list[OpenCTIReport]:
        if not self.admin_token:
            logger.warning("opencti_token_missing")
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
                description
                created_at
                externalReferences {
                  edges { node { url source_name } }
                }
              }
            }
          }
        }
        """
        try:
            data = self._post(query, {"from": since.isoformat()})
        except Exception as exc:
            logger.exception("opencti_query_failed error=%s", exc)
            return []

        reports: list[OpenCTIReport] = []
        for edge in data.get("reports", {}).get("edges", []):
            node = edge.get("node", {})
            description = node.get("description") or ""
            created_at = node.get("created_at") or ""
            external_refs = node.get("externalReferences", {}).get("edges", [])
            source_url = ""
            if external_refs:
                source_url = external_refs[0].get("node", {}).get("url", "")
            reports.append(
                OpenCTIReport(
                    title=node.get("name", "Untitled"),
                    description=description,
                    created_at=created_at,
                    source_url=source_url,
                    cves=[],
                    observables=[],
                )
            )
        return reports
