import logging
import os
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


@dataclass
class DailyMetrics:
    new_cves: int = 0
    new_iocs: int = 0
    cisa_kev_new: int = 0
    cisa_kev_updated: int = 0
    kev_update_field: str = "none"


@dataclass
class OpenCTIIntrusionSet:
    id: str
    name: str
    created_at: str


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

    def reports_between(self, start: datetime, end: datetime) -> list[OpenCTIReport]:
        if not self.admin_token:
            logger.warning("opencti_token_missing")
            return []
        page_size = max(1, int(os.getenv("BRIEFING_OPENCTI_PAGE_SIZE", "200")))
        max_pages = max(1, int(os.getenv("BRIEFING_OPENCTI_MAX_PAGES", "50")))
        query = """
        query Reports($from: Any!, $to: Any!, $first: Int!, $after: ID) {
          reports(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "created_at", values: [$from], operator: gte},
                {key: "created_at", values: [$to], operator: lt}
              ]
            }
            first: $first
            after: $after
            orderBy: created_at
            orderMode: desc
          ) {
            pageInfo {
              hasNextPage
              endCursor
            }
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
        reports: list[OpenCTIReport] = []
        cursor: str | None = None
        pages = 0
        while pages < max_pages:
            try:
                data = self._post(
                    query,
                    {
                        "from": start.isoformat(),
                        "to": end.isoformat(),
                        "first": page_size,
                        "after": cursor,
                    },
                )
            except Exception as exc:
                logger.exception("opencti_query_failed error=%s", exc)
                return reports

            report_block = data.get("reports", {})
            for edge in report_block.get("edges", []):
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

            page_info = report_block.get("pageInfo", {})
            has_next = bool(page_info.get("hasNextPage"))
            cursor = page_info.get("endCursor")
            pages += 1
            if not has_next or not cursor:
                break
        if pages >= max_pages and cursor:
            logger.warning(
                "opencti_query_pagination_capped max_pages=%s page_size=%s reports=%s",
                max_pages,
                page_size,
                len(reports),
            )
        return reports

    def get_daily_metrics(self, start: datetime, end: datetime) -> DailyMetrics:
        if not self.admin_token:
            return DailyMetrics()
        metrics = DailyMetrics()
        metrics.new_cves = self._count_vulnerabilities_by_date(start, end, "created_at")
        metrics.new_iocs = self._count_observables_by_created_at(start, end)
        metrics.cisa_kev_new = self._count_kev_by_date(start, end, "created_at")[0]

        kev_updated, used_field = self._count_kev_updates(start, end)
        metrics.cisa_kev_updated = kev_updated
        metrics.kev_update_field = used_field
        return metrics

    def intrusion_sets_between(
        self, start: datetime, end: datetime
    ) -> list[OpenCTIIntrusionSet]:
        if not self.admin_token:
            return []
        page_size = max(1, int(os.getenv("BRIEFING_OPENCTI_PAGE_SIZE", "200")))
        max_pages = max(1, int(os.getenv("BRIEFING_OPENCTI_MAX_PAGES", "50")))
        query = """
        query IntrusionSets($from: Any!, $to: Any!, $first: Int!, $after: ID) {
          intrusionSets(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "created_at", values: [$from], operator: gte},
                {key: "created_at", values: [$to], operator: lt}
              ]
            }
            first: $first
            after: $after
            orderBy: created_at
            orderMode: desc
          ) {
            pageInfo { hasNextPage endCursor }
            edges {
              node {
                id
                name
                created_at
              }
            }
          }
        }
        """
        items: list[OpenCTIIntrusionSet] = []
        cursor: str | None = None
        pages = 0
        while pages < max_pages:
            try:
                data = self._post(
                    query,
                    {
                        "from": start.isoformat(),
                        "to": end.isoformat(),
                        "first": page_size,
                        "after": cursor,
                    },
                )
            except Exception:
                return items
            block = data.get("intrusionSets", {})
            for edge in block.get("edges", []):
                node = edge.get("node", {})
                items.append(
                    OpenCTIIntrusionSet(
                        id=node.get("id", ""),
                        name=node.get("name", "Unnamed Intrusion Set"),
                        created_at=node.get("created_at", ""),
                    )
                )
            page_info = block.get("pageInfo", {})
            has_next = bool(page_info.get("hasNextPage"))
            cursor = page_info.get("endCursor")
            pages += 1
            if not has_next or not cursor:
                break
        return items

    def _count_vulnerabilities_by_date(
        self, start: datetime, end: datetime, date_field: str
    ) -> int:
        query = """
        query Vulnerabilities($from: Any!, $to: Any!, $first: Int!, $after: ID) {
          vulnerabilities(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "__DATE_FIELD__", values: [$from], operator: gte},
                {key: "__DATE_FIELD__", values: [$to], operator: lt}
              ]
            }
            first: $first
            after: $after
            orderBy: created_at
            orderMode: desc
          ) {
            pageInfo { hasNextPage endCursor }
            edges { node { id } }
          }
        }
        """.replace("__DATE_FIELD__", date_field)
        return self._count_edges(query, start, end)

    def _count_observables_by_created_at(self, start: datetime, end: datetime) -> int:
        query = """
        query Observables($from: Any!, $to: Any!, $first: Int!, $after: ID) {
          stixCyberObservables(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "created_at", values: [$from], operator: gte},
                {key: "created_at", values: [$to], operator: lt}
              ]
            }
            first: $first
            after: $after
            orderBy: created_at
            orderMode: desc
          ) {
            pageInfo { hasNextPage endCursor }
            edges { node { id } }
          }
        }
        """
        return self._count_edges(query, start, end, root_field="stixCyberObservables")

    def _count_kev_by_date(
        self, start: datetime, end: datetime, date_field: str
    ) -> tuple[int, bool]:
        query = """
        query Vulnerabilities($from: Any!, $to: Any!, $first: Int!, $after: ID) {
          vulnerabilities(
            filters: {
              mode: and,
              filterGroups: [],
              filters: [
                {key: "__DATE_FIELD__", values: [$from], operator: gte},
                {key: "__DATE_FIELD__", values: [$to], operator: lt}
              ]
            }
            first: $first
            after: $after
            orderBy: created_at
            orderMode: desc
          ) {
            pageInfo { hasNextPage endCursor }
            edges {
              node {
                id
                objectLabel { edges { node { value } } }
              }
            }
          }
        }
        """.replace("__DATE_FIELD__", date_field)
        return self._count_kev_from_query(query, start, end)

    def _count_kev_updates(self, start: datetime, end: datetime) -> tuple[int, str]:
        for field in ("updated_at", "modified"):
            count, ok = self._count_kev_by_date(start, end, field)
            if ok:
                return count, field
        return 0, "none"

    def _count_kev_from_query(self, query: str, start: datetime, end: datetime) -> tuple[int, bool]:
        page_size = max(1, int(os.getenv("BRIEFING_METRICS_PAGE_SIZE", "200")))
        max_pages = max(1, int(os.getenv("BRIEFING_METRICS_MAX_PAGES", "20")))
        cursor: str | None = None
        pages = 0
        count = 0
        while pages < max_pages:
            try:
                data = self._post(
                    query,
                    {
                        "from": start.isoformat(),
                        "to": end.isoformat(),
                        "first": page_size,
                        "after": cursor,
                    },
                )
            except Exception:
                return 0, False
            block = data.get("vulnerabilities", {})
            for edge in block.get("edges", []):
                node = edge.get("node", {})
                labels = node.get("objectLabel", {}).get("edges", [])
                values = [
                    (label.get("node", {}).get("value") or "").strip().lower()
                    for label in labels
                ]
                if self._is_kev_label(values):
                    count += 1
            page_info = block.get("pageInfo", {})
            has_next = bool(page_info.get("hasNextPage"))
            cursor = page_info.get("endCursor")
            pages += 1
            if not has_next or not cursor:
                break
        return count, True

    def _is_kev_label(self, labels: list[str]) -> bool:
        if not labels:
            return False
        for value in labels:
            compact = value.replace("-", " ").replace("_", " ")
            if "kev" in compact:
                return True
            if "known exploited" in compact:
                return True
            if "cisa" in compact and "exploited" in compact:
                return True
        return False

    def _count_edges(
        self, query: str, start: datetime, end: datetime, root_field: str = "vulnerabilities"
    ) -> int:
        page_size = max(1, int(os.getenv("BRIEFING_METRICS_PAGE_SIZE", "200")))
        max_pages = max(1, int(os.getenv("BRIEFING_METRICS_MAX_PAGES", "20")))
        cursor: str | None = None
        pages = 0
        total = 0
        while pages < max_pages:
            try:
                data = self._post(
                    query,
                    {
                        "from": start.isoformat(),
                        "to": end.isoformat(),
                        "first": page_size,
                        "after": cursor,
                    },
                )
            except Exception:
                return 0
            block = data.get(root_field, {})
            total += len(block.get("edges", []))
            page_info = block.get("pageInfo", {})
            has_next = bool(page_info.get("hasNextPage"))
            cursor = page_info.get("endCursor")
            pages += 1
            if not has_next or not cursor:
                break
        return total
