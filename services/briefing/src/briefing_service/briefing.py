import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence
from urllib.parse import quote_plus, urlparse
from zoneinfo import ZoneInfo

from jinja2 import Environment, PackageLoader, select_autoescape

from .opencti_client import OpenCTIClient, OpenCTIIntrusionSet, OpenCTIReport
from .storage import Storage
from .watchlist import evaluate_watchlist

logger = logging.getLogger(__name__)

env = Environment(
    loader=PackageLoader("briefing_service", "templates"),
    autoescape=select_autoescape(["html"]),
)


@dataclass
class BriefingItem:
    title: str
    description: str
    source_url: str
    created_at: str
    cves: list[str]
    observables: list[str]
    watch_hit: bool = False


@dataclass
class Briefing:
    date: str
    html: str
    json: str
    items: list[BriefingItem]


@dataclass
class BriefingCluster:
    headline: str
    rationale: list[str]
    item_count: int
    watch_hits: int
    source_domains: list[str]
    cves: list[str]
    first_seen: str
    last_seen: str
    score: int
    items: list[BriefingItem]


def _render_html(
    date: str,
    items: Sequence[BriefingItem],
    clusters: Sequence[BriefingCluster],
    summary: dict[str, object],
) -> str:
    template = env.get_template("latest.html")
    return template.render(date=date, items=items, clusters=clusters, summary=summary)


def _to_item(report: OpenCTIReport) -> BriefingItem:
    return BriefingItem(
        title=report.title,
        description=report.description,
        source_url=report.source_url,
        created_at=report.created_at,
        cves=report.cves,
        observables=report.observables,
    )


def _domain(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    return (parsed.netloc or "").lower().strip()


def _title_tokens(title: str) -> set[str]:
    stop = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "into",
        "that",
        "this",
        "your",
        "about",
        "new",
        "update",
        "report",
        "analysis",
        "security",
    }
    cleaned = "".join(ch.lower() if ch.isalnum() else " " for ch in title)
    return {part for part in cleaned.split() if len(part) > 2 and part not in stop}


def _title_similarity(left: str, right: str) -> float:
    left_tokens = _title_tokens(left)
    right_tokens = _title_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    overlap = len(left_tokens.intersection(right_tokens))
    union = len(left_tokens.union(right_tokens))
    if union == 0:
        return 0.0
    return overlap / union


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _is_related(left: BriefingItem, right: BriefingItem, title_threshold: float) -> bool:
    left_cves = {value.upper() for value in left.cves}
    right_cves = {value.upper() for value in right.cves}
    if left_cves.intersection(right_cves):
        return True

    left_obs = {value.lower() for value in left.observables}
    right_obs = {value.lower() for value in right.observables}
    if left_obs.intersection(right_obs):
        return True

    left_domain = _domain(left.source_url)
    right_domain = _domain(right.source_url)
    if left_domain and left_domain == right_domain:
        return True

    return _title_similarity(left.title, right.title) >= title_threshold


def _cluster_reports(items: list[BriefingItem]) -> list[list[BriefingItem]]:
    if not items:
        return []
    title_threshold = 0.45
    parent = list(range(len(items)))

    def find(idx: int) -> int:
        while parent[idx] != idx:
            parent[idx] = parent[parent[idx]]
            idx = parent[idx]
        return idx

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for left in range(len(items)):
        for right in range(left + 1, len(items)):
            if _is_related(items[left], items[right], title_threshold):
                union(left, right)

    grouped: dict[int, list[BriefingItem]] = {}
    for idx, item in enumerate(items):
        root = find(idx)
        grouped.setdefault(root, []).append(item)
    return list(grouped.values())


def _build_cluster(group: list[BriefingItem]) -> BriefingCluster:
    domains = sorted({_domain(item.source_url) for item in group if _domain(item.source_url)})
    cves = sorted({value.upper() for item in group for value in item.cves})
    watch_hits = sum(1 for item in group if item.watch_hit)

    timestamps = [dt for dt in (_parse_dt(item.created_at) for item in group) if dt]
    first_seen = ""
    last_seen = ""
    if timestamps:
        first_seen = min(timestamps).isoformat()
        last_seen = max(timestamps).isoformat()

    rationale: list[str] = []
    if watch_hits:
        rationale.append("watchlist hit")
    if cves:
        rationale.append("shared CVE context")
    if len(domains) == 1 and len(group) > 1:
        rationale.append(f"same source domain: {domains[0]}")
    if len(group) >= 3:
        rationale.append("multi-source corroboration")
    if not rationale:
        rationale.append("title and context similarity")

    score = watch_hits * 10 + len(cves) * 4 + len(domains) * 2 + len(group)
    headline = max(group, key=lambda item: len(item.title or "")).title or "Untitled cluster"
    return BriefingCluster(
        headline=headline,
        rationale=rationale,
        item_count=len(group),
        watch_hits=watch_hits,
        source_domains=domains,
        cves=cves,
        first_seen=first_seen,
        last_seen=last_seen,
        score=score,
        items=sorted(group, key=lambda item: item.created_at, reverse=True),
    )


def _build_opencti_links(start_utc: datetime, end_utc: datetime) -> dict[str, str]:
    base = (
        os.getenv("OPENCTI_EXTERNAL_URL")
        or os.getenv("OPENCTI_PUBLIC_URL")
        or os.getenv("OPENCTI_URL")
        or "http://localhost:8080"
    ).rstrip("/")
    search_path = os.getenv("OPENCTI_SEARCH_PATH", "/dashboard/search")
    if not search_path.startswith("/"):
        search_path = f"/{search_path}"
    search_base = f"{base}{search_path}"
    from_str = start_utc.isoformat()
    to_str = end_utc.isoformat()

    def _search(query: str) -> str:
        return f"{search_base}?q={quote_plus(query)}"

    return {
        "new_cves": _search(f"CVE-* AND created_at:[{from_str} TO {to_str}]"),
        "new_iocs": _search(
            f"(indicator OR observable) AND created_at:[{from_str} TO {to_str}]"
        ),
        "kev_new": _search(
            f"(kev OR \"known exploited\") AND created_at:[{from_str} TO {to_str}]"
        ),
        "kev_updated": _search(
            f"(kev OR \"known exploited\") AND (updated_at:[{from_str} TO {to_str}] OR modified:[{from_str} TO {to_str}])"
        ),
        "intrusion_sets": _search(
            f"\"Intrusion-Set\" AND created_at:[{from_str} TO {to_str}]"
        ),
    }


def _build_intrusion_set_links(
    intrusion_sets: list[OpenCTIIntrusionSet], search_base: str
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for item in intrusion_sets:
        rows.append(
            {
                "id": item.id,
                "name": item.name,
                "created_at": item.created_at,
                "opencti_url": f"{search_base}?q={quote_plus(item.name)}",
            }
        )
    return rows


def build_daily_briefing(storage: Storage, client: OpenCTIClient) -> Briefing:
    timezone_name = storage.get_state("briefing_timezone") or "Europe/Stockholm"
    local_tz = ZoneInfo(timezone_name)
    now_local = datetime.now(local_tz)
    target_day = (now_local - timedelta(days=1)).date()

    start_local = datetime.combine(target_day, datetime.min.time(), tzinfo=local_tz)
    end_local = start_local + timedelta(days=1)
    start_utc = start_local.astimezone(timezone.utc)
    end_utc = end_local.astimezone(timezone.utc)

    reports = client.reports_between(start_utc, end_utc)
    intrusion_sets = client.intrusion_sets_between(start_utc, end_utc)
    metrics = client.get_daily_metrics(start_utc, end_utc)
    items = [_to_item(report) for report in reports]
    evaluate_watchlist(storage, items)
    grouped = _cluster_reports(items)
    clusters = [_build_cluster(group) for group in grouped]
    clusters.sort(key=lambda cluster: (cluster.score, cluster.item_count), reverse=True)

    date_str = target_day.isoformat()
    opencti_links = _build_opencti_links(start_utc, end_utc)
    intrusion_set_rows = _build_intrusion_set_links(
        intrusion_sets, opencti_links["intrusion_sets"].split("?q=", 1)[0]
    )
    summary = {
        "total_reports": len(items),
        "total_clusters": len(clusters),
        "watch_hits": sum(1 for item in items if item.watch_hit),
        "new_cves": metrics.new_cves,
        "new_iocs": metrics.new_iocs,
        "cisa_kev_new": metrics.cisa_kev_new,
        "cisa_kev_updated": metrics.cisa_kev_updated,
        "kev_update_field": metrics.kev_update_field,
        "new_intrusion_sets": len(intrusion_sets),
        "opencti_links": opencti_links,
        "intrusion_sets": intrusion_set_rows,
    }
    html = _render_html(date_str, items, clusters, summary)
    json_payload = json.dumps(
        {
            "date": date_str,
            "items": [item.__dict__ for item in items],
            "summary": summary,
            "clusters": [
                {
                    "headline": cluster.headline,
                    "rationale": cluster.rationale,
                    "item_count": cluster.item_count,
                    "watch_hits": cluster.watch_hits,
                    "source_domains": cluster.source_domains,
                    "cves": cluster.cves,
                    "first_seen": cluster.first_seen,
                    "last_seen": cluster.last_seen,
                    "score": cluster.score,
                    "items": [item.__dict__ for item in cluster.items],
                }
                for cluster in clusters
            ],
        },
        indent=2,
    )
    briefing = Briefing(date=date_str, html=html, json=json_payload, items=items)
    storage.upsert_briefing(briefing)
    storage.set_state("last_run_timestamp", datetime.now(timezone.utc).isoformat())
    return briefing
