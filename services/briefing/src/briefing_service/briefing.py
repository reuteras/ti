import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from jinja2 import Environment, PackageLoader, select_autoescape

from .opencti_client import OpenCTIClient, OpenCTIReport
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


def _render_html(date: str, items: Sequence[BriefingItem]) -> str:
    template = env.get_template("latest.html")
    return template.render(date=date, items=items)


def _to_item(report: OpenCTIReport) -> BriefingItem:
    return BriefingItem(
        title=report.title,
        description=report.description,
        source_url=report.source_url,
        created_at=report.created_at,
        cves=report.cves,
        observables=report.observables,
    )


def build_daily_briefing(storage: Storage, client: OpenCTIClient) -> Briefing:
    now = datetime.now(timezone.utc)
    last_run = storage.get_state("last_run_timestamp")
    if last_run:
        since = datetime.fromisoformat(last_run)
    else:
        since = now - timedelta(hours=24)

    reports = client.reports_since(since)
    items = [_to_item(report) for report in reports]
    evaluate_watchlist(storage, items)

    date_str = now.date().isoformat()
    html = _render_html(date_str, items)
    json_payload = json.dumps(
        {
            "date": date_str,
            "items": [item.__dict__ for item in items],
        },
        indent=2,
    )
    briefing = Briefing(date=date_str, html=html, json=json_payload, items=items)
    storage.upsert_briefing(briefing)
    storage.set_state("last_run_timestamp", now.isoformat())
    return briefing
