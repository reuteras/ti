import json
import logging
import os
import uuid
from contextvars import ContextVar
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, PackageLoader, select_autoescape

from .briefing import build_daily_briefing
from .miniflux_admin import refresh_feeds
from .opencti_client import OpenCTIClient
from .readwise_admin import refresh_tags as refresh_readwise_tags
from .rss import build_rss_feed
from .storage import Storage
from .zotero_admin import refresh_collections as refresh_zotero_collections
from .zotero_admin import refresh_tags as refresh_zotero_tags

REQUEST_ID_CTX: ContextVar[str] = ContextVar("request_id", default="-")


def _configure_logging() -> None:
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()

    class RequestIdFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.request_id = REQUEST_ID_CTX.get("-")
            return True

    formatter = logging.Formatter(
        "time=%(asctime)s level=%(levelname)s request_id=%(request_id)s msg=%(message)s"
    )
    handler.setFormatter(formatter)
    handler.addFilter(RequestIdFilter())
    logger.handlers = [handler]


_configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI()

storage: Storage | None = None
scheduler: BackgroundScheduler | None = None
env = Environment(
    loader=PackageLoader("briefing_service", "templates"),
    autoescape=select_autoescape(["html"]),
)


def _get_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    token = REQUEST_ID_CTX.set(request_id)
    try:
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response
    finally:
        REQUEST_ID_CTX.reset(token)


@app.on_event("startup")
def on_startup() -> None:
    global storage, scheduler
    storage = Storage(os.getenv("BRIEFING_DB_PATH", "/data/briefing.sqlite"))
    opencti_token = os.getenv("OPENCTI_APP__ADMIN__TOKEN") or os.getenv("OPENCTI_ADMIN_TOKEN", "")
    client = OpenCTIClient(
        os.getenv("OPENCTI_URL", "http://opencti:8080"),
        opencti_token,
        fallback_token=os.getenv("OPENCTI_APP__ADMIN__TOKEN", ""),
    )

    def run_daily_job() -> None:
        if storage is None:
            return
        briefing = build_daily_briefing(storage, client)
        logger.info("daily_briefing_generated date=%s items=%s", briefing.date, len(briefing.items))

    def refresh_miniflux_job() -> None:
        if storage is None:
            return
        count = refresh_feeds(storage)
        logger.info("miniflux_feeds_refreshed count=%s", count)

    def refresh_zotero_job() -> None:
        if storage is None:
            return
        tag_count = refresh_zotero_tags(storage)
        collection_count = refresh_zotero_collections(storage)
        if tag_count:
            logger.info("zotero_tags_refreshed count=%s", tag_count)
        if collection_count:
            logger.info("zotero_collections_refreshed count=%s", collection_count)

    def refresh_readwise_job() -> None:
        if storage is None:
            return
        max_pages = _get_env_int("READWISE_TAG_REFRESH_MAX_PAGES", 5)
        tag_count = refresh_readwise_tags(storage, max_pages=max_pages)
        if tag_count:
            logger.info("readwise_tags_refreshed count=%s", tag_count)

    tz_name = os.getenv("BRIEFING_TIMEZONE", "Europe/Stockholm")
    scheduler = BackgroundScheduler(timezone=ZoneInfo(tz_name))
    trigger = CronTrigger(
        hour=_get_env_int("BRIEFING_SCHEDULE_HOUR", 4),
        minute=_get_env_int("BRIEFING_SCHEDULE_MINUTE", 5),
    )
    scheduler.add_job(run_daily_job, trigger, id="daily_briefing")
    scheduler.add_job(refresh_miniflux_job, IntervalTrigger(hours=1), id="miniflux_refresh")
    scheduler.add_job(refresh_zotero_job, IntervalTrigger(hours=1), id="zotero_refresh")
    readwise_interval = int(os.getenv("READWISE_TAG_REFRESH_MINUTES", "60"))
    scheduler.add_job(
        refresh_readwise_job,
        IntervalTrigger(minutes=readwise_interval),
        id="readwise_refresh",
    )
    scheduler.start()
    run_daily_job()
    refresh_miniflux_job()
    refresh_zotero_job()
    refresh_readwise_job()


@app.on_event("shutdown")
def on_shutdown() -> None:
    if scheduler:
        scheduler.shutdown(wait=False)
    if storage:
        storage.close()


@app.get("/health", response_class=PlainTextResponse)
async def health() -> str:
    return "ok"


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    links = [
        ("/miniflux/feeds", "Miniflux feeds"),
        ("/readwise/tags", "Readwise tags"),
        ("/zotero/tags", "Zotero tags"),
        ("/zotero/collections", "Zotero collections"),
        ("/feeds/daily.rss", "Daily briefings RSS"),
        ("/latest", "Latest briefing"),
    ]
    rows = "".join(f"<li><a href=\"{path}\">{label}</a></li>" for path, label in links)
    return f"<html><body><h1>Briefing Service</h1><ul>{rows}</ul></body></html>"


@app.get("/latest", response_class=HTMLResponse)
async def latest() -> str:
    if storage is None:
        return "<html><body>Storage not ready</body></html>"
    latest_briefing = storage.get_latest_briefing()
    if not latest_briefing:
        return "<html><body>No briefing available</body></html>"
    return latest_briefing.html


@app.get("/briefings/daily/today", response_class=HTMLResponse)
async def today() -> str:
    if storage is None:
        return "<html><body>Storage not ready</body></html>"
    latest_briefing = storage.get_latest_briefing()
    if not latest_briefing:
        return "<html><body>No briefing available</body></html>"
    return latest_briefing.html


@app.get("/briefings/{date}.json")
async def briefing_json(date: str) -> Response:
    if storage is None:
        return Response(content="{}", media_type="application/json")
    briefing = storage.get_briefing(date)
    if not briefing:
        return Response(content="{}", media_type="application/json")
    return Response(content=briefing.json, media_type="application/json")


@app.get("/feeds/daily.rss", response_class=Response)
async def daily_rss() -> Response:
    if storage is None:
        return Response(content="", media_type="application/rss+xml")
    briefings = storage.get_recent_briefings(limit=20)
    base_url = os.getenv("BRIEFING_BASE_URL", "http://localhost:8088")
    rss = build_rss_feed(briefings, base_url)
    return Response(content=rss, media_type="application/rss+xml")


@app.get("/feeds/daily.xsl", response_class=Response)
async def daily_xsl() -> Response:
    template = env.get_template("daily.xsl")
    return Response(content=template.render(), media_type="text/xsl")


@app.get("/miniflux/feeds", response_class=HTMLResponse)
async def miniflux_feeds() -> str:
    if storage is None:
        return "<html><body>Storage not ready</body></html>"
    feeds = storage.list_miniflux_feeds()
    template = env.get_template("miniflux_feeds.html")
    return template.render(feeds=feeds)


@app.get("/miniflux/feeds/approved.json")
async def miniflux_feeds_approved() -> Response:
    if storage is None:
        return Response(content="[]", media_type="application/json")
    approved = storage.get_miniflux_approved_ids()
    payload = json.dumps(approved)
    return Response(content=payload, media_type="application/json")


@app.post("/miniflux/feeds/refresh")
async def miniflux_feeds_refresh() -> RedirectResponse:
    if storage is None:
        return RedirectResponse("/miniflux/feeds", status_code=303)
    refresh_feeds(storage)
    return RedirectResponse("/miniflux/feeds", status_code=303)


@app.post("/miniflux/feeds/refresh.json")
async def miniflux_feeds_refresh_json() -> Response:
    if storage is None:
        return Response(content="{\"status\":\"not_ready\"}", media_type="application/json")
    count = refresh_feeds(storage)
    payload = json.dumps({"status": "ok", "count": count})
    return Response(content=payload, media_type="application/json")


@app.post("/miniflux/feeds/{feed_id}/approve")
async def miniflux_feed_approve(feed_id: int) -> RedirectResponse:
    if storage is not None:
        storage.set_miniflux_feed_approved(feed_id, True)
    return RedirectResponse("/miniflux/feeds", status_code=303)


@app.post("/miniflux/feeds/{feed_id}/reject")
async def miniflux_feed_reject(feed_id: int) -> RedirectResponse:
    if storage is not None:
        storage.set_miniflux_feed_approved(feed_id, False)
    return RedirectResponse("/miniflux/feeds", status_code=303)


@app.post("/miniflux/categories/{category_id}/approve")
async def miniflux_category_approve(category_id: int) -> RedirectResponse:
    if storage is not None:
        storage.approve_miniflux_category(category_id)
    return RedirectResponse("/miniflux/feeds", status_code=303)


@app.get("/readwise/tags", response_class=HTMLResponse)
async def readwise_tags() -> str:
    if storage is None:
        return "<html><body>Storage not ready</body></html>"
    tags = storage.list_readwise_tags()
    template = env.get_template("readwise_tags.html")
    return template.render(tags=tags)


@app.get("/readwise/tags/approved.json")
async def readwise_tags_approved() -> Response:
    if storage is None:
        return Response(content="[]", media_type="application/json")
    approved = storage.get_readwise_approved_tags()
    return Response(content=json.dumps(approved), media_type="application/json")


@app.post("/readwise/tags/refresh")
async def readwise_tags_refresh() -> RedirectResponse:
    if storage is not None:
        max_pages = _get_env_int("READWISE_TAG_REFRESH_MAX_PAGES", 5)
        refresh_readwise_tags(storage, max_pages=max_pages)
    return RedirectResponse("/readwise/tags", status_code=303)


@app.post("/readwise/tags/approve")
async def readwise_tag_approve(request: Request) -> RedirectResponse:
    if storage is not None:
        form = await request.form()
        tag = (form.get("tag") or "").strip()
        if tag:
            storage.set_readwise_tag_approved(tag, True)
    return RedirectResponse("/readwise/tags", status_code=303)


@app.post("/readwise/tags/reject")
async def readwise_tag_reject(request: Request) -> RedirectResponse:
    if storage is not None:
        form = await request.form()
        tag = (form.get("tag") or "").strip()
        if tag:
            storage.set_readwise_tag_approved(tag, False)
    return RedirectResponse("/readwise/tags", status_code=303)


@app.get("/zotero/tags", response_class=HTMLResponse)
async def zotero_tags() -> str:
    if storage is None:
        return "<html><body>Storage not ready</body></html>"
    tags = storage.list_zotero_tags()
    template = env.get_template("zotero_tags.html")
    return template.render(tags=tags)


@app.get("/zotero/collections", response_class=HTMLResponse)
async def zotero_collections() -> str:
    if storage is None:
        return "<html><body>Storage not ready</body></html>"
    collections = storage.list_zotero_collections()
    template = env.get_template("zotero_collections.html")
    return template.render(collections=collections)


@app.get("/zotero/tags/approved.json")
async def zotero_tags_approved() -> Response:
    if storage is None:
        return Response(content="[]", media_type="application/json")
    approved = storage.get_zotero_approved_tags()
    return Response(content=json.dumps(approved), media_type="application/json")


@app.get("/zotero/collections/approved.json")
async def zotero_collections_approved() -> Response:
    if storage is None:
        return Response(content="[]", media_type="application/json")
    approved = storage.get_zotero_approved_collections()
    return Response(content=json.dumps(approved), media_type="application/json")


@app.post("/zotero/tags/refresh")
async def zotero_tags_refresh() -> RedirectResponse:
    if storage is not None:
        refresh_zotero_tags(storage)
    return RedirectResponse("/zotero/tags", status_code=303)


@app.post("/zotero/collections/refresh")
async def zotero_collections_refresh() -> RedirectResponse:
    if storage is not None:
        refresh_zotero_collections(storage)
    return RedirectResponse("/zotero/collections", status_code=303)


@app.post("/zotero/tags/approve")
async def zotero_tag_approve(request: Request) -> RedirectResponse:
    if storage is not None:
        form = await request.form()
        tag = (form.get("tag") or "").strip()
        if tag:
            storage.set_zotero_tag_approved(tag, True)
    return RedirectResponse("/zotero/tags", status_code=303)


@app.post("/zotero/tags/reject")
async def zotero_tag_reject(request: Request) -> RedirectResponse:
    if storage is not None:
        form = await request.form()
        tag = (form.get("tag") or "").strip()
        if tag:
            storage.set_zotero_tag_approved(tag, False)
    return RedirectResponse("/zotero/tags", status_code=303)


@app.post("/zotero/collections/approve")
async def zotero_collection_approve(request: Request) -> RedirectResponse:
    if storage is not None:
        form = await request.form()
        collection_id = (form.get("collection_id") or "").strip()
        if collection_id:
            storage.set_zotero_collection_approved(collection_id, True)
    return RedirectResponse("/zotero/collections", status_code=303)


@app.post("/zotero/collections/reject")
async def zotero_collection_reject(request: Request) -> RedirectResponse:
    if storage is not None:
        form = await request.form()
        collection_id = (form.get("collection_id") or "").strip()
        if collection_id:
            storage.set_zotero_collection_approved(collection_id, False)
    return RedirectResponse("/zotero/collections", status_code=303)
