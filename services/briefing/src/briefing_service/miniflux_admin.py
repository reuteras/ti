import logging
import os
from dataclasses import dataclass

import httpx

from .storage import MinifluxFeed, Storage

logger = logging.getLogger(__name__)


@dataclass
class MinifluxCategory:
    category_id: int
    title: str


def _normalize_base_url(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    if base_url.endswith("/v1"):
        return base_url[:-3]
    return base_url


def _client(token: str) -> httpx.Client:
    headers = {"X-Auth-Token": token}
    return httpx.Client(timeout=30, headers=headers)


def fetch_categories(base_url: str, token: str) -> dict[int, MinifluxCategory]:
    if not base_url or not token:
        return {}
    url = f"{_normalize_base_url(base_url)}/v1/categories"
    with _client(token) as client:
        response = client.get(url)
        response.raise_for_status()
        payload = response.json()
    categories: dict[int, MinifluxCategory] = {}
    for category in payload or []:
        category_id = int(category.get("id") or 0)
        if not category_id:
            continue
        categories[category_id] = MinifluxCategory(
            category_id=category_id,
            title=category.get("title") or "",
        )
    return categories


def refresh_feeds(storage: Storage) -> int:
    base_url = os.getenv("MINIFLUX_URL", "")
    token = os.getenv("MINIFLUX_TOKEN", "")
    if not base_url or not token:
        logger.warning("miniflux_not_configured")
        return 0

    url = f"{_normalize_base_url(base_url)}/v1/feeds"
    categories = fetch_categories(base_url, token)
    with _client(token) as client:
        response = client.get(url)
        response.raise_for_status()
        payload = response.json()

    count = 0
    for feed in payload or []:
        feed_id = int(feed.get("id") or 0)
        if not feed_id:
            continue
        category_id = int(feed.get("category", {}).get("id") or feed.get("category_id") or 0)
        category_title = ""
        if category_id and category_id in categories:
            category_title = categories[category_id].title
        storage.upsert_miniflux_feed(
            MinifluxFeed(
                feed_id=feed_id,
                title=feed.get("title") or "",
                site_url=feed.get("site_url") or "",
                feed_url=feed.get("feed_url") or "",
                category_id=category_id,
                category_title=category_title,
                approved=False,
            )
        )
        count += 1
    return count
