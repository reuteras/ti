import os
import uuid
from dataclasses import dataclass
from typing import Any

from .storage import Storage


@dataclass
class WatchItem:
    id: str
    value: str


def _seed_watch_items(storage: Storage) -> None:
    raw = os.getenv("WATCHLIST_SEED", "")
    values = [value.strip() for value in raw.split(",") if value.strip()]
    if not values:
        return
    with storage._lock:
        cursor = storage.conn.cursor()
        for value in values:
            cursor.execute(
                "INSERT OR IGNORE INTO watch_item(id, type, value) VALUES(?, ?, ?)",
                (str(uuid.uuid4()), "keyword", value),
            )
        storage._commit()


def _load_watch_items(storage: Storage) -> list[WatchItem]:
    cursor = storage.conn.cursor()
    cursor.execute("SELECT id, value FROM watch_item")
    return [WatchItem(id=row["id"], value=row["value"]) for row in cursor.fetchall()]


def evaluate_watchlist(storage: Storage, items: list[Any]) -> None:
    _seed_watch_items(storage)
    watch_items = _load_watch_items(storage)
    if not watch_items:
        return
    with storage._lock:
        cursor = storage.conn.cursor()
        for item in items:
            for watch in watch_items:
                if watch.value.lower() in (item.title + " " + item.description).lower():
                    item.watch_hit = True
                    cursor.execute(
                        "INSERT INTO watch_alert(id, watch_item_id, report_title, report_url, created_at) VALUES(?, ?, ?, ?, datetime('now'))",
                        (str(uuid.uuid4()), watch.id, item.title, item.source_url),
                    )
        storage._commit()
