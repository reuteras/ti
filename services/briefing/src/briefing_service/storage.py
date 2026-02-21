import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class BriefingRecord:
    date: str
    html: str
    json: str


@dataclass
class MinifluxFeed:
    feed_id: int
    title: str
    site_url: str
    feed_url: str
    category_id: int
    category_title: str
    approved: bool
    last_seen_at: str = ""


class Storage:
    def __init__(self, path: str) -> None:
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _commit(self) -> None:
        try:
            self.conn.commit()
        except sqlite3.OperationalError as exc:
            if "no transaction is active" in str(exc):
                return
            raise

    def _init_schema(self) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS briefing (
                    date TEXT PRIMARY KEY,
                    html TEXT NOT NULL,
                    json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS watch_item (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    aliases TEXT,
                    include_terms TEXT,
                    exclude_terms TEXT,
                    severity_override TEXT,
                    monitoring_interval_hours INTEGER,
                    websearch_enabled INTEGER,
                    last_checked_at TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS watch_alert (
                    id TEXT PRIMARY KEY,
                    watch_item_id TEXT NOT NULL,
                    report_title TEXT NOT NULL,
                    report_url TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS miniflux_feed (
                    feed_id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    site_url TEXT,
                    feed_url TEXT,
                    category_id INTEGER,
                    category_title TEXT,
                    approved INTEGER NOT NULL DEFAULT 0,
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS zotero_tag (
                    tag TEXT PRIMARY KEY,
                    approved INTEGER NOT NULL DEFAULT 0,
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS readwise_tag (
                    tag TEXT PRIMARY KEY,
                    approved INTEGER NOT NULL DEFAULT 0,
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS zotero_collection (
                    collection_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    parent_id TEXT,
                    approved INTEGER NOT NULL DEFAULT 0,
                    last_seen_at TEXT NOT NULL
                )
                """
            )
            self._ensure_column(cursor, "zotero_collection", "parent_id", "TEXT")
            self._commit()

    def _ensure_column(
        self, cursor: sqlite3.Cursor, table: str, column: str, col_type: str
    ) -> None:
        cursor.execute(f"PRAGMA table_info({table})")
        columns = {row[1] for row in cursor.fetchall()}
        if column in columns:
            return
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")

    def get_state(self, key: str) -> Optional[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM state WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO state(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._commit()

    def upsert_briefing(self, briefing) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO briefing(date, html, json, created_at)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(date) DO UPDATE SET html=excluded.html, json=excluded.json, created_at=excluded.created_at
                """,
                (
                    briefing.date,
                    briefing.html,
                    briefing.json,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._commit()

    def get_latest_briefing(self) -> Optional[BriefingRecord]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT date, html, json FROM briefing ORDER BY date DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if not row:
            return None
        return BriefingRecord(date=row["date"], html=row["html"], json=row["json"])

    def get_briefing(self, date: str) -> Optional[BriefingRecord]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT date, html, json FROM briefing WHERE date = ?", (date,))
        row = cursor.fetchone()
        if not row:
            return None
        return BriefingRecord(date=row["date"], html=row["html"], json=row["json"])

    def get_recent_briefings(self, limit: int) -> list[BriefingRecord]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT date, html, json FROM briefing ORDER BY date DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        return [
            BriefingRecord(date=row["date"], html=row["html"], json=row["json"])
            for row in rows
        ]

    def close(self) -> None:
        self.conn.close()

    def upsert_miniflux_feed(self, feed: MinifluxFeed) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO miniflux_feed(
                    feed_id, title, site_url, feed_url, category_id, category_title, approved, last_seen_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feed_id) DO UPDATE SET
                    title=excluded.title,
                    site_url=excluded.site_url,
                    feed_url=excluded.feed_url,
                    category_id=excluded.category_id,
                    category_title=excluded.category_title,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    feed.feed_id,
                    feed.title,
                    feed.site_url,
                    feed.feed_url,
                    feed.category_id,
                    feed.category_title,
                    1 if feed.approved else 0,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._commit()

    def list_miniflux_feeds(self) -> list[MinifluxFeed]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT feed_id, title, site_url, feed_url, category_id, category_title, approved, last_seen_at
            FROM miniflux_feed
            ORDER BY approved ASC, last_seen_at DESC, category_title ASC, title ASC
            """
        )
        rows = cursor.fetchall()
        return [
            MinifluxFeed(
                feed_id=row["feed_id"],
                title=row["title"],
                site_url=row["site_url"] or "",
                feed_url=row["feed_url"] or "",
                category_id=row["category_id"] or 0,
                category_title=row["category_title"] or "",
                approved=bool(row["approved"]),
                last_seen_at=row["last_seen_at"] or "",
            )
            for row in rows
        ]

    def set_miniflux_feed_approved(self, feed_id: int, approved: bool) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE miniflux_feed SET approved = ? WHERE feed_id = ?",
                (1 if approved else 0, feed_id),
            )
            self._commit()

    def approve_miniflux_category(self, category_id: int) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE miniflux_feed SET approved = 1 WHERE category_id = ?",
                (category_id,),
            )
            self._commit()

    def get_miniflux_approved_ids(self) -> list[int]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT feed_id FROM miniflux_feed WHERE approved = 1")
        rows = cursor.fetchall()
        return [int(row["feed_id"]) for row in rows]

    def upsert_zotero_tag(self, tag: str, approved: bool) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO zotero_tag(tag, approved, last_seen_at)
                VALUES(?, ?, ?)
                ON CONFLICT(tag) DO UPDATE SET
                    last_seen_at=excluded.last_seen_at
                """,
                (tag, 1 if approved else 0, datetime.now(timezone.utc).isoformat()),
            )
            self._commit()

    def list_zotero_tags(self) -> list[tuple[str, bool, str]]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT tag, approved, last_seen_at
            FROM zotero_tag
            ORDER BY approved ASC, last_seen_at DESC, tag ASC
            """
        )
        rows = cursor.fetchall()
        return [
            (row["tag"], bool(row["approved"]), row["last_seen_at"] or "")
            for row in rows
        ]

    def set_zotero_tag_approved(self, tag: str, approved: bool) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE zotero_tag SET approved = ? WHERE tag = ?",
                (1 if approved else 0, tag),
            )
            self._commit()

    def get_zotero_approved_tags(self) -> list[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT tag FROM zotero_tag WHERE approved = 1")
        rows = cursor.fetchall()
        return [row["tag"] for row in rows]

    def upsert_readwise_tag(self, tag: str, approved: bool) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO readwise_tag(tag, approved, last_seen_at)
                VALUES(?, ?, ?)
                ON CONFLICT(tag) DO UPDATE SET
                    last_seen_at=excluded.last_seen_at
                """,
                (tag, 1 if approved else 0, datetime.now(timezone.utc).isoformat()),
            )
            self._commit()

    def list_readwise_tags(self) -> list[tuple[str, bool, str]]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT tag, approved, last_seen_at
            FROM readwise_tag
            ORDER BY approved ASC, last_seen_at DESC, tag ASC
            """
        )
        rows = cursor.fetchall()
        return [
            (row["tag"], bool(row["approved"]), row["last_seen_at"] or "")
            for row in rows
        ]

    def set_readwise_tag_approved(self, tag: str, approved: bool) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE readwise_tag SET approved = ? WHERE tag = ?",
                (1 if approved else 0, tag),
            )
            self._commit()

    def get_readwise_approved_tags(self) -> list[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT tag FROM readwise_tag WHERE approved = 1")
        rows = cursor.fetchall()
        return [row["tag"] for row in rows]

    def upsert_zotero_collection(
        self, collection_id: str, name: str, approved: bool, parent_id: str | None
    ) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT INTO zotero_collection(collection_id, name, parent_id, approved, last_seen_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(collection_id) DO UPDATE SET
                    name=excluded.name,
                    parent_id=excluded.parent_id,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    collection_id,
                    name,
                    parent_id,
                    1 if approved else 0,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._commit()

    def list_zotero_collections(self) -> list[tuple[str, str, bool, str]]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT collection_id, name, approved, last_seen_at
            FROM zotero_collection
            ORDER BY approved ASC, last_seen_at DESC, name ASC
            """
        )
        rows = cursor.fetchall()
        return [
            (
                row["collection_id"],
                row["name"],
                bool(row["approved"]),
                row["last_seen_at"] or "",
            )
            for row in rows
        ]

    def list_zotero_collections_with_parent(
        self,
    ) -> list[tuple[str, str, str | None, bool, str]]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT collection_id, name, parent_id, approved, last_seen_at
            FROM zotero_collection
            ORDER BY approved ASC, last_seen_at DESC, name ASC
            """
        )
        rows = cursor.fetchall()
        return [
            (
                row["collection_id"],
                row["name"],
                row["parent_id"],
                bool(row["approved"]),
                row["last_seen_at"] or "",
            )
            for row in rows
        ]

    def _zotero_parent_map(self) -> dict[str, str]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT collection_id, parent_id
            FROM zotero_collection
            WHERE parent_id IS NOT NULL AND parent_id != ''
            """
        )
        rows = cursor.fetchall()
        return {row["collection_id"]: row["parent_id"] for row in rows}

    def approve_zotero_collection_with_children(self, collection_id: str) -> None:
        if not collection_id:
            return
        parent_map = self._zotero_parent_map()
        children_map: dict[str, list[str]] = {}
        for child_id, parent_id in parent_map.items():
            children_map.setdefault(parent_id, []).append(child_id)
        to_visit = [collection_id]
        approved = set()
        while to_visit:
            current = to_visit.pop()
            if current in approved:
                continue
            approved.add(current)
            for child in children_map.get(current, []):
                if child not in approved:
                    to_visit.append(child)
        if not approved:
            return
        with self._lock:
            cursor = self.conn.cursor()
            cursor.executemany(
                "UPDATE zotero_collection SET approved = 1 WHERE collection_id = ?",
                [(cid,) for cid in approved],
            )
            self._commit()

    def set_zotero_collection_approved(
        self, collection_id: str, approved: bool
    ) -> None:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE zotero_collection SET approved = ? WHERE collection_id = ?",
                (1 if approved else 0, collection_id),
            )
            self._commit()

    def get_zotero_approved_collections(self) -> list[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT collection_id FROM zotero_collection WHERE approved = 1")
        rows = cursor.fetchall()
        return [row["collection_id"] for row in rows]
