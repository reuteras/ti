from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator


class MappingStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self._ensure_db()

    def _ensure_db(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS url_map (
                    url_hash TEXT PRIMARY KEY,
                    canonical_url TEXT,
                    opencti_id TEXT,
                    type TEXT,
                    updated_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS external_id_map (
                    source TEXT,
                    external_id TEXT,
                    opencti_id TEXT,
                    type TEXT,
                    updated_at TEXT,
                    PRIMARY KEY (source, external_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS doi_map (
                    doi TEXT PRIMARY KEY,
                    opencti_id TEXT,
                    type TEXT,
                    updated_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS content_map (
                    content_fp TEXT PRIMARY KEY,
                    opencti_id TEXT,
                    type TEXT,
                    updated_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS title_map (
                    title_fp TEXT PRIMARY KEY,
                    opencti_id TEXT,
                    type TEXT,
                    updated_at TEXT
                )
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def get_by_url_hash(self, url_hash: str) -> str | None:
        if not url_hash:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT opencti_id FROM url_map WHERE url_hash = ?",
                (url_hash,),
            ).fetchone()
        return row[0] if row else None

    def upsert_url(self, url_hash: str, canonical_url: str, opencti_id: str, obj_type: str) -> None:
        if not url_hash or not opencti_id:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO url_map (url_hash, canonical_url, opencti_id, type, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(url_hash)
                DO UPDATE SET canonical_url=excluded.canonical_url,
                              opencti_id=excluded.opencti_id,
                              type=excluded.type,
                              updated_at=excluded.updated_at
                """,
                (url_hash, canonical_url, opencti_id, obj_type, self._now()),
            )

    def get_by_external_id(self, source: str, external_id: str) -> str | None:
        if not source or not external_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT opencti_id FROM external_id_map WHERE source = ? AND external_id = ?",
                (source, external_id),
            ).fetchone()
        return row[0] if row else None

    def upsert_external_id(self, source: str, external_id: str, opencti_id: str, obj_type: str) -> None:
        if not source or not external_id or not opencti_id:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO external_id_map (source, external_id, opencti_id, type, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source, external_id)
                DO UPDATE SET opencti_id=excluded.opencti_id,
                              type=excluded.type,
                              updated_at=excluded.updated_at
                """,
                (source, external_id, opencti_id, obj_type, self._now()),
            )

    def list_external_ids_by_source(self, source: str) -> list[tuple[str, str, str]]:
        if not source:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT external_id, opencti_id, type FROM external_id_map WHERE source = ?",
                (source,),
            ).fetchall()
        return [(row[0], row[1], row[2]) for row in rows]

    def delete_external_id(self, source: str, external_id: str) -> None:
        if not source or not external_id:
            return
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM external_id_map WHERE source = ? AND external_id = ?",
                (source, external_id),
            )

    def get_by_doi(self, doi: str) -> str | None:
        if not doi:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT opencti_id FROM doi_map WHERE doi = ?",
                (doi,),
            ).fetchone()
        return row[0] if row else None

    def upsert_doi(self, doi: str, opencti_id: str, obj_type: str) -> None:
        if not doi or not opencti_id:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO doi_map (doi, opencti_id, type, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(doi)
                DO UPDATE SET opencti_id=excluded.opencti_id,
                              type=excluded.type,
                              updated_at=excluded.updated_at
                """,
                (doi, opencti_id, obj_type, self._now()),
            )

    def get_by_content_fp(self, content_fp: str) -> str | None:
        if not content_fp:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT opencti_id FROM content_map WHERE content_fp = ?",
                (content_fp,),
            ).fetchone()
        return row[0] if row else None

    def upsert_content_fp(self, content_fp: str, opencti_id: str, obj_type: str) -> None:
        if not content_fp or not opencti_id:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO content_map (content_fp, opencti_id, type, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(content_fp)
                DO UPDATE SET opencti_id=excluded.opencti_id,
                              type=excluded.type,
                              updated_at=excluded.updated_at
                """,
                (content_fp, opencti_id, obj_type, self._now()),
            )

    def get_by_title_fp(self, title_fp: str) -> str | None:
        if not title_fp:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT opencti_id FROM title_map WHERE title_fp = ?",
                (title_fp,),
            ).fetchone()
        return row[0] if row else None

    def upsert_title_fp(self, title_fp: str, opencti_id: str, obj_type: str) -> None:
        if not title_fp or not opencti_id:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO title_map (title_fp, opencti_id, type, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(title_fp)
                DO UPDATE SET opencti_id=excluded.opencti_id,
                              type=excluded.type,
                              updated_at=excluded.updated_at
                """,
                (title_fp, opencti_id, obj_type, self._now()),
            )
