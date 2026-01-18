import logging
import os
from dataclasses import dataclass

import httpx

from .storage import Storage

logger = logging.getLogger(__name__)


@dataclass
class ZoteroTag:
    tag: str


@dataclass
class ZoteroCollection:
    collection_id: str
    name: str


def _base_url() -> tuple[str, str, str] | None:
    api_key = os.getenv("ZOTERO_API_KEY", "")
    library_id = os.getenv("ZOTERO_LIBRARY_ID", "")
    library_type = os.getenv("ZOTERO_LIBRARY_TYPE", "user")
    if not api_key or not library_id:
        logger.warning("zotero_not_configured")
        return None
    base_url = f"https://api.zotero.org/{library_type}s/{library_id}"
    return base_url, api_key, library_type


def _client(api_key: str) -> httpx.Client:
    headers = {"Zotero-API-Key": api_key}
    return httpx.Client(timeout=30, headers=headers)


def refresh_tags(storage: Storage, limit: int = 100) -> int:
    base = _base_url()
    if not base:
        return 0
    base_url, api_key, _ = base
    offset = 0
    count = 0
    while True:
        url = f"{base_url}/tags"
        params = {"limit": limit, "start": offset}
        with _client(api_key) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            payload = response.json()
        if not payload:
            break
        for item in payload:
            tag = item.get("tag")
            if isinstance(tag, str) and tag.strip():
                storage.upsert_zotero_tag(tag.strip(), approved=False)
                count += 1
        offset += limit
    return count


def refresh_collections(storage: Storage, limit: int = 100) -> int:
    base = _base_url()
    if not base:
        return 0
    base_url, api_key, _ = base
    offset = 0
    count = 0
    while True:
        url = f"{base_url}/collections"
        params = {"limit": limit, "start": offset}
        with _client(api_key) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            payload = response.json()
        if not payload:
            break
        for item in payload:
            collection_id = item.get("key") or ""
            name = item.get("data", {}).get("name") or ""
            if collection_id and name:
                storage.upsert_zotero_collection(collection_id, name, approved=False)
                count += 1
        offset += limit
    return count
