import logging
import os
import re
import time

import httpx

logger = logging.getLogger(__name__)

_CACHE: dict[str, object] = {"expires_at": 0.0, "data": {}}


def _normalize(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _default_payload() -> dict[str, set[str]]:
    return {
        "all": set(),
        "persons": set(),
        "organizations": set(),
        "products": set(),
        "countries": set(),
        "authors": set(),
        "patterns": [],
    }


def _parse_payload(payload: object) -> dict[str, set[str]]:
    data = _default_payload()
    if isinstance(payload, list):
        data["all"] = {_normalize(str(item)) for item in payload if str(item).strip()}
        return data
    if isinstance(payload, dict):
        for key, value in payload.items():
            if not isinstance(value, list):
                continue
            key_norm = _normalize(str(key))
            if key_norm not in data:
                continue
            if key_norm == "patterns":
                patterns = []
                for item in value:
                    pattern = str(item).strip()
                    if not pattern:
                        continue
                    try:
                        patterns.append(re.compile(pattern, re.IGNORECASE))
                    except re.error as exc:
                        logger.warning(
                            "denylist_pattern_invalid pattern=%s error=%s", pattern, exc
                        )
                data[key_norm] = patterns
            else:
                data[key_norm] = {
                    _normalize(str(item)) for item in value if str(item).strip()
                }
    return data


def _fetch_payload(url: str) -> object:
    with httpx.Client(timeout=5) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.json()


def get_denylist() -> dict[str, set[str]]:
    ttl = int(os.getenv("DENYLIST_TTL_SECONDS", "300"))
    now = time.time()
    if now < float(_CACHE.get("expires_at", 0)):
        cached = _CACHE.get("data", {})
        if isinstance(cached, dict):
            return cached
    url = os.getenv("DENYLIST_URL", "http://briefing:8088/denylist.json")
    try:
        payload = _fetch_payload(url)
        data = _parse_payload(payload)
        _CACHE["data"] = data
        _CACHE["expires_at"] = now + ttl
        return data
    except Exception as exc:
        logger.warning("denylist_fetch_failed url=%s error=%s", url, exc)
        data = _default_payload()
        _CACHE["data"] = data
        _CACHE["expires_at"] = now + ttl
        return data


def is_denied(value: str, category: str) -> bool:
    if not value:
        return False
    data = get_denylist()
    patterns = data.get("patterns", [])
    for pattern in patterns:
        try:
            if pattern.search(value):
                return True
        except Exception:
            continue
    normalized = _normalize(value)
    if not normalized:
        return False
    if normalized in data.get("all", set()):
        return True
    category_key = _normalize(category or "")
    if normalized in data.get(category_key, set()):
        return True
    if category_key == "persons" and normalized in data.get("authors", set()):
        return True
    return False


def filter_values(values: list[str], category: str) -> list[str]:
    return [value for value in values if value and not is_denied(value, category)]
