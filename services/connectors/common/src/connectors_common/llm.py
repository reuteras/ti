import json
import os
import textwrap

import httpx

from connectors_common.denylist import filter_values


def summarize_text(text: str) -> str | None:
    enabled = os.getenv("ENRICHMENT_LLM_ENABLED", "false").lower() == "true"
    if not enabled:
        return None
    endpoint = os.getenv("ENRICHMENT_LLM_ENDPOINT", "http://host.docker.internal:11434/api/generate")
    model = os.getenv("ENRICHMENT_LLM_MODEL", "llama3.1:8b")
    prompt = textwrap.dedent(
        f"""
        Summarize the following in 2-3 bullet points.
        - Use "-" bullet prefixes.
        - Plain text only, no extra markup or headings.
        - Keep it factual and concise.

        {text}
        """
    ).strip()
    payload = {"model": model, "prompt": prompt, "stream": False}
    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(endpoint, json=payload)
            response.raise_for_status()
            body = response.json()
    except Exception:
        return None
    summary = body.get("response", "").strip()
    if not summary:
        return None
    return summary[:1500]


def extract_entities(text: str, max_chars: int = 4000) -> dict[str, list[str]]:
    enabled = os.getenv("ENRICHMENT_LLM_ENABLED", "false").lower() == "true"
    if not enabled:
        return {"persons": [], "organizations": [], "products": [], "countries": []}
    value = (text or "").strip()
    if not value:
        return {"persons": [], "organizations": [], "products": [], "countries": []}
    if len(value) > max_chars:
        value = value[:max_chars]
    endpoint = os.getenv("ENRICHMENT_LLM_ENDPOINT", "http://host.docker.internal:11434/api/generate")
    model = os.getenv("ENRICHMENT_LLM_MODEL", "llama3.1:8b")
    prompt = textwrap.dedent(
        f"""
        Extract named entities from the text. Return strict JSON only with arrays:
        {{"persons":[],"organizations":[],"products":[],"countries":[]}}

        Rules:
        - Only include entities explicitly mentioned in the text.
        - Persons should include full names when possible (first+last).
        - Use canonical country names (e.g., US/USA/U.S. => United States).
        - Products include software and technologies (e.g., Adobe ColdFusion).
        - Do not include cities.
        - No code fences or extra keys.

        Text:
        {value}
        """
    ).strip()
    payload = {"model": model, "prompt": prompt, "stream": False}
    try:
        with httpx.Client(timeout=60) as client:
            response = client.post(endpoint, json=payload)
            response.raise_for_status()
            body = response.json()
    except Exception:
        return {"persons": [], "organizations": [], "products": [], "countries": []}
    raw = (body.get("response") or "").strip()
    if not raw:
        return {"persons": [], "organizations": [], "products": [], "countries": []}
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {"persons": [], "organizations": [], "products": [], "countries": []}
    try:
        data = json.loads(raw[start : end + 1])
    except Exception:
        return {"persons": [], "organizations": [], "products": [], "countries": []}
    result: dict[str, list[str]] = {}
    for key in ("persons", "organizations", "products", "countries"):
        values = data.get(key, [])
        if isinstance(values, list):
            cleaned = [str(item).strip() for item in values if str(item).strip()]
            filtered = filter_values(cleaned, key)
            result[key] = sorted(set(filtered))
        else:
            result[key] = []
    return result
