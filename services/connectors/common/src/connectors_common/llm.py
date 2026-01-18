import os
import textwrap

import httpx


def summarize_text(text: str) -> str | None:
    enabled = os.getenv("ENRICHMENT_LLM_ENABLED", "false").lower() == "true"
    if not enabled:
        return None
    endpoint = os.getenv("ENRICHMENT_LLM_ENDPOINT", "http://host.docker.internal:11434/api/generate")
    model = os.getenv("ENRICHMENT_LLM_MODEL", "llama3.1")
    prompt = textwrap.dedent(
        f"""
        Summarize the following in 2-3 bullet points. Keep it factual.

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
