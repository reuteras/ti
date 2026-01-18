import os
import re
from typing import Iterable


def _parse_label_rules(raw: str) -> list[tuple[re.Pattern[str], str]]:
    rules: list[tuple[re.Pattern[str], str]] = []
    for chunk in raw.split(";"):
        if not chunk.strip() or "=" not in chunk:
            continue
        pattern, label = chunk.split("=", 1)
        try:
            rules.append((re.compile(pattern, re.IGNORECASE), label.strip()))
        except re.error:
            continue
    return rules


def apply_label_rules(text: str) -> list[str]:
    raw = os.getenv("ENRICHMENT_LABEL_RULES", "")
    if not raw:
        return []
    labels = []
    for pattern, label in _parse_label_rules(raw):
        if pattern.search(text or ""):
            labels.append(label)
    return labels


def source_confidence(source_name: str) -> int | None:
    raw = os.getenv("SOURCE_CONFIDENCE_MAP", "")
    for chunk in raw.split(","):
        if not chunk.strip() or "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        if name.strip().lower() == source_name.lower():
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def source_labels(source_name: str) -> list[str]:
    raw = os.getenv("SOURCE_LABELS_MAP", "")
    for chunk in raw.split(","):
        if not chunk.strip() or "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        if name.strip().lower() == source_name.lower():
            return [label.strip() for label in value.split("|") if label.strip()]
    return []
