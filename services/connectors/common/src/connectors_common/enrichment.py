import os


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
