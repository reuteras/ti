import re
from dataclasses import dataclass
from typing import Iterable

_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "are",
    "was",
    "were",
    "has",
    "have",
    "had",
    "not",
    "but",
    "you",
    "your",
    "into",
    "over",
    "under",
    "after",
    "before",
    "new",
    "update",
    "security",
    "vulnerability",
}


@dataclass
class ReportCandidate:
    report_id: str
    title: str
    confidence: int | None
    external_refs: list[dict]
    tokens: set[str]


def _tokenize(text: str) -> set[str]:
    parts = re.split(r"[^a-zA-Z0-9]+", text.lower())
    tokens = {p for p in parts if len(p) >= 3 and p not in _STOPWORDS}
    return tokens


def prepare_candidates(reports: Iterable[dict]) -> list[ReportCandidate]:
    candidates: list[ReportCandidate] = []
    for report in reports:
        title = report.get("name") or ""
        tokens = _tokenize(title)
        refs = report.get("externalReferences", {}).get("edges", [])
        external_refs = [edge.get("node", {}) for edge in refs]
        candidates.append(
            ReportCandidate(
                report_id=report.get("id", ""),
                title=title,
                confidence=report.get("confidence"),
                external_refs=external_refs,
                tokens=tokens,
            )
        )
    return candidates


def similarity(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    overlap = len(a & b)
    union = len(a | b)
    return overlap / union if union else 0.0


def find_best_match(title: str, candidates: list[ReportCandidate], threshold: float) -> ReportCandidate | None:
    tokens = _tokenize(title)
    best = None
    best_score = 0.0
    for candidate in candidates:
        score = similarity(tokens, candidate.tokens)
        if score >= threshold and score > best_score:
            best = candidate
            best_score = score
    return best
