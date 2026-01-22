from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

from connectors_common.mapping_store import MappingStore
from connectors_common.url_utils import canonicalize_url, normalize_doi, url_hash


@dataclass
class CandidateIdentity:
    doi: str | None = None
    urls: list[str] | None = None
    external_ids: list[tuple[str, str]] | None = None
    content_fp: str | None = None
    title: str | None = None
    published: str | None = None

    def iter_urls(self) -> Iterable[str]:
        for url in self.urls or []:
            if url:
                yield url

    def iter_external_ids(self) -> Iterable[tuple[str, str]]:
        for source, external_id in self.external_ids or []:
            if source and external_id:
                yield source, external_id


def _title_fingerprint(title: str | None, published: str | None) -> str:
    if not title:
        return ""
    normalized = " ".join(title.strip().lower().split())
    published_key = (published or "").strip()
    raw = f"{normalized}|{published_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def resolve_canonical_id(
    mapping: MappingStore,
    candidate: CandidateIdentity,
    allow_title_fallback: bool = False,
) -> tuple[str | None, str | None]:
    doi = normalize_doi(candidate.doi or "")
    if doi:
        existing = mapping.get_by_doi(doi)
        if existing:
            return existing, "doi"

    for url in candidate.iter_urls():
        canonical = canonicalize_url(url)
        digest = url_hash(canonical)
        if not digest:
            continue
        existing = mapping.get_by_url_hash(digest)
        if existing:
            return existing, "url"

    for source, external_id in candidate.iter_external_ids():
        existing = mapping.get_by_external_id(source, external_id)
        if existing:
            return existing, "external_id"

    if candidate.content_fp:
        existing = mapping.get_by_content_fp(candidate.content_fp)
        if existing:
            return existing, "content_fp"

    if allow_title_fallback:
        title_fp = _title_fingerprint(candidate.title, candidate.published)
        if title_fp:
            existing = mapping.get_by_title_fp(title_fp)
            if existing:
                return existing, "title_published"

    return None, None


def store_identity_mappings(
    mapping: MappingStore,
    opencti_id: str,
    obj_type: str,
    candidate: CandidateIdentity,
) -> None:
    if candidate.doi:
        doi = normalize_doi(candidate.doi)
        if doi:
            mapping.upsert_doi(doi, opencti_id, obj_type)
    for url in candidate.iter_urls():
        canonical = canonicalize_url(url)
        digest = url_hash(canonical)
        if digest:
            mapping.upsert_url(digest, canonical, opencti_id, obj_type)
    for source, external_id in candidate.iter_external_ids():
        mapping.upsert_external_id(source, external_id, opencti_id, obj_type)
    if candidate.content_fp:
        mapping.upsert_content_fp(candidate.content_fp, opencti_id, obj_type)
    title_fp = _title_fingerprint(candidate.title, candidate.published)
    if title_fp:
        mapping.upsert_title_fp(title_fp, opencti_id, obj_type)
