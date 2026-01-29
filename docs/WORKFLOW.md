# OpenCTI Ingestion Workflow: Readwise + Zotero + RSS/Miniflux → Canonical Objects + Evidence + Relationship Stitching

Repo: [https://github.com/reuteras/ti](https://github.com/reuteras/ti)

Goal: “I saved/highlighted something anywhere → it lands in OpenCTI once, with strong provenance, and links across sources.”
Sources include (but are not limited to): Readwise Reader links, web articles, PDFs, podcasts, and Zotero library items (PDFs + metadata + highlights). Podcasts are just one content type; the workflow must be source-agnostic.

This document is written for Codex to implement in the repo.

---

## Principles

### 1) Canonical object vs. evidence/mentions
Treat each real-world item as one canonical OpenCTI entity. Everything else becomes evidence, provenance, or relationships.

- Canonical items:
  - Web article / blog post / advisory → `Report` (or `Note`/`ExternalReference`-only depending on strategy)
  - PDF / paper / whitepaper (often from Zotero) → `Report` (container) + `ExternalReference` to DOI/URL (if any)
  - Podcast episode → `Report` (container) (optional; only when present)

- Evidence:
  - Highlights (Readwise, Zotero) → `Note` objects attached to the canonical item
  - Your comments/annotations → `Note` (or `Opinion` if you want assessment semantics)
  - Extracted IOCs/CVEs/entities → dedicated OpenCTI entities linked back to the evidence `Note` and container `Report`

### 2) Dedup by stable keys (URLs/DOIs/IDs), not titles
Titles change; stable identifiers don’t.
Primary stable keys, in priority order, per item:
- DOI (for papers)
- Canonical URL (for web content)
- Zotero item key (for library items)
- Readwise document id (for Reader documents)
- RSS GUID (for feed items)
- Podcast episode GUID/show-page URL (when relevant)

### 3) Separate ingestion from enrichment
- Import connectors: deterministic upserts + attach evidence + basic relationships
- Enrichment connectors: entity extraction/IOC parsing/ATT&CK mapping

---

## High-level architecture

Implement a shared library in the repo and multiple connectors that all use it:

```text
ti/
├── connectors/
│   ├── import_readwise/
│   │   ├── README.md
│   │   ├── connector.py
│   │   └── config.yml
│   ├── import_zotero/
│   │   ├── README.md
│   │   ├── connector.py
│   │   └── config.yml
│   ├── import_miniflux/
│   │   ├── README.md
│   │   ├── connector.py
│   │   └── config.yml
│   └── enrich_text/
│       ├── README.md
│       ├── connector.py
│       └── config.yml
├── lib/
│   ├── init.py
│   ├── urlnorm.py
│   ├── fingerprint.py
│   ├── mapping_store.py
│   ├── identity.py
│   ├── stix_builders.py
│   ├── opencti_client.py
│   └── extractors/
│       ├── init.py
│       ├── iocs.py
│       ├── cve.py
│       └── entities.py
└── tests/
├── test_urlnorm.py
├── test_mapping_store.py
├── test_fingerprint.py
├── test_identity.py
└── test_dedup_logic.py
```

All connectors MUST:
1. Normalize identifiers (URLs/DOI/etc.)
2. Resolve/create canonical OpenCTI entity id via mapping store
3. Attach external references + provenance labels
4. Create `Note` evidence for highlights/annotations
5. Defer entity extraction to `enrich_text`

---

## Core “fixers” (shared across connectors)

### A) URL normalization fixer (critical)
`ti/lib/urlnorm.py`

Functions:
- `canonicalize_url(url: str) -> str`
  - lowercase scheme/host
  - remove default ports
  - strip trailing slash (except root)
  - remove trackers (`utm_*`, `fbclid`, `gclid`, `mc_cid`, `mc_eid`, etc.)
  - normalize query param order
- `url_hash(url: str) -> str` → sha256 hex of canonical url

Used for:
- dedup across Readwise ↔ Miniflux ↔ Zotero “URL” field ↔ show notes links ↔ anywhere

### B) Content fingerprint fixer
`ti/lib/fingerprint.py`

- `normalize_text(text: str) -> str` (unicode normalization + whitespace collapse)
- `content_fingerprint(text: str, max_chars=8000) -> str` (sha256 of normalized prefix)

Used for:
- detecting duplicates when URLs differ but content is identical/near-identical
- protecting against re-import duplication

### C) Mapping store (“relationship stitching glue”)
`ti/lib/mapping_store.py` using SQLite.

Tables:
- `url_map(url_hash TEXT PRIMARY KEY, canonical_url TEXT, opencti_id TEXT, type TEXT, updated_at TEXT)`
- `external_id_map(source TEXT, external_id TEXT, opencti_id TEXT, type TEXT, updated_at TEXT, PRIMARY KEY(source, external_id))`
- `doi_map(doi TEXT PRIMARY KEY, opencti_id TEXT, type TEXT, updated_at TEXT)`
- `content_map(content_fp TEXT PRIMARY KEY, opencti_id TEXT, type TEXT, updated_at TEXT)`

Purpose:
- Make upserts deterministic across heterogeneous sources
- Support “same doc seen in Readwise and Zotero” and “same article seen in Readwise and Miniflux”

### D) Identity resolution (source-agnostic)
`ti/lib/identity.py`

Implement:
- `resolve_canonical_id(candidate: CandidateIdentity) -> (opencti_id | None, match_reason)`
- `CandidateIdentity` contains:
  - `doi`
  - `urls[]`
  - `external_ids[]` (e.g., zotero item key, readwise doc id, rss guid)
  - `content_fp` (optional)
  - `title` (fallback only)
  - `published` (fallback only)

Matching precedence:
1. DOI
2. Any URL hash
3. Any (source, external_id)
4. Content fingerprint
5. Fallback heuristic: (normalized title + published date) with low confidence (only if configured)

Store all discovered identifiers back into mapping tables after creation.

---

## OpenCTI object modeling

### Canonical item: use `Report` as the default container
Default canonical representation for “a document-like thing” is an OpenCTI `Report`.

Rationale:
- Works for web pages, advisories, PDFs/papers, blog posts, podcast episodes
- Lets you attach multiple external references and many Notes
- Provides an anchor for relationships (“this report references that report”)

Report minimum fields:
- `name`: title
- `description`: short summary if available
- `published`: datetime if known
- `confidence`: based on source and type

### Evidence: highlights/annotations are `Note`
Each highlight = one `Note` linked to the canonical `Report`.

- For Readwise highlights:
  - `external_id_map(source='readwise_highlight', external_id=<highlight_id>)`
- For Zotero highlights:
  - create a stable external id (e.g., `zotero:<itemKey>:<annotationKey>` if available)

Note content should include:
- excerpt text
- your comment/annotation (if any)
- source attribution + location metadata (page number, location, timestamp) if available

### External references
Attach all relevant references to the canonical Report:
- Canonical URL(s)
- DOI URL (if present)
- Publisher page, PDF direct link, arXiv, etc.
- For podcasts only when applicable: show page / platform links (Apple, Overcast, etc.)

De-dup external references by canonical URL hash.

---

## Connector: import_readwise (general-purpose, not podcast-centric)

### Purpose (Readwise)
Import Readwise Reader documents + highlights for ALL content types:
- web articles (most common)
- PDFs saved into Reader
- podcasts (if present)
- any other Reader docs

### Inputs (Readwise)
- Readwise document metadata (title, source URL, author, tags, created/updated timestamps)
- highlights (id, text, note/comment, location metadata)

### Output (Readwise)
- Canonical `Report` per document
- `Note` per highlight
- External references attached
- Optional: extracted links from the document (see linking strategy)

### Identity & dedup (Readwise)
CandidateIdentity for a Readwise doc:
- `external_ids`: `('readwise_doc', document_id)`
- `urls`: document/source URL(s)
- `content_fp`: optional from document text/summary if accessible
- `title/published`: fallback only

### Behavior
1. For each Readwise doc since last run:
   - Build CandidateIdentity and resolve canonical OpenCTI id
   - Create/update `Report` (upsert)
   - Store mappings:
     - readwise_doc id → report id
     - url hashes → report id (for all URLs)
     - content_fp (optional) → report id

2. For each highlight:
   - Upsert `Note` keyed by highlight_id
   - Link Note → Report

3. Optional: link extraction from Readwise doc content/notes
   - Extract URLs present in the doc body/highlight notes
   - Normalize URLs and attempt to resolve to existing OpenCTI entities
   - If found: create relationship (container Report → referenced entity)
   - If not found: apply link strategy (below)

Configuration:
- `TI_LINK_STRATEGY=report|reference_only|none`
  - `report`: create minimal referenced `Report` objects for unknown links
  - `reference_only`: attach links as external references to the container only
  - `none`: ignore extracted links at import time

---

## Connector: import_zotero (PDF-centric, metadata-rich)

### Purpose (Zotero)
Import Zotero library items (PDFs/papers/reports/articles) with rich metadata + annotations/highlights.

### Inputs (Zotero)
Zotero item data:
- item key (stable)
- title
- creators/authors
- date
- DOI, ISBN, URL
- publication / journal
- attachments (PDF file path or link)
- annotations/highlights (text, comment, page, position, annotation key if available)

### Output (Zotero)
- Canonical `Report` per Zotero item
- `Note` per annotation/highlight
- External references:
  - DOI (preferred)
  - URL (publisher page)
  - local file reference only if your OpenCTI deployment supports attachments safely (optional and configurable)

### Identity & dedup (Zotero)
CandidateIdentity for a Zotero item:
- `external_ids`: `('zotero_item', item_key)`
- `doi` if present (highest priority)
- `urls` from Zotero URL field and DOI resolver URL
- `content_fp`: optional if you can extract text (not required initially)

### Author handling
Authors should be preserved in the Report description or as structured custom fields (depending on OpenCTI schema/usage in your instance).
Minimum:
- Include authors in `description` as a formatted line, or attach as labels (not ideal).
Better:
- Store in custom fields or as linked `Identity` entities if your OpenCTI model supports it cleanly.

### Annotation handling
- Upsert notes based on a stable Zotero annotation key if possible:
  - `external_id_map(source='zotero_annot', external_id=<annotation_key>)`
- If no annotation key exists, derive a stable hash:
  - `sha256(item_key + page + normalized_excerpt[:N])`

---

## Connector: import_miniflux (optional here)
If you already ingest RSS/Miniflux to OpenCTI, ensure it uses the same identity library:
- URL normalization + url_hash mapping must match `import_readwise`
- RSS GUID can be stored in `external_id_map(source='rss_guid', external_id=<guid>)`

This is how “Readwise link” and “RSS item” become the same canonical Report.

---

## Connector: enrich_text (unified enrichment)
Runs after imports. Input is new/updated Reports and Notes from ALL sources.

### What it does
- Extract CVEs: `CVE-\d{4}-\d{4,7}`
- Extract IOCs: IPs/domains/URLs/hashes
- Optional dictionary/entity extraction for malware/actors/orgs
- Create relationships back to:
  - the evidence Note (strongest provenance)
  - and the container Report

Confidence rules (suggested):
- Explicit CVE string: higher confidence
- IOC parsed from excerpt: medium confidence
- Named entity fuzzy matches: low confidence unless curated list hit

---

## Relationship stitching rules

### 1) Link extracted URLs to existing entities whenever possible
When a connector extracts a URL (from Readwise doc, Zotero note, etc.):
- Normalize → url_hash
- If url_hash exists in mapping store → link to that OpenCTI entity
- Else apply `TI_LINK_STRATEGY`

### 2) Avoid external-reference spam
- External references must be unique by canonical URL hash
- Keep references meaningful:
  - publisher page
  - DOI URL
  - canonical content URL
  - platform links (only when they add value)

### 3) Cross-source convergence
When Zotero item has DOI and Readwise has the publisher URL:
- DOI match should unify them automatically (DOI first)
- Then store the URL hashes onto the same canonical Report

---

## Configuration (env vars)

Required for each connector:
- `OPENCTI_URL=...`
- `OPENCTI_TOKEN=...`
- `TI_MAPPING_DB=/data/ti-mapping.sqlite`

Readwise:
- `READWISE_API_KEY=...`
- `TI_READWISE_LOOKBACK_DAYS=14`

Zotero:
- `ZOTERO_API_KEY=...`
- `ZOTERO_LIBRARY_TYPE=user|group`
- `ZOTERO_LIBRARY_ID=...`
- `TI_ZOTERO_LOOKBACK_DAYS=30`

Linking:
- `TI_LINK_STRATEGY=report|reference_only|none`
- `TI_CONFIDENCE_IMPORT=50`

---

## Testing requirements (pytest)

- URL normalization equivalence
- DOI normalization (case/format)
- Mapping store upsert/reuse
- Identity resolver precedence tests:
  - DOI beats URL
  - URL beats external_id
  - external_id beats content_fp
- Connector-level tests (mock OpenCTI):
  - Readwise doc imported twice does not duplicate
  - Zotero annotations imported twice do not duplicate
  - Same item seen via Zotero (DOI) and Readwise (URL) converges to one Report

---

## Milestones

### M1: Shared core
- urlnorm + fingerprint + mapping_store + identity resolver
- tests

### M2: import_readwise (general content)
- documents → Reports
- highlights → Notes
- link extraction optional via `TI_LINK_STRATEGY`

### M3: import_zotero
- items → Reports
- annotations → Notes
- DOI/author metadata preserved

### M4: enrich_text
- CVE/IOC extraction + relationships

### M5: Stitching polish
- better link extraction
- stronger convergence heuristics (content_fp optional)

---

## Acceptance criteria

- Same web article saved in Readwise and later seen via RSS results in **one** OpenCTI Report with multiple external references.
- Same PDF/paper in Zotero (DOI) and Readwise (publisher URL) converges to **one** Report.
- Highlights/annotations become Notes; re-import updates rather than duplicates.
- Extracted CVEs/IOCs are created and linked back to evidence Notes and container Reports.
