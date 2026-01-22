# Architecture (OpenCTI-first)

## Overview
We use OpenCTI as the central CTI knowledge base (graph + STIX 2.1 + ATT&CK dataset). We implement:
1) Source connectors (Miniflux, Readwise, Zotero) that ingest items incrementally and push as STIX objects into OpenCTI.
2) A briefing web service that queries OpenCTI and outputs daily briefings as HTML + RSS/Atom, storing briefing artifacts.
3) A watchlist subsystem that tracks "named items" (CVE IDs, campaigns, malware names) and triggers extra monitoring.

## Components
### 1. OpenCTI stack
- opencti
- elasticsearch (OpenCTI dependency)
- redis (OpenCTI dependency)
- rabbitmq (OpenCTI dependency)
- postgresql (OpenCTI dependency)

### 2. Connectors (custom)
- connector-miniflux
- connector-readwise
- connector-zotero
- connector-enrich-text

Each import connector:
- keeps its own cursor (state) in a persistent volume
- fetches new/updated items since last cursor
- normalizes identifiers (URL/DOI/external IDs) and resolves canonical Reports via the mapping store
- creates Reports + External References + Notes for highlights/annotations
- defers CVE/IOC extraction to the enrichment connector

The enrichment connector:
- reads recent Reports/Notes
- extracts CVEs/IOCs and creates relationships

### 3. Briefing service (custom)
- A FastAPI service that:
  - queries OpenCTI GraphQL for items "created since last run"
  - groups/cluster lightly (MVP: by shared CVE + title similarity + source URL host)
  - produces briefing artifacts (JSON + HTML + RSS/Atom)
  - persists its own state in a local SQLite volume

### 4. Watchlist (custom, inside briefing service or separate worker)
- Watch items: {type, value, aliases, query rules, escalation behavior}
- On schedule, queries OpenCTI for matches (new CVE sightings, campaign-name mentions)
- Optional: web searches for watch items (feature-flagged, off by default)
- Produces "watch alerts" included in daily briefings

## Data flow
1) Import connector pulls new items -> normalize -> push to OpenCTI.
2) Enrichment connector scans new Reports/Notes -> adds CVEs/IOCs.
3) Briefing service queries OpenCTI -> builds daily briefing -> publishes RSS/HTML -> stores artifacts.
4) Reports (weekly/monthly/quarterly/yearly) are generated from stored briefing artifacts + OpenCTI aggregates.

## MVP constraints
- Keep connector logic deterministic and idempotent:
  - stable external_id per item
  - dedup by source_item_id and content hash
- Avoid over-creating entities early:
  - Import connectors create Report + ExternalReference + Notes
  - Enrichment connector handles CVEs/Observables
  - ATT&CK linking is Phase 2 (after ingestion is stable)
