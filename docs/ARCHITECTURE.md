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

Each connector:
- keeps its own cursor (state) in a persistent volume (SQLite or JSON file)
- fetches new/updated items since last cursor
- extracts content (HTML/PDF text where possible)
- extracts observables (IOCs) and CVEs
- creates STIX objects and relationships in OpenCTI:
  - Report (or Note) for the item
  - External Reference (URL) to original source
  - Observables (Domain-Name, Url, IPv4-Addr, File hash, etc.)
  - Vulnerability object for CVEs
  - Optional: Indicator objects later (not MVP)

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
1) Connector pulls new items -> normalize -> enrich -> push to OpenCTI.
2) Briefing service queries OpenCTI -> builds daily briefing -> publishes RSS/HTML -> stores artifacts.
3) Reports (weekly/monthly/quarterly/yearly) are generated from stored briefing artifacts + OpenCTI aggregates.

## MVP constraints
- Keep connector logic deterministic and idempotent:
  - stable external_id per item
  - dedup by source_item_id and content hash
- Avoid over-creating entities early:
  - Create "Report" + "ExternalReference" + CVE + Observables
  - ATT&CK linking is Phase 2 (after ingestion is stable)
