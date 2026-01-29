# Connectors

## Connector contract
Each connector is a Python service with:
- periodic loop (e.g., every 10 minutes) OR a simple "run once" with docker restart policy
- persistent cursor state stored in a volume
- idempotent ingestion (safe to re-run)

### Common environment variables
- OPENCTI_URL
- OPENCTI_ADMIN_TOKEN (or a dedicated connector token later)
- CONNECTOR_NAME
- CONNECTOR_SCOPE (e.g., "miniflux", "readwise", "zotero")
- CONNECTOR_RUN_INTERVAL_SECONDS
- TI_MAPPING_DB (shared mapping SQLite path)
- TI_ALLOW_TITLE_FALLBACK (enable title+published fallback)
- TI_CONFIDENCE_IMPORT (default confidence when source map missing)

### Common internal modules
- connectors_common/opencti_client.py: wrapper for OpenCTI GraphQL mutations
- connectors_common/state_store.py: SQLite/JSON cursor store
- connectors_common/url_utils.py: URL normalization + hashing
- connectors_common/fingerprint.py: content fingerprinting
- connectors_common/mapping_store.py: shared SQLite ID mapping
- connectors_common/identity.py: canonical identity resolution

## STIX mapping (MVP)
For each source item:
- Create a STIX Report:
  - name: item title
  - description: short excerpt + connector metadata
  - report_types: ["threat-report"] (or "internal-report")
  - published: item date if known
- Create External Reference:
  - source_name: "miniflux" / "readwise" / "zotero"
  - url: original URL (if any)
- Link Report -> External Reference
- Create Note evidence objects for highlights/annotations
- CVE/IOC extraction is handled by the `connector-enrich-text` service

## External OpenCTI connectors
The stack also runs official OpenCTI connectors for public datasets and enrichment:
- AlienVault OTX
- Abuse.ch SSL Blacklist
- Abuse.ch ThreatFox
- Abuse.ch URLhaus
- CISA KEV (exploited CVEs)
- FIRST EPSS (CVSS exploitability probability)
- MalwareBazaar
- Malpedia
- MISP Feed (CIRCL OSINT)
- OpenCTI Datasets
- RansomwareLive
- VirusTotal
- Shodan InternetDB
- Shodan
- YARA (internal enrichment)

Note: NVD is not used; CVE coverage comes primarily from CISA KEV + OpenCTI Datasets.

## Miniflux connector
### Inputs (Miniflux)
- MINIFLUX_URL
- MINIFLUX_API_KEY

### Incremental strategy (Miniflux)
- Cursor based on miniflux entry IDs and/or "updated_at".
- Store last_run timestamp and last_entry_id per feed (or global).

### Implementation details
- Fetch unread + recently updated entries (configurable)
- Optionally mark entries as "read" after ingestion (feature-flagged, default off)

## Readwise connector
### Inputs (Readwise)
- READWISE_API_KEY

### Incremental strategy (Readwise)
- Use "updatedAfter" style parameter if available; otherwise poll and diff by updated timestamp
- Treat highlights as Notes linked to the parent Report
### Optional link extraction
- TI_LINK_STRATEGY=report|reference_only|none
- TI_READWISE_LOOKBACK_DAYS=14 (initial backfill window)

## Zotero connector
### Inputs (Zotero)
- ZOTERO_API_KEY, ZOTERO_LIBRARY_ID, ZOTERO_LIBRARY_TYPE

### Incremental strategy (Zotero)
- Zotero has a library version; store last seen version.
- Treat annotations as Notes linked to the parent Report
- TI_ZOTERO_LOOKBACK_DAYS=30 (initial backfill window)
- TI_LINK_STRATEGY=report|reference_only|none (optional link extraction from annotations)

## Enrich Text connector
Adds CVEs/IOCs for recent Reports and Notes and links them back to the container Report.
- Inputs: recent Reports/Notes from OpenCTI
- Output: Vulnerability/Observable relationships
- Filters by label via `TI_ENRICH_SOURCES` and recency via `ENRICH_LOOKBACK_DAYS`
- Optional LLM entity extraction via `ENRICHMENT_LLM_*` (persons, orgs, products, countries)

## Acceptance criteria
- Each connector can run in isolation (`docker compose up connector-miniflux`)
- It ingests at least one real item and creates:
  - Report + ExternalReference + Notes (if highlights/annotations exist)
- Re-running does not create duplicates.

## CVE List V5 connector
Imports CVE entries from the CVEProject `cvelistV5` repository.
- Pulls the Git repository and processes updated CVE JSON files.
- Creates or updates Vulnerability objects and attaches external references.
- Runs hourly by default (`CVELIST_RUN_INTERVAL_SECONDS=3600`).
