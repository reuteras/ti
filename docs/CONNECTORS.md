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

### Common internal modules
- client_opencti.py: wrapper for OpenCTI GraphQL mutations
- state_store.py: SQLite/JSON cursor store
- extractors/
  - html.py (readability/trafilatura)
  - pdf.py (pypdf/pdfminer fallback)
- enrichers/
  - ioc_extract.py
  - cve_extract.py
- stix/
  - mappers.py (source item -> STIX objects)
  - relationships.py

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
- Extract CVEs:
  - Create Vulnerability objects (name="CVE-YYYY-NNNN")
  - Link Report -> Vulnerability ("related-to")
- Extract Observables:
  - Domain-Name, Url, IPv4-Addr, IPv6-Addr, File (hashes), Email-Addr
  - Link Report -> Observable ("related-to")

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
- Montysecurity C2-Tracker
- MISP Feed (CIRCL OSINT)
- OpenCTI Datasets
- RansomwareLive
- VirusTotal
- Shodan InternetDB
- Shodan
- YARA (internal enrichment)

Note: NVD is not used; CVE coverage comes primarily from CISA KEV + OpenCTI Datasets.

## Miniflux connector
### Inputs
- MINIFLUX_URL
- MINIFLUX_TOKEN

### Incremental strategy
- Cursor based on miniflux entry IDs and/or "updated_at".
- Store last_run timestamp and last_entry_id per feed (or global).

### Implementation details
- Fetch unread + recently updated entries (configurable)
- Optionally mark entries as "read" after ingestion (feature-flagged, default off)

## Readwise connector
### Inputs
- READWISE_TOKEN

### Incremental strategy
- Use "updatedAfter" style parameter if available; otherwise poll and diff by updated timestamp
- Treat highlights as:
  - either separate Reports OR
  - Notes linked to the parent source (Phase 2)

## Zotero connector
### Inputs
- ZOTERO_API_KEY, ZOTERO_LIBRARY_ID, ZOTERO_LIBRARY_TYPE

### Incremental strategy
- Zotero has a library version; store last seen version.
- For PDF attachments:
  - download metadata; optionally download file (config)
  - extract text and store as blob

## Acceptance criteria
- Each connector can run in isolation (`docker compose up connector-miniflux`)
- It ingests at least one real item and creates:
  - Report + ExternalReference + at least one observable or CVE if present
- Re-running does not create duplicates.

## CVE List V5 connector
Imports CVE entries from the CVEProject `cvelistV5` repository.
- Pulls the Git repository and processes updated CVE JSON files.
- Creates or updates Vulnerability objects and attaches external references.
- Runs hourly by default (`CVELIST_RUN_INTERVAL_SECONDS=3600`).
