# Miniflux -> OpenCTI ingestion (read-only Miniflux) using Miniflux Python API

Goal: Ingest RSS entries from a **local Miniflux** instance into **OpenCTI**
as **STIX 2.1** via an **OpenCTI external-import connector**.
The connector MUST be **read-only** towards Miniflux (no marking read, no edits).
It MUST import **since last run** (stateful incremental).
It MUST ingest **as much text as possible** from entries.
It MUST do **deep extraction** (ATT&CK, CVEs, IOCs, YARA/Sigma/Snort, actors/malware)
and create relationships for correlation.
Dedup MUST be **URL-first**, with Miniflux entry ID as secondary.

## High-level approach

Implement an OpenCTI connector service:
- Polls Miniflux periodically using the official Miniflux Python client (`miniflux`).
- Retrieves a bounded window of entries (e.g., last N entries across all feeds or last X days), then filters **locally** to only process entries newer than stored connector state.
- For each qualifying entry:
  - Build a STIX 2.1 Bundle containing a carrier `Report` (and optionally `Note`) with full text.
  - Extract entities from content (CVE, IOC, ATT&CK, malware/actor names, rules, etc.).
  - Add those entities to the bundle and connect them to the carrier object with relationships.
  - Push the STIX bundle into OpenCTI using the OpenCTI connector helper `send_stix2_bundle`.
- Store state after successful ingestion so the next run continues incrementally.

References (for implementation):
- Miniflux Python client: `pip install miniflux`
- OpenCTI Python client / connector helper: `pip install pycti`
- STIX 2.1 Python lib: `pip install stix2`

## Constraints (MUST)

1. Miniflux is read-only:
   - MUST NOT mark items read/unread
   - MUST NOT edit entries
   - MUST NOT change feeds or categories

2. Incremental since-last-run:
   - MUST store and update connector state:
     - `last_published_at` (timestamp)
     - `last_entry_id` (tie-breaker for equal timestamps)
     - optional rolling set of `recent_url_sha256` for duplicate dampening
   - MUST fetch a bounded set from Miniflux then filter by state.

3. Text completeness:
   - MUST ingest as much entry text as possible:
     - title
     - content (prefer full content; include summary if content missing)
     - optionally keep both HTML and plain text if needed

4. Deep extraction:
   - MUST extract and model:
     - CVEs -> `Vulnerability`
     - IOCs (ip/domain/url/hash/email) -> `Indicator` w/ STIX patterns
     - ATT&CK technique IDs -> `AttackPattern` (mapped by technique id)
     - Malware, Threat Actor, IntrusionSet (from NER/dictionaries)
     - YARA, Sigma, Snort rules as artifacts/notes/labels + relationships

5. Deduplication (URL-first):
   - MUST canonicalize URLs and use them as primary identity for “same story”
   - MUST still include Miniflux entry ID as secondary ID

6. Attribution:
   - MUST create an `Identity` for "Miniflux" (as ingestion system)
   - SHOULD create publisher/organization identity from feed metadata (domain/title)
   - SHOULD create author individual identity from entry metadata if available
   - MUST link carrier object to attribution identities/author(s)

## Data model (STIX mapping)

Per entry create:

### Carrier object (choose one primary carrier)
- Preferred: `Report` (STIX 2.1)
  - `name`: entry.title
  - `description`: full entry text (plain text by default; see HTML below)
  - `published`: entry.published_at
  - `labels`: include tags like `miniflux`, feed category, etc.
  - `external_references`:
    - original/canonical URL
    - feed URL
    - `source_name="miniflux"` + `external_id=<entry_id>`

Optionally add a `Note` for:
- preserved HTML (if you want fidelity)
- extracted rules (YARA/Sigma/Snort) if you don’t model them as first-class objects
- extra metadata not fitting Report cleanly

### Source identities
- `Identity` "Miniflux" (system/tool)
- `Identity` for publisher (from feed site domain / title)
- `Identity` for authors (if present; use `Individual` identity class if your tooling supports)

### Extracted entities (deep)
- `Vulnerability` objects for CVEs
- `Indicator` objects for IOCs
  - use STIX patterns:
    - IP: `[ipv4-addr:value = '1.2.3.4']`
    - Domain: `[domain-name:value = 'example.com']`
    - URL: `[url:value = 'https://…']`
    - Hashes:
      - MD5: `[file:hashes.MD5 = '…']`
      - SHA-1: `[file:hashes.'SHA-1' = '…']`
      - SHA-256: `[file:hashes.'SHA-256' = '…']`
- `AttackPattern` for ATT&CK technique IDs (Txxxx)
- `Malware`, `ThreatActor`, `IntrusionSet` as discovered

### Relationships
- carrier `Report` -> extracted objects:
  - `report` references each extracted entity (or add to `object_refs`)
- optionally:
  - `Indicator` indicates `Malware` / `IntrusionSet` where explicit
- attribution:
  - carrier created-by / published-by publisher Identity (choose the relationship type that OpenCTI handles best)
  - carrier attributed-to author Identity (if modeled)

## Fetching entries from Miniflux (read-only)

Use miniflux client:
- Authenticate with API key
- Fetch entries across all feeds within a bounded window:
  - Last N entries (recommended: N=200..1000)
  - OR last X days (recommended: X=7..30)
- If Miniflux has a “modified_since” / “updated_since” filter in your used endpoint, use it.
- Otherwise do bounded fetch + local filter.

Local filter rules:
- Process entry if:
  - entry.published_at > state.last_published_at
  - OR (equal timestamps AND entry.id > state.last_entry_id)
- Additional duplicate guard:
  - compute url hash (sha256 of canonical_url) and skip if in state.recent_url_sha256

State update:
- After successful ingestion of all entries, set:
  - last_published_at = max(published_at processed)
  - last_entry_id = max(id among entries with that max timestamp)
  - recent_url_sha256 = updated rolling set (e.g. keep last 500 hashes)

## URL canonicalization (URL-first dedup)

Implement `canonicalize_url(url)`:
- lower-case scheme + host
- remove fragment (#...)
- strip common tracking parameters:
  - utm_source, utm_medium, utm_campaign, utm_term, utm_content
  - gclid, fbclid, mc_cid, mc_eid, ref, ref_src, spm, etc.
- normalize:
  - remove default ports (:80, :443)
  - collapse duplicate slashes
  - optional: remove trailing slash consistency

Compute:
- `url_sha256 = sha256(canonical_url.encode("utf-8")).hexdigest()`

Store:
- as external_reference in STIX:
  - `source_name="url"`, `url=canonical_url`
  - `source_name="miniflux"`, `external_id=str(entry.id)`

## Text handling (maximum text)

- Prefer entry.content if present
- Else entry.summary (or equivalent)
- Also include:
  - entry.title
  - feed title
  - feed site URL
  - author fields
- Convert HTML -> plain text for `Report.description` by default (better search)
- Optionally preserve HTML:
  - store HTML in a `Note` linked to the Report
  - store both as separate notes (plain + html) if helpful

## Deep extraction pipeline

From combined text (title + content + summary):
- CVE extraction:
  - regex `CVE-\d{4}-\d{4,7}`
  - create `Vulnerability` objects for each unique CVE
- IOC extraction:
  - IPv4 (exclude private/reserved by default unless configured)
  - domains (exclude common placeholders: example.com, test, localhost)
  - URLs
  - hashes (md5/sha1/sha256)
  - emails (optional)
  - create `Indicator` objects w/ STIX patterns and confidence score
- ATT&CK techniques:
  - regex `T\d{4}(\.\d{3})?`
  - map to `AttackPattern` objects (with external refs to MITRE page)
- Malware/Actor/IntrusionSet:
  - (optional) dictionary-based matching + NER
- Rules extraction:
  - YARA: detect `rule <name> { ... }`
  - Sigma: detect YAML structure with `title:`, `logsource:`, `detection:`
  - Snort/Suricata: detect `alert ... ( ... )`
  - store as `Note` with labels `yara` / `sigma` / `snort` and link to carrier Report

All extracted objects MUST be linked to carrier Report via relationships/object_refs.

## OpenCTI ingestion

Use pycti connector helper:
- Build STIX bundle (`stix2.Bundle(objects=[...])`)
- Send:
  - `helper.send_stix2_bundle(bundle.serialize())`

Use connector state:
- `helper.get_state()` / `helper.set_state(state)` (or equivalent)
- Only update state after successful send.

## Configuration (env vars)

Required:
- `MINIFLUX_URL` (e.g., [http://miniflux:8080](http://miniflux:8080))
- `MINIFLUX_API_KEY`
- `OPENCTI_URL` (e.g., [http://opencti:8080](http://opencti:8080))
- `OPENCTI_TOKEN`
- `CONNECTOR_ID` (uuid)
- `CONNECTOR_NAME` (e.g., Miniflux)
- `CONNECTOR_SCOPE` (e.g., text/html, application/rss+xml)
- `CONNECTOR_LOG_LEVEL` (INFO/DEBUG)
- `POLL_INTERVAL_SECONDS` (e.g., 300)
- `FETCH_LIMIT` (e.g., 500) OR `FETCH_DAYS` (e.g., 14)

Optional:
- `STORE_HTML_NOTE` (true/false)
- `IOC_EXCLUDE_PRIVATE_IPS` (true/false)
- `IOC_EXCLUDE_PLACEHOLDERS` (true/false)
- `URL_STRIP_TRACKING` (true/false)
- `RECENT_URL_HASHES_MAX` (e.g., 500)

## Docker-compose integration

Add a service `connector-miniflux` that:
- depends on OpenCTI stack
- has the env vars above
- runs the connector loop

(Implementer: create dockerfile + compose service similar to other OpenCTI connectors in this repo.)

## Deliverables (what to implement in this repo)

1. `connectors/miniflux/` (new connector)
   - `Dockerfile`
   - `requirements.txt` or `pyproject.toml`
   - `src/connector.py` (main loop)
   - `src/miniflux_client.py` (Miniflux fetch wrappers)
   - `src/stix_builder.py` (STIX object construction)
   - `src/extractors/` (cve/ioc/attack/rules)
   - `src/utils/url.py` (canonicalization + hashing)
   - `README.md` (setup + env vars)

2. `docker-compose.yml` updates
   - add `connector-miniflux` service and required env vars

3. Tests
   - URL canonicalization tests
   - Extractor tests (CVE/IOC/ATT&CK/rules)
   - Dedup logic tests (state + url hash window)

## Open questions / TODO (need answers in implementation)

- Miniflux fields availability:
  - which entry fields exist: original_url vs url, content vs summary, author fields?
- OpenCTI version specifics:
  - which relationship types are best supported for attribution?
- Content fidelity:
  - keep HTML as Note or drop?
- Extraction policy:
  - thresholds and excludes (private IPs, placeholders, etc.)

Implementation should default to safe, low-noise extraction (exclude private IPs and placeholders) but allow overrides via env vars.
