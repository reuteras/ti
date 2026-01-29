# Codex instructions: Zotero (WebDAV, indexed fulltext) → OpenCTI (free, latest) connector

## Goal
Implement a Dockerized connector/service in this repo that:

- Pulls **Zotero indexed full-text** for **attachment items** (NOT the PDF binaries; user uses WebDAV).
- Creates/updates OpenCTI objects:
  - **Report** for the parent bibliographic Zotero item
  - **Artifact observable** for each attachment (no file upload; use hashes/metadata)
  - **Note** (one per attachment) containing the **indexed fulltext**, linked to BOTH the Report and the Artifact
- Uses **incremental sync** based on Zotero “since” versioning for fulltext changes to avoid reprocessing.

## Non-goals
- Do not download PDFs from Zotero/WebDAV.
- Do not implement OCR; only use Zotero’s indexed text.
- Do not require OpenCTI enterprise features.

---

## High-level design

### Data flow
1. Poll Zotero for fulltext changes since last run  
   - GET /users/{user_id}/fulltext?since={last_fulltext_version}
2. For each changed attachment key  
   - GET /users/{user_id}/items/{attachment_key}/fulltext  
   - If 404: skip and retry later (indexing may not exist yet)
3. Resolve the attachment’s parent item metadata (title, authors, date, DOI, URL, tags)
4. Upsert in OpenCTI  
   - Report (parent item)  
   - Artifact observable (attachment)  
   - Note (attachment fulltext)  
   - Relationships  
     - Note → Report  
     - Note → Artifact  
     - Optional: Report → Artifact (“related-to”)

### Libraries
- Zotero  
  - Use pyzotero for item and attachment metadata and auth handling  
  - Use direct HTTP requests for the two fulltext endpoints if pyzotero does not expose them cleanly
- OpenCTI  
  - Use pycti (OpenCTI Python client / connector helper)

---

## Repo structure to add

- connectors/
  - zotero-fulltext/
    - README.md
    - Dockerfile
    - docker-compose.yml (or document usage in top-level compose)
    - pyproject.toml (preferred) or requirements.txt
    - src/
      - zotero_fulltext_connector/
        - `__init__.py`
        - main.py
        - config.py
        - zotero_client.py
        - opencti_client.py
        - mapper.py
        - state.py
        - utils.py
    - tests/
      - test_zotero_fulltext.py
      - test_mapping.py

Follow existing repo conventions if a connector pattern already exists.

---

## Configuration (environment variables)

### Zotero
- ZOTERO_API_KEY (required)
- ZOTERO_USER_ID (required, user library)
- ZOTERO_API_BASE (optional, default [https://api.zotero.org](https://api.zotero.org))
- ZOTERO_PAGE_SIZE (optional, default 100)

### OpenCTI
- OPENCTI_URL (required)
- OPENCTI_TOKEN (required)
- OPENCTI_CONNECTOR_ID (required UUID)
- OPENCTI_CONNECTOR_NAME (default: Zotero Fulltext)
- OPENCTI_CONNECTOR_SCOPE (default: report,artifact,note)
- OPENCTI_CONNECTOR_LOG_LEVEL (default: info)

### Runtime / state
- POLL_INTERVAL_SECONDS (default: 900)
- STATE_PATH (default: /data/state.json)
- NOTE_MAX_CHARS (default: 150000)
- ARTIFACT_KIND (default: artifact, allow fallback to file)

---

## State handling
Persist state in a JSON file mounted to /data.

Fields:
- last_fulltext_version (integer)
- processed  
  - attachment_key  
    - last_content_hash  
    - last_seen_version  
    - last_run_timestamp  

Rules:
- Update last_fulltext_version only after successful processing
- Skip creating notes if content hash has not changed

---

## Zotero API specifics

### Incremental list of changed fulltext
- GET /users/{ZOTERO_USER_ID}/fulltext?since={last_fulltext_version}
- Read Last-Modified-Version header as new version
- JSON keys represent attachment item keys

### Fetch attachment fulltext
- GET /users/{ZOTERO_USER_ID}/items/{attachment_key}/fulltext
- 404 means not indexed yet; retry later
- Response fields:
  - content
  - indexedPages
  - totalPages

### Metadata resolution
For each attachment:
- Fetch attachment item
- Extract parentItem key
- Fetch parent item metadata
- Extract title, creators, date, DOI, URL, publication, tags

---

## OpenCTI object mapping

### Report (parent item)
- name: title
- description: optional
- published: parsed date if available
- labels: Zotero tags
- external references: DOI, URL, zotero:parent:{key}

Dedup priority:
1. DOI
2. URL
3. Zotero parent key

### Artifact observable (per attachment)
- Type: Artifact observable (fallback to File observable if required)
- name: attachment filename or title
- hashes:
  - SHA-256 of normalized fulltext
- labels:
  - source:zotero
  - zotero:attachment:{attachment_key}
  - optional zotero:parent:{parent_key}

Normalization rules for hashing:
- CRLF to LF
- Strip trailing whitespace
- Collapse multiple blank lines to max two
- Do not lowercase content

### Note (one per attachment)
- attribute: text
- content:
  - Title: Zotero fulltext: {attachment title}
  - Metadata block:
    - zotero_attachment_key
    - zotero_parent_key
    - doi
    - url
    - indexed_pages
    - retrieved_at
    - content_sha256
  - Blank line
  - Fulltext content

Chunking:
- If content exceeds NOTE_MAX_CHARS, split into parts
- Suffix titles with (part N/M)
- Each chunk links to the same Report and Artifact

Dedup:
- Do not create new notes if content hash unchanged

---

## Relationships
- Note → Report
- Note → Artifact (or File observable)
- Optional: Report → Artifact (“related-to”)

Use pycti helper methods; avoid manual STIX JSON unless necessary.

---

## Polling loop
1. Load state
2. Determine since version
3. Fetch changed attachment keys
4. For each key:
   - Fetch fulltext
   - Resolve metadata
   - Upsert Report, Artifact, Note, relationships
   - Update state
5. Save state
6. Sleep POLL_INTERVAL_SECONDS
7. Repeat

Log counts:
- changed_keys
- processed_ok
- skipped_404
- skipped_unchanged
- errors

---

## Error handling
- Zotero 429: respect Retry-After
- Zotero 5xx: exponential backoff
- OpenCTI transient failures: retry
- One failed attachment must not stop the loop

---

## Tests
Write unit tests for:
- fulltext normalization and hashing
- mapping logic
- note chunking
- state load/save

No network calls in tests.

---

## Deliverables
1. Connector folder with code, Dockerfile, and README
2. docker-compose example with required env vars and /data volume
3. Validation steps documented:
   - verify Report creation
   - verify Artifact observable with sha256
   - verify Note linked to both Report and Artifact
