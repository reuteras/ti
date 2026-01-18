# Codex tasks (implement directly)

## Repo layout (must match)
.
├─ docker-compose.yml
├─ .env.example
├─ README.md
├─ services/
│  ├─ briefing/
│  │  ├─ Dockerfile
│  │  ├─ pyproject.toml
│  │  ├─ src/briefing_service/
│  │  │  ├─ main.py
│  │  │  ├─ opencti_client.py
│  │  │  ├─ storage.py
│  │  │  ├─ briefing.py
│  │  │  ├─ rss.py
│  │  │  ├─ watchlist.py
│  │  │  └─ templates/
│  │  │     └─ latest.html
│  └─ connectors/
│     ├─ common/
│     │  ├─ pyproject.toml
│     │  └─ src/connectors_common/...
│     ├─ miniflux/
│     │  ├─ Dockerfile
│     │  ├─ pyproject.toml
│     │  └─ src/connector_miniflux/main.py
│     ├─ readwise/
│     │  ├─ Dockerfile
│     │  ├─ pyproject.toml
│     │  └─ src/connector_readwise/main.py
│     └─ zotero/
│        ├─ Dockerfile
│        ├─ pyproject.toml
│        └─ src/connector_zotero/main.py
└─ docs/
   ├─ ARCHITECTURE.md
   ├─ DEPLOYMENT.md
   ├─ CONNECTORS.md
   ├─ BRIEFING_SERVICE.md
   ├─ WATCHLIST.md
   └─ CODEX_TASKS.md

## Task 1: docker-compose with OpenCTI + custom services
- Provide OpenCTI stack containers.
- Add briefing service container on port 8088.
- Add connector containers with environment variables and persistent state volumes.
- Add healthchecks.

Acceptance:
- `docker compose up -d --build` starts all containers successfully.

## Task 2: Briefing service MVP (FastAPI)
Implement:
- /health
- /latest (HTML)
- /feeds/daily.rss (RSS)
- A scheduled job inside container:
  - every day at 04:05 Europe/Stockholm generate daily briefing
  - store in SQLite volume
Notes:
- For scheduling, simplest is APScheduler inside app process.

Acceptance:
- /feeds/daily.rss returns valid RSS with at least one item after first run.

## Task 3: OpenCTI GraphQL client
- Implement minimal GraphQL queries:
  - get Reports created between timestamps
  - fetch external references, linked CVEs, linked observables
- Configure via OPENCTI_URL + OPENCTI_ADMIN_TOKEN

Acceptance:
- A test query returns non-empty when OpenCTI contains data.

## Task 4: Miniflux connector MVP
- Poll miniflux for new entries since cursor
- Map to OpenCTI Report + ExternalReference
- Extract CVEs + basic IOCs from title+content
- Store cursor

Acceptance:
- At least one new miniflux item appears as Report in OpenCTI.

## Task 5: Watchlist MVP (briefing service)
- SQLite tables: watch_item, watch_alert
- Add a minimal CLI command or env-seeded watch items
- Boost ranking if matches

Acceptance:
- A watch item causes a matching report to appear in "Watch alerts" section.

## Task 6: Readwise + Zotero connectors (skeleton + cursor)
- Implement auth, cursor, and create Reports with external refs.
- Content extraction can be minimal at first (description only).

Acceptance:
- Connectors run and ingest at least metadata without crashing.

## Quality requirements
- Python 3.12+
- Use `uv` in pyproject.toml for dependency management
- Structured logging (json or key=value) with request ids in briefing service
- Idempotency: re-run connectors without duplicating objects

## Out of scope for MVP
- Embeddings, advanced clustering
- ATT&CK technique linking
- Web search ingestion (keep feature flags and stubs)
