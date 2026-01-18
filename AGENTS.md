# Project agent guide

## Mission
Build a personal CTI platform with OpenCTI as the source of truth, custom connectors, and a briefing service that outputs HTML + RSS with stored artifacts.

## Current repo layout (expected)
- docker-compose.yml
- .env.example
- services/briefing (FastAPI app)
- services/connectors/{common,miniflux,readwise,zotero}
- docs/*.md for architecture + requirements

## Implementation priorities
1) Docker compose stack with OpenCTI + briefing + connectors and healthchecks.
2) Briefing service MVP: /health, /latest, /feeds/daily.rss, scheduled daily job, SQLite storage.
3) Minimal OpenCTI GraphQL client for reading Reports and connector ingestion.
4) Connectors skeletons with cursor state and idempotent ingestion.
5) Watchlist MVP inside briefing service.

## Required behaviors
- Python 3.12+
- Use `uv` in pyproject-based builds
- Structured logging (key=value) with request ids for briefing service
- Idempotent ingestion: avoid duplicating reports
- Persist cursors/state via volume-backed storage

## Reference docs
- docs/ARCHITECTURE.md
- docs/BRIEFING_SERVICE.md
- docs/CONNECTORS.md
- docs/WATCHLIST.md
- docs/DEPLOYMENT.md
- docs/CODEX_TASKS.md

## Conventions
- Prefer FastAPI for briefing service
- OpenCTI access via GraphQL (`OPENCTI_URL`, `OPENCTI_ADMIN_TOKEN`)
- Keep MVP simple; avoid LLM or clustering work beyond the brief
