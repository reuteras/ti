# Deployment (docker-compose)

## Goals
- One `docker-compose.yml` that runs:
  - OpenCTI stack
  - OpenCTI worker (queue ingestion)
  - core connectors (miniflux/readwise/zotero)
  - enrichment connector (enrich-text)
  - external enrichment/import connectors
  - briefing service

## Notes
- OpenCTI requires Elasticsearch + Redis + RabbitMQ + Postgres.
- Use persistent volumes.
- Provide healthchecks for all services.
- Some connectors also write to a shared mapping database volume (`mapping-data`). If you see permission errors (e.g., `attempt to write a readonly database`), ensure the volume is owned by the connector user (uid=100,gid=101 by default for `app`). You can run `scripts/fix_volume_permissions.sh` once to chown the relevant volumes.
- Provide profiles:
  - `dev` (everything local)
  - `prod` (reverse proxy, TLS, externalized secrets) - future

## Required deliverables
- docker-compose.yml
- optional docker-compose.override.yml for local dev
- per-service Dockerfiles:
  - services/briefing/Dockerfile
  - services/connectors/miniflux/Dockerfile
  - services/connectors/readwise/Dockerfile
  - services/connectors/zotero/Dockerfile
  - services/connectors/enrich_text/Dockerfile

## Acceptance criteria
- `docker compose up -d --build` works
- OpenCTI UI reachable on localhost:8080
- briefing service reachable on localhost:8088
- connectors run and log successful auth + "no new items" when empty
- external connectors start cleanly (CISA KEV, EPSS, OpenCTI Datasets, OTX, ThreatFox, VirusTotal, Shodan)
