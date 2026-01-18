# Deployment (docker-compose)

## Goals
- One `docker-compose.yml` that runs:
  - OpenCTI stack
  - 3 connectors
  - briefing service

## Notes
- OpenCTI requires Elasticsearch + Redis + RabbitMQ + Postgres.
- Use persistent volumes.
- Provide healthchecks for all services.
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

## Acceptance criteria
- `docker compose up -d --build` works
- OpenCTI UI reachable on localhost:8080
- briefing service reachable on localhost:8088
- connectors run and log successful auth + "no new items" when empty
