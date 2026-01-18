# ti

# personal-cti (OpenCTI-first)

Personal Threat Intel platform:
- OpenCTI as the primary knowledge base (STIX 2.1 / graph UI / ATT&CK objects)
- Custom connectors for personal sources:
  - Miniflux (RSS)
  - Readwise / Readwise Reader
  - Zotero (docs/PDFs/notes)
- A "briefing service" that:
  - queries OpenCTI for new intel since last run
  - produces a daily briefing (HTML + RSS/Atom)
  - stores briefing artifacts for weekly/monthly/quarterly/yearly rollups
- "Watch items" (CVE/campaign names) with extra monitoring and optional targeted web searches

## Non-goals (for now)
- TheHive/Cortex (license constraints)
- MISP (maybe later)
- Full-blown SOC case management workflows

## Quickstart (dev)
1) Copy `.env.example` to `.env` and fill required values.
2) Run:
   ```bash
   docker compose up -d --build
3) Open:
- OpenCTI UI: <http://localhost:8080>
- Briefing service: <http://localhost:8088>

OpenCTI’s “official” way for connectors is typically via their connector framework and/or the OpenCTI Python client. Codex should:
- Prefer the official OpenCTI Python client / connector patterns if feasible
- But for MVP, it’s acceptable to talk GraphQL directly (fewer moving parts), as long as it’s idempotent and stable.

## Optional local LLM summaries
Connectors can optionally call a local LLM endpoint to append short summaries to ingested text.

1) Run a local Ollama (default):
   - Endpoint: `http://host.docker.internal:11434/api/generate`
2) Set in `.env`:
   - `ENRICHMENT_LLM_ENABLED=true`
   - `ENRICHMENT_LLM_ENDPOINT=http://host.docker.internal:11434/api/generate`
   - `ENRICHMENT_LLM_MODEL=llama3.1`

You can point `ENRICHMENT_LLM_ENDPOINT` to any compatible HTTP endpoint (local or container).
