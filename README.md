# ti

# personal-cti (OpenCTI-first)

Personal Threat Intel platform:
- OpenCTI as the primary knowledge base (STIX 2.1 / graph UI / ATT&CK objects)
- Custom connectors for personal sources:
  - Miniflux (RSS)
  - Readwise / Readwise Reader
  - Zotero (docs/PDFs/notes)
- Official OpenCTI connectors for public data and enrichment (AlienVault OTX, URLhaus, ThreatFox, Abuse.ch SSL, MalwareBazaar, Malpedia, RansomwareLive, CISA KEV, EPSS, VirusTotal, Shodan, OpenCTI Datasets, YARA, MISP Feed, CVE List V5)
- A "briefing service" that:
  - queries OpenCTI for new intel since last run
  - produces a daily briefing (HTML + RSS/Atom)
  - stores briefing artifacts for weekly/monthly/quarterly/yearly rollups
- "Watch items" (CVE/campaign names) with extra monitoring and optional targeted web searches

## Non-goals (for now)
- TheHive/Cortex (license constraints)
- MISP (maybe later)
- Full-blown SOC case management workflows
- NVD connector (not used; CVE coverage is via CISA KEV + OpenCTI Datasets)

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

## Manuall connectors

From OpenCTI Integrations Library, [hub](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations).

- Blocklist.de
- Dan.me.uk (EXIT Nodes only)
- Emerging Threats Blockrules Compromised IPs
- James Brine Threat Feed Endpoint
- LolBas Project
- Spamhaus DROP list
- Threatview.io - Bitcoin Address Intel
- Threatview.io - C2 Hunt Feed
