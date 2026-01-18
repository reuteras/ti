# Briefing service

## Goals
- Provide a web UI endpoint for "Latest intel"
- Publish daily briefings as:
  - HTML (human-readable)
  - RSS/Atom feed (for consumption in readers)
- Store all briefings for later rollups (weekly/monthly/quarterly/yearly)

## Stack
- Python + FastAPI
- SQLite (state + stored briefing artifacts) in a volume
- Talks to OpenCTI via GraphQL

## Endpoints (MVP)
- GET /health
- GET /latest
  - HTML page (server-rendered) listing top clusters/stories
- GET /briefings/daily/today
  - HTML daily briefing
- GET /feeds/daily.rss
  - RSS feed of daily briefings (latest N)
- GET /briefings/{date}.json
  - structured briefing artifact

## Briefing generation (MVP)
1) Query OpenCTI for Reports/Notes created since last briefing run (or last 24h at first).
2) Extract:
   - title, description, created_at, external refs, linked CVEs, linked observables
3) Cluster (simple):
   - same CVE => same cluster
   - else, same normalized title similarity + same host => cluster
4) Rank:
   - boost: CVE present, many observables, trusted sources, watchlist match
   - penalty: very short items, duplicates
5) Render:
   - Top 5 clusters with:
     - summary bullets (MVP: heuristic; later LLM)
     - why it matters (template)
     - links to sources (OpenCTI + original)
     - CVEs and observables highlights
   - Notable mentions section

## Storage
- briefing table:
  - date (YYYY-MM-DD)
  - html
  - json (structured)
  - created_at
- state table:
  - last_run_timestamp
  - last_opencti_cursor (if needed)

## Acceptance criteria
- /feeds/daily.rss returns valid RSS XML and includes a link back to /briefings/daily/today
- Running "generate briefing" twice on same day is idempotent (replaces or keeps one canonical daily entry)
