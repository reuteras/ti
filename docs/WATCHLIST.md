# Watchlist & extra monitoring

## Goal
Let the user "pin" an item (CVE, campaign name, malware name, vendor/product) and:
- boost relevance score
- ensure it appears in daily briefings if new mentions appear
- optionally run targeted web searches for fresh info (feature-flagged OFF by default)

## Watch item schema (MVP)
- id (uuid)
- type: cve|campaign|malware|actor|vendor_product|keyword
- value: e.g. "CVE-2026-12345" or "Shai-Hulud"
- aliases: array of strings
- include_terms: array (AND terms)
- exclude_terms: array (NOT terms)
- severity_override: low|medium|high|critical
- monitoring_interval_hours: int (default 6)
- websearch_enabled: bool (default false)
- last_checked_at: timestamp

## Monitoring behavior
1) Query OpenCTI for Reports created since last_checked_at that mention:
   - the watch value in title/description
   - OR linked Vulnerability matches CVE watch
2) If matches:
   - create a "watch_alert" record in briefing service DB
   - mark cluster/story as boosted

## Optional: web search ingestion (Phase 2, gated)
- Only for watch items with websearch_enabled=true
- Use configured websearch backend
- Normalize results into "Report" objects in OpenCTI, linked back to the watch item (via labels or external refs)
- MUST store provenance: query, timestamp, result URLs

## Acceptance criteria
- Adding a watch item causes relevant OpenCTI items to be flagged and boosted in /latest
- Watch alerts appear in daily briefing when new matches happen
