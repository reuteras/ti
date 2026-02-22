import json
from xml.sax.saxutils import escape

from .storage import BriefingRecord


def _cdata(value: str) -> str:
    return f"<![CDATA[{value}]]>"


def _summary_html(briefing: BriefingRecord) -> str:
    try:
        payload = json.loads(briefing.json or "{}")
    except Exception:
        return "Daily briefing available."

    summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
    clusters = payload.get("clusters", []) if isinstance(payload, dict) else []
    total_reports = int(summary.get("total_reports", 0) or 0)
    total_clusters = int(summary.get("total_clusters", 0) or 0)
    watch_hits = int(summary.get("watch_hits", 0) or 0)
    new_cves = int(summary.get("new_cves", 0) or 0)
    new_iocs = int(summary.get("new_iocs", 0) or 0)
    cisa_kev_new = int(summary.get("cisa_kev_new", 0) or 0)
    cisa_kev_updated = int(summary.get("cisa_kev_updated", 0) or 0)
    new_intrusion_sets = int(summary.get("new_intrusion_sets", 0) or 0)

    lines = [
        (
            f"<p>{total_reports} reports grouped into {total_clusters} clusters. "
            f"Watch hits: {watch_hits}. New CVEs: {new_cves}. New IOCs: {new_iocs}. "
            f"CISA KEV new: {cisa_kev_new}. CISA KEV updated: {cisa_kev_updated}. "
            f"New Intrusion Sets: {new_intrusion_sets}.</p>"
        )
    ]

    if isinstance(clusters, list) and clusters:
        lines.append("<ul>")
        for cluster in clusters[:5]:
            if not isinstance(cluster, dict):
                continue
            headline = escape(str(cluster.get("headline") or "Untitled cluster"))
            item_count = int(cluster.get("item_count", 0) or 0)
            cves = cluster.get("cves", [])
            cve_text = ""
            if isinstance(cves, list) and cves:
                cve_text = f" | CVEs: {', '.join(escape(str(value)) for value in cves[:3])}"
            lines.append(f"<li><strong>{headline}</strong> ({item_count} reports){cve_text}</li>")
        lines.append("</ul>")
    return "".join(lines)


def build_rss_feed(briefings: list[BriefingRecord], base_url: str) -> str:
    items = []
    for briefing in briefings:
        briefing_url = f"{base_url}/briefings/{briefing.date}.html"
        summary_html = _summary_html(briefing)
        items.append(
            "\n".join(
                [
                    "    <item>",
                    f"      <title>{escape(f'Briefing {briefing.date}')}</title>",
                    f"      <link>{escape(briefing_url)}</link>",
                    f"      <guid>{escape(f'{base_url}/briefings/{briefing.date}.json')}</guid>",
                    f"      <description>{_cdata(summary_html)}</description>",
                    "    </item>",
                ]
            )
        )

    rss = "\n".join(
        [
            '<?xml version="1.0" encoding="utf-8"?>',
            f'<?xml-stylesheet type="text/xsl" href="{escape(base_url)}/feeds/daily.xsl"?>',
            '<rss version="2.0">',
            "  <channel>",
            "    <title>Daily Briefings</title>",
            f"    <link>{escape(f'{base_url}/briefings/daily/today')}</link>",
            "    <description>Daily OpenCTI briefings</description>",
            "\n".join(items),
            "  </channel>",
            "</rss>",
        ]
    )
    return rss
