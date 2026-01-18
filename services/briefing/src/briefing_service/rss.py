from xml.sax.saxutils import escape

from .storage import BriefingRecord


def _cdata(value: str) -> str:
    return f"<![CDATA[{value}]]>"


def build_rss_feed(briefings: list[BriefingRecord], base_url: str) -> str:
    items = []
    for briefing in briefings:
        items.append(
            "\n".join(
                [
                    "    <item>",
                    f"      <title>{escape(f'Briefing {briefing.date}')}</title>",
                    f"      <link>{escape(f'{base_url}/briefings/daily/today')}</link>",
                    f"      <guid>{escape(f'{base_url}/briefings/{briefing.date}.json')}</guid>",
                    f"      <description>{_cdata(briefing.html)}</description>",
                    "    </item>",
                ]
            )
        )

    rss = "\n".join(
        [
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            f"<?xml-stylesheet type=\"text/xsl\" href=\"{escape(base_url)}/feeds/daily.xsl\"?>",
            "<rss version=\"2.0\">",
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
