<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" indent="yes"/>

  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <title>Daily Briefings RSS</title>
        <style>
          :root {
            color-scheme: light;
            --bg: #f5f7fb;
            --panel: #ffffff;
            --ink: #0b1f3a;
            --muted: #5f6f81;
            --accent: #2f6feb;
            --accent-2: #12b5cb;
            --border: #d9e2ec;
            --shadow: 0 18px 40px rgba(15, 28, 45, 0.08);
          }
          * { box-sizing: border-box; }
          body {
            margin: 0;
            font-family: "Space Grotesk", "Segoe UI", sans-serif;
            background: linear-gradient(135deg, #f5f7fb 0%, #eef4ff 35%, #f7f9fc 100%);
            color: var(--ink);
          }
          header {
            background: radial-gradient(circle at top right, rgba(47, 111, 235, 0.28), transparent 55%), #0b1f3a;
            color: #f8fafc;
            padding: 24px 32px;
          }
          header .kicker {
            font-size: 0.75rem;
            letter-spacing: 0.2em;
            text-transform: uppercase;
            color: rgba(248, 250, 252, 0.6);
          }
          header h1 { margin: 6px 0 0; font-size: 1.8rem; }
          main {
            max-width: 980px;
            margin: 28px auto 60px;
            padding: 0 24px;
          }
          .meta { color: var(--muted); margin-bottom: 20px; }
          .item {
            background: var(--panel);
            padding: 16px 18px;
            margin-bottom: 16px;
            border-radius: 14px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
          }
          .item h2 { margin: 0 0 10px 0; font-size: 1.1rem; }
          .item a { color: var(--accent); text-decoration: none; font-weight: 600; }
          .item a:hover { color: var(--accent-2); }
        </style>
      </head>
      <body>
        <header>
          <div class="kicker">OpenCTI Briefing</div>
          <h1><xsl:value-of select="rss/channel/title"/></h1>
        </header>
        <main>
          <div class="meta">Human-friendly view of the RSS feed. Use your feed reader for updates.</div>
          <xsl:for-each select="rss/channel/item">
            <div class="item">
              <h2>
                <a>
                  <xsl:attribute name="href"><xsl:value-of select="link"/></xsl:attribute>
                  <xsl:value-of select="title"/>
                </a>
              </h2>
              <div>
                <xsl:value-of select="description" disable-output-escaping="yes"/>
              </div>
            </div>
          </xsl:for-each>
        </main>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
