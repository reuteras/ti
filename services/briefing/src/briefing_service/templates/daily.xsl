<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" indent="yes"/>

  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <title>Daily Briefings RSS</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 24px; background: #f6f4ef; color: #1b1b1b; }
          h1 { margin-bottom: 8px; }
          .meta { color: #666; margin-bottom: 24px; }
          .item { background: #fff; padding: 16px; margin-bottom: 16px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
          .item h2 { margin: 0 0 8px 0; font-size: 1.1rem; }
          .item a { color: #1b4f8a; text-decoration: none; }
          .item a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <h1><xsl:value-of select="rss/channel/title"/></h1>
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
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
