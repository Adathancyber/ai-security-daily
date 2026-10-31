import sys, json
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build

NOW = datetime(2026, 10, 31, 5, 13, tzinfo=timezone.utc)
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Exposure management platform maps AI agent attack paths</title><link>https://ex.com/1</link><pubDate>Fri, 30 Oct 2026 10:00:00 +0000</pubDate><description>&lt;p&gt;New CTEM tool finds exposed MCP servers.&lt;/p&gt;</description></item>
<item><title>Webinar: AI security for everyone</title><link>https://ex.com/2</link><pubDate>Fri, 30 Oct 2026 10:00:00 +0000</pubDate><description>Join us</description></item>
<item><title>Ransomware hits hospital</title><link>https://ex.com/3</link><pubDate>Fri, 30 Oct 2026 10:00:00 +0000</pubDate><description>Hospital systems were encrypted.</description></item>
<item><title>Hackers use AI-generated phishing to breach banks</title><link>https://ex.com/4</link><pubDate>Thu, 29 Oct 2026 10:00:00 +0000</pubDate><description>A campaign used LLMs. It spread fast.</description></item>
<item><title>Old AI story</title><link>https://ex.com/5</link><pubDate>Thu, 01 Oct 2026 10:00:00 +0000</pubDate><description>AI</description></item>
</channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Prompt injection flaw in Copilot leaks secrets</title><link rel="alternate" href="https://ex.org/a"/><published>2026-10-30T08:00:00Z</published><summary>Researchers found a prompt injection bug.</summary></entry>
</feed>"""

def test_pipeline():
    items = build.parse_feed(RSS, "Ex") + build.parse_feed(ATOM, "Ex2")
    assert len(items) == 6
    ed = build.build(now=NOW, offline_items=items)
    urls = [s["url"] for s in ed["stories"]]
    assert "https://ex.com/2" not in urls  # webinar dropped
    assert "https://ex.com/3" not in urls  # not AI
    assert "https://ex.com/5" not in urls  # too old
    assert urls[0] == "https://ex.com/1"
    assert ed["stories"][0]["cat"] == "exposure"
    assert ed["stories"][0]["why"] == "New CTEM tool finds exposed MCP servers."
    cats = {s["url"]: s["cat"] for s in ed["stories"]}
    assert cats["https://ex.org/a"] == "vuln"
    assert cats["https://ex.com/4"] == "threat"
    html = build.render(ed)
    assert "__EDITION_JSON__" not in html and "Exposure management platform" in html
    print(json.dumps(ed, indent=1)[:900])

test_pipeline()
print("ok")
