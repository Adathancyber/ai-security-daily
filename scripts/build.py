#!/usr/bin/env python3
"""Build the AI Security Daily page.

Pulls security news RSS/Atom feeds, keeps stories about AI, scores them for
relevance to AI security and exposure management, and writes the top ten into
public/index.html. Uses only the Python standard library.

If too few fresh stories are found (for example a feed outage), it fills the
list from the previous edition in data/news.json so the page is never empty.
"""
from __future__ import annotations

import html
import json
import math
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
FEEDS_FILE = ROOT / "data" / "feeds.json"
NEWS_FILE = ROOT / "data" / "news.json"
TEMPLATE = ROOT / "site" / "template.html"
OUT_DIR = ROOT / "public"

TOP_N = 10
MAX_AGE_DAYS = 7
MAX_PER_SOURCE = 4
LONDON = ZoneInfo("Europe/London")
UA = "Mozilla/5.0 (compatible; AISecurityDaily/1.0; +https://github.com)"

# A story must mention AI to be considered at all.
AI_TERMS = [
    r"\bAI\b", r"\bA\.I\.", r"artificial intelligence", r"\bLLMs?\b", r"large language model",
    r"\bGenAI\b", r"generative", r"machine learning", r"\bML\b", r"agentic", r"\bAI agents?\b",
    r"\bagents?\b(?=.*\b(AI|LLM|model)\b)", r"chatgpt", r"openai", r"\bGPT-?\d", r"anthropic",
    r"\bclaude\b", r"gemini", r"copilot", r"deepfake", r"prompt injection", r"jailbreak",
    r"\bMCP\b", r"model context protocol", r"frontier model", r"\bAI-(powered|driven|generated|assisted)",
    r"hugging ?face", r"vibe cod", r"coding agent",
]
# Weighted signals. Higher weight = more relevant to the brief.
SIGNALS = {
    "exposure": [
        (r"exposure management", 6), (r"\bCTEM\b", 6), (r"attack surface", 5),
        (r"attack paths?", 4), (r"vulnerability management", 4), (r"exposed", 3),
        (r"misconfigur", 3), (r"(credentials?|secrets?|api keys?|tokens?) (leak|expos|found)", 4),
        (r"leaked (credentials?|secrets?|keys?)", 4), (r"prioriti[sz]", 2), (r"shadow AI", 4),
        (r"unpatched", 2), (r"internet-facing|publicly accessible|open to the internet", 3),
        (r"\bCVE-\d{4}-\d+", 2), (r"CVSS", 2), (r"patch(ed|es|ing)?\b", 1), (r"risk", 1),
        (r"asset (inventory|discovery)", 4), (r"\bAI-BOM\b|\bAIBOM\b|AI inventory", 4),
    ],
    "threat": [
        (r"hackers?|threat actors?|attackers?|APT\d*|state-sponsored|nation-state", 2),
        (r"malware|ransomware|phishing|botnet|backdoor|infostealer|stealer", 2),
        (r"campaign|breach(ed)?|compromis", 2), (r"(AI|LLM)-(powered|driven|generated|assisted) (attack|malware|phish)", 4),
        (r"deepfake", 3), (r"weaponi[sz]", 2),
    ],
    "vuln": [
        (r"prompt injection", 5), (r"jailbreak", 4), (r"(flaw|vulnerabilit|bug|exploit)", 2),
        (r"(AI|model|LLM) (finds?|found|discovers?|discovered|wrote|writes) ", 4),
        (r"zero-day|0-day", 2), (r"sandbox escape|model poisoning|data poisoning", 4),
        (r"\bMCP\b|model context protocol", 3), (r"benchmark", 2),
    ],
    "industry": [
        (r"acqui(re|sition)|merger|raises?\b|funding|series [A-F]", 3), (r"regulat|governance|policy|framework|NIST|CISA|EU AI Act|guidance", 2),
        (r"\bCISOs?\b|board", 2), (r"launch(es|ed)?|unveil|introduc|announc", 1), (r"report|survey|study", 1),
    ],
}
NOISE = re.compile(r"webinar|sponsored|\bpodcast\b|weekly recap|threatsday|week in review|newsletter|\bdeal\b|% off|discount", re.I)
CATEGORY_LABEL_ORDER = ["exposure", "threat", "vuln", "industry"]


def fetch(url: str, timeout: int = 20) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:  # noqa: BLE001 - one bad feed must not stop the build
        print(f"  ! {url}: {e}", file=sys.stderr)
        return None


def text_of(el) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


def clean(s: str) -> str:
    s = html.unescape(re.sub(r"<[^>]+>", " ", s or ""))
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"The post .*? appeared first on .*?\.?$", "", s).strip()
    s = re.sub(r"\[(…|\.\.\.)\]$", "", s).strip()
    return s


def first_sentences(s: str, limit: int = 220) -> str:
    s = clean(s)
    if len(s) <= limit:
        return s
    parts = re.split(r"(?<=[.!?])\s+", s)
    out = ""
    for p in parts:
        if len(out) + len(p) + 1 > limit:
            break
        out = (out + " " + p).strip()
    if not out:
        out = s[: limit - 1].rsplit(" ", 1)[0] + "…"
    return out


def parse_date(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_feed(raw: bytes, source: str) -> list[dict]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        print(f"  ! {source}: parse error {e}", file=sys.stderr)
        return []
    items = []
    for el in root.iter():
        name = local(el.tag)
        if name not in ("item", "entry"):
            continue
        fields: dict[str, str] = {}
        link = ""
        for child in el:
            cn = local(child.tag)
            if cn == "link":
                href = child.get("href")
                if href and child.get("rel", "alternate") == "alternate":
                    link = link or href
                elif not href and child.text:
                    link = link or child.text.strip()
            elif cn in ("title", "description", "summary", "content", "encoded", "pubDate", "published", "updated", "date", "guid"):
                fields.setdefault(cn, text_of(child))
        if not link and fields.get("guid", "").startswith("http"):
            link = fields["guid"]
        title = clean(fields.get("title", ""))
        date = parse_date(fields.get("pubDate") or fields.get("published") or fields.get("date") or fields.get("updated", ""))
        desc = fields.get("description") or fields.get("summary") or fields.get("encoded") or fields.get("content") or ""
        if title and link and date:
            items.append({"title": title, "url": link, "source": source, "dt": date, "desc": clean(desc)})
    return items


def has_ai(text: str) -> bool:
    return any(re.search(p, text, re.I) for p in AI_TERMS)


def score(item: dict, now: datetime) -> tuple[float, str]:
    title, body = item["title"], item["desc"]
    cat_scores = {}
    for cat, pats in SIGNALS.items():
        s = 0.0
        for pat, w in pats:
            if re.search(pat, title, re.I):
                s += w * 2  # title matches count double
            elif re.search(pat, body, re.I):
                s += w
        cat_scores[cat] = s
    # AI in the headline is a strong signal the story is really about AI.
    ai_bonus = 6 if has_ai(title) else 0
    relevance = ai_bonus + cat_scores["exposure"] * 1.4 + cat_scores["threat"] + cat_scores["vuln"] * 1.1 + cat_scores["industry"] * 0.6
    age_days = max((now - item["dt"]).total_seconds() / 86400, 0)
    recency = math.exp(-age_days / 3.0)  # halves roughly every two days
    total = relevance * (0.35 + 0.65 * recency)
    cat = max(CATEGORY_LABEL_ORDER, key=lambda c: (cat_scores[c] * (1.4 if c == "exposure" else 1), -CATEGORY_LABEL_ORDER.index(c)))
    if cat_scores[cat] == 0:
        cat = "threat" if re.search(r"attack|hack|malware", title, re.I) else "industry"
    return total, cat


def norm_title(t: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", t.lower())
    stop = {"the", "a", "an", "of", "to", "in", "and", "for", "on", "with", "as", "by", "is", "are", "at", "from", "new"}
    return {w for w in words if w not in stop and len(w) > 2}


def is_dup(t: str, chosen: list[dict]) -> bool:
    a = norm_title(t)
    for c in chosen:
        b = norm_title(c["title"])
        if a and b and len(a & b) / min(len(a), len(b)) >= 0.6:
            return True
    return False


def build(now: datetime | None = None, offline_items: list[dict] | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    feeds = json.loads(FEEDS_FILE.read_text())
    items: list[dict] = []
    if offline_items is not None:
        items = offline_items
    else:
        for f in feeds:
            raw = fetch(f["url"])
            got = parse_feed(raw, f["name"]) if raw else []
            print(f"  {f['name']}: {len(got)} items", file=sys.stderr)
            items.extend(got)

    cutoff = now - timedelta(days=MAX_AGE_DAYS)
    candidates = []
    seen_urls = set()
    for it in items:
        if it["url"] in seen_urls or it["dt"] < cutoff or it["dt"] > now + timedelta(hours=6):
            continue
        seen_urls.add(it["url"])
        text = f"{it['title']} {it['desc']}"
        if NOISE.search(it["title"]) or not has_ai(text):
            continue
        s, cat = score(it, now)
        if s <= 0:
            continue
        candidates.append({**it, "score": s, "cat": cat})
    candidates.sort(key=lambda c: c["score"], reverse=True)

    chosen: list[dict] = []
    per_source: dict[str, int] = {}
    for c in candidates:
        if len(chosen) >= TOP_N:
            break
        if per_source.get(c["source"], 0) >= MAX_PER_SOURCE or is_dup(c["title"], chosen):
            continue
        chosen.append(c)
        per_source[c["source"]] = per_source.get(c["source"], 0) + 1

    # Make sure exposure management is represented when the feeds have it.
    want_exposure = 2
    have = sum(1 for c in chosen if c["cat"] == "exposure")
    if have < want_exposure:
        extra = [c for c in candidates if c["cat"] == "exposure" and c not in chosen and not is_dup(c["title"], chosen)]
        for e in extra[: want_exposure - have]:
            if len(chosen) >= TOP_N:
                # drop the lowest-ranked non-exposure story
                for i in range(len(chosen) - 1, -1, -1):
                    if chosen[i]["cat"] != "exposure":
                        chosen.pop(i)
                        break
            chosen.append(e)
        chosen.sort(key=lambda c: c["score"], reverse=True)

    stories = [
        {
            "cat": c["cat"],
            "title": c["title"],
            "url": c["url"],
            "source": c["source"],
            "date": c["dt"].astimezone(LONDON).date().isoformat(),
            "why": first_sentences(c["desc"]) or "",
        }
        for c in chosen
    ]

    # Top up from the previous edition if feeds were thin.
    if len(stories) < TOP_N and NEWS_FILE.exists():
        prev = json.loads(NEWS_FILE.read_text()).get("stories", [])
        for p in prev:
            if len(stories) >= TOP_N:
                break
            if p["url"] in {s["url"] for s in stories} or is_dup(p["title"], stories):
                continue
            if datetime.fromisoformat(p["date"]).date() < (now - timedelta(days=MAX_AGE_DAYS + 3)).date():
                continue
            stories.append(p)

    lnow = now.astimezone(LONDON)
    dates = sorted(s["date"] for s in stories) or [lnow.date().isoformat()]
    d0, d1 = datetime.fromisoformat(dates[0]), datetime.fromisoformat(dates[-1])
    if d0.month == d1.month:
        window = f"Stories from {d0.day} to {d1.day} {d1:%B %Y}" if d0 != d1 else f"Stories from {d1.day} {d1:%B %Y}"
    else:
        window = f"Stories from {d0.day} {d0:%B} to {d1.day} {d1:%B %Y}"
    return {
        "date": lnow.date().isoformat(),
        "window": window,
        "updated": f"Updated {lnow.day} {lnow:%B %Y}, {lnow:%H:%M} {lnow.tzname()}",
        "stories": stories,
    }


def render(edition: dict) -> str:
    tpl = TEMPLATE.read_text()
    payload = json.dumps(edition, indent=2, ensure_ascii=False).replace("</", "<\\/")
    return tpl.replace("__EDITION_JSON__", payload)


def main() -> None:
    edition = build()
    if not edition["stories"]:
        sys.exit("No stories found and no previous edition to fall back on.")
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "index.html").write_text(render(edition))
    (OUT_DIR / "news.json").write_text(json.dumps(edition, indent=2, ensure_ascii=False))
    NEWS_FILE.write_text(json.dumps(edition, indent=2, ensure_ascii=False) + "\n")
    print(f"Built {len(edition['stories'])} stories. Top: {edition['stories'][0]['title']}")


if __name__ == "__main__":
    main()
