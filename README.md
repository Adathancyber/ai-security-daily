# AI Security Daily

A web page that shows the ten most relevant news stories about AI in security and exposure management. It rebuilds itself every morning.

## How it works

1. A GitHub Action runs every day at 05:13 UTC (05:13 London time in winter, 06:13 in summer). You can also run it by hand from the **Actions** tab with **Run workflow**.
2. `scripts/build.py` reads the security news feeds in `data/feeds.json`, keeps stories from the last seven days that mention AI, and scores each one. Exposure management signals (exposed assets and credentials, attack paths, vulnerability prioritisation, CTEM) count the most, then AI-driven threats and AI vulnerability research, then industry news. Newer stories score higher.
3. The top ten go into the page and are published to GitHub Pages. Today's list is also saved in `data/news.json`, which fills gaps if a feed is down.

## Changing it

- Add or remove news sources in `data/feeds.json`.
- Tune the keywords and weights at the top of `scripts/build.py`.
- Change the look in `site/template.html`.

Run it locally with `python scripts/build.py`, then open `public/index.html`. Tests: `python tests/test_build.py`.
