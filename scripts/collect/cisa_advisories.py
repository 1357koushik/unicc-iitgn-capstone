"""CISA joint cybersecurity advisories, AA/CSA series (role: incident).

Enumeration: the public RSS feed of cybersecurity advisories, keeping items whose URL slug is an
`aaYY-NNNx` identifier; each advisory page is then fetched and reduced to plain text.

STATUS: cisa.gov answers every automated request with an Akamai "Access Denied" (HTTP 403), including
robots.txt, from the project PC. The collector does NOT try to evade that block (no browser
impersonation, no mirrors). It records the source as unavailable. The parsers below are unit-tested on
fixtures only and have never run against the live site.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

import httpx

from collect_common import (USER_AGENT, Context, SourceSpec, SourceUnavailable, find_cves, http_download)

FEED = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
SPEC = SourceSpec(
    name="cisa_advisories",
    role="incident",
    urls=[FEED, "https://www.cisa.gov/news-events/cybersecurity-advisories"],
    license_name="US Government work (CISA website content; verify per-page notices)",
    license_url="https://www.cisa.gov/about/website-policies",
    license_note=("CISA publishes advisories for public use; reading them to write original narrative queries is "
                  "fine. Quote sparingly and credit CISA; third-party images/logos may carry their own rights."),
    description="Joint CSA/AA advisories mentioning CVE ids (not KEV). Unavailable when cisa.gov blocks automation.",
)

_AA_SLUG = re.compile(r"/(aa\d{2}-\d{3}[a-z]?)(?:$|[/?#])", re.IGNORECASE)


def parse_feed(xml_text: str) -> list[dict]:
    """RSS -> [{advisory_id, title, url, published}] for AA-series items only."""
    root = ET.fromstring(xml_text)
    out = []
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        m = _AA_SLUG.search(link)
        if not m:
            continue
        out.append({"advisory_id": m.group(1).upper(), "title": (item.findtext("title") or "").strip(),
                    "url": link, "published": (item.findtext("pubDate") or "").strip()})
    return out


class _Text(HTMLParser):
    _SKIP = {"script", "style", "nav", "header", "footer", "noscript"}

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        elif tag in ("p", "br", "li", "h1", "h2", "h3", "h4", "tr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _Text()
    p.feed(html)
    text = "".join(p.parts)
    return re.sub(r"\n\s*\n+", "\n\n", re.sub(r"[ \t\r\f\v]+", " ", text)).strip()


def collect(ctx: Context):
    try:
        r = httpx.get(FEED, follow_redirects=True, timeout=60, headers={"User-Agent": USER_AGENT})
    except httpx.HTTPError as e:
        raise SourceUnavailable(f"cisa.gov not reachable: {type(e).__name__}: {e}")
    if r.status_code in (401, 403):
        raise SourceUnavailable(
            f"cisa.gov returned HTTP {r.status_code} (Akamai Access Denied) to automated requests for the RSS "
            "feed, advisory pages and robots.txt; not circumvented. Owner decision needed (manual export, or "
            "accept a different incident source).")
    r.raise_for_status()
    (ctx.raw_dir / "all.xml").write_bytes(r.content)
    items = parse_feed(r.text)
    ctx.extra["enumeration"] = f"RSS feed {FEED}, AA-series slugs only; {len(items)} items"
    for it in items:
        dest = ctx.raw_dir / "pages" / (it["advisory_id"] + ".html")
        http_download(it["url"], dest)
        text = html_to_text(dest.read_text(encoding="utf-8", errors="replace"))
        cves = ctx.cves(find_cves(text))
        if not cves:
            continue
        yield {**it, "text": text, "cve_ids": cves}
