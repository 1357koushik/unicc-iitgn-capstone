"""UK National Cyber Security Centre advisories, news and reports on threat activity, ncsc.gov.uk (role: incident).

Joint advisories (e.g. with CISA and the Five Eyes partners) are published by the NCSC as /news/ items (titles such as
"Advisory: ...", "Alert: ..."), /report/ items (malware analysis reports, assessments) and /blog-post/ items.

Enumeration: the NCSC RSS feeds (`/api/1/services/v1/all-rss-feed.xml`, `news-rss-feed.xml`, `report-rss-feed.xml`;
20 newest items each, they supply dates and summaries) plus the XML sitemap (`/sitemap.xml?page=1..N`, restricted to
the /news/, /report/ and /blog-post/ sections). Feed items come first, the rest follow in descending sitemap
lastmod. Each page is fetched, reduced to plain text and kept when it mentions a CVE or describes threat-actor
activity (web_common.KEEP_RULE).

Access policy: honest research User-Agent, robots.txt fetched and honoured (the site answers 404 for it, which means
no restrictions), one request per second, retries with backoff. HTTP 401/403 or a challenge page stops the run with
status `unavailable`.
"""
from __future__ import annotations

import hashlib
import re

from collect_common import Context, SourceSpec, SourceUnavailable
from web_common import (KEEP_RULE, PoliteFetcher, build_record, extract_page, parse_rss, parse_sitemap, safe_name)

SITE = "https://www.ncsc.gov.uk"
FEEDS = [SITE + "/api/1/services/v1/all-rss-feed.xml", SITE + "/api/1/services/v1/news-rss-feed.xml",
         SITE + "/api/1/services/v1/report-rss-feed.xml"]
SITEMAP = SITE + "/sitemap.xml"
SECTIONS = ("news", "report", "blog-post")
LICENCE_URL = SITE + "/section/about-this-website/terms-and-conditions"
MAX_SITEMAP_PAGES = 20
MAX_ARTICLES = 700

SPEC = SourceSpec(
    name="ncsc_uk_advisories",
    role="incident",
    urls=[SITEMAP, *FEEDS],
    license_name="Open Government Licence v3.0 (OGL v3.0)",
    license_url="https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/",
    license_note=("NCSC terms and conditions: site content may be used or reused without prior permission under OGL "
                  "v3.0 provided the source is acknowledged (NCSC, ncsc.gov.uk) with a link to the licence; "
                  "third-party material, logos and images may carry other terms."),
    description="NCSC UK news, advisories, reports and blog posts with CVE ids or threat-actor activity.",
)


def section_of(url: str) -> str | None:
    m = re.match(r"https?://[^/]+/([^/?#]+)/[^/?#]+/?$", url)
    return m.group(1) if m and m.group(1) in SECTIONS else None


def parse_article(html: str) -> dict:
    return extract_page(html, roots=("main", "article"))


def collect(ctx: Context):
    f = PoliteFetcher(SITE, ctx.raw_dir)
    try:
        ctx.extra["robots_txt"] = f.check_robots()
        ctx.extra["licence_verified"] = {
            "page": LICENCE_URL, "statement": "you may use or reuse the content published on the Websites without "
            "prior permission but must adhere to and accept the terms of the Open Government Licence (OGL) v3.0",
            "verified_at": "collector run (page text read manually on 2026-11-14)"}
        ctx.extra["keep_rule"] = KEEP_RULE

        # ---- enumerate
        cand: dict[str, dict] = {}
        feed_items = 0
        for feed in FEEDS:
            xml, raw = f.get_text(feed)
            f.save_gz(f"feed/{safe_name(feed.rsplit('/', 1)[-1])}", raw)
            for it in parse_rss(xml):
                feed_items += 1
                if section_of(it["url"]):
                    cand.setdefault(it["url"], {"summary": it["summary"], "published": it["published"],
                                                "title": it["title"]})
        idx_xml, raw = f.get_text(SITEMAP)
        f.save_gz("sitemap/index.xml", raw)
        pages = [loc for loc, _ in parse_sitemap(idx_xml) if "sitemap.xml" in loc][:MAX_SITEMAP_PAGES]
        urlset: list[tuple[str, str]] = []
        for n, loc in enumerate(pages, 1):
            xml, raw = f.get_text(loc)
            f.save_gz(f"sitemap/page_{n:02d}.xml", raw)
            urlset += parse_sitemap(xml)
        urlset.sort(key=lambda t: t[1], reverse=True)
        for loc, _lm in urlset:
            if section_of(loc):
                cand.setdefault(loc, {"summary": "", "published": "", "title": ""})
        order = list(cand.items())[:MAX_ARTICLES]
        enum_sha = hashlib.sha256("\n".join(u for u, _ in order).encode()).hexdigest()
        ctx.upstream["sha256"] = enum_sha
        ctx.upstream["enumeration_sha256"] = enum_sha
        ctx.extra["enumeration"] = (f"RSS feeds ({feed_items} items) then XML sitemap ({len(pages)} pages, "
                                    f"{len(urlset)} URLs) restricted to /{', /'.join(SECTIONS)}/; "
                                    f"{len(order)} candidate pages")
        ctx.log(f"{len(order)} candidate pages")

        # ---- fetch articles
        failed, kept, skipped = [], [], 0
        for i, (url, info) in enumerate(order, 1):
            try:
                html, raw = f.get_text(url)
            except PoliteFetcher.Gone as e:
                failed.append({"url": url, "error": str(e)[:120]})
                continue
            f.save_gz(f"pages/{section_of(url)}__{safe_name(url.rstrip('/').rsplit('/', 1)[-1])}.html", raw)
            rec = build_record(SPEC.name, section_of(url) or "", url, parse_article(html), info, ctx.cves)
            if rec is None:
                skipped += 1
            else:
                kept.append(rec)
            if i % 25 == 0:
                ctx.log(f"{i}/{len(order)} fetched, {len(kept)} kept")
        ctx.extra.update({"pages_fetched": len(order) - len(failed), "pages_gone": failed,
                          "pages_dropped_by_keep_rule": skipped, "http_requests": f.requests})
        if len(failed) > max(5, len(order) // 10):
            raise SourceUnavailable(f"{len(failed)} of {len(order)} advisory pages were not retrievable", "unavailable")
        kept.sort(key=lambda r: (r["published"], r["url"]), reverse=True)
        yield from kept
    finally:
        f.close()
