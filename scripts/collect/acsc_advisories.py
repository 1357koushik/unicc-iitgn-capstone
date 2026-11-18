"""Australian Cyber Security Centre alerts and advisories, cyber.gov.au (role: incident).

Replaces the blocked `cisa_advisories` source (kept as documentation of the block). The ACSC republishes the joint
advisories (CISA, NSA, FBI, NCSC, ...) and issues its own alerts about exploited vulnerabilities.

Enumeration: the site's "Alerts and advisories" listing (`/about-us/view-all-content/alerts-and-advisories?page=N`)
and its archive (`/archived-alerts-and-advisories?page=N`), each paged until an empty page, plus the RSS feeds
`/rss/advisories` and `/rss/alerts` (advertised on /terms-of-use). Faceted listing URLs are not used. Every
`/advisory/...` and `/alert/...` page found is fetched, newest listing entries first, reduced to plain text and kept
when it mentions a CVE or describes threat-actor activity (web_common.KEEP_RULE).

Access policy: honest research User-Agent, robots.txt fetched and honoured, one request per second, retries with
backoff. HTTP 401/403 or a challenge page stops the run with status `unavailable`.
"""
from __future__ import annotations

import hashlib
import re

from collect_common import Context, SourceSpec, SourceUnavailable
from web_common import (KEEP_RULE, PoliteFetcher, build_record, canonical_link, extract_page,
                        page_identity_problem, parse_rss, safe_name)

SITE = "https://www.cyber.gov.au"
LISTINGS = [SITE + "/about-us/view-all-content/alerts-and-advisories", SITE + "/archived-alerts-and-advisories"]
FEEDS = [SITE + "/rss/advisories", SITE + "/rss/alerts"]
LICENCE_URL = SITE + "/copyright"
MAX_LISTING_PAGES = 80
MAX_ARTICLES = 500

SPEC = SourceSpec(
    name="acsc_advisories",
    role="incident",
    urls=[LISTINGS[0], LISTINGS[1], FEEDS[0], FEEDS[1]],
    license_name="Creative Commons Attribution 4.0 International (CC BY 4.0)",
    license_url=LICENCE_URL,
    license_note=("Site copyright page states all material is under CC BY 4.0 except the Commonwealth Coat of Arms, "
                  "the ACSC logo, third-party content and material marked otherwise. Reuse and adaptation are allowed "
                  "with attribution (ASD's ACSC, cyber.gov.au) and a link to the licence; indicate changes."),
    description=("ACSC alerts and (joint) advisories with CVE ids or threat-actor activity; stands in for the "
                 "blocked CISA advisories."),
)

_ITEM = re.compile(r'href="(/(?:alert|advisory)/[^"?#/]+)', re.IGNORECASE)


def parse_listing(html: str) -> list[str]:
    """Listing page -> advisory/alert paths in page order (deduplicated, case-insensitive)."""
    seen, out = set(), []
    for m in _ITEM.finditer(html):
        path = m.group(1)
        if path.lower() not in seen:
            seen.add(path.lower())
            out.append(path)
    return out


def doc_type_of(url: str) -> str:
    return "advisory" if "/advisory/" in url.lower() else "alert"


def parse_article(html: str) -> dict:
    return extract_page(html, roots=("article",), title_suffix="| CGA")


def collect(ctx: Context):
    f = PoliteFetcher(SITE, ctx.raw_dir)
    try:
        ctx.extra["robots_txt"] = f.check_robots()
        ctx.extra["licence_verified"] = {
            "page": LICENCE_URL, "statement": "All material presented on this website is provided under a "
            "Creative Commons Attribution 4.0 International licence, with listed exceptions",
            "verified_at": "collector run (page text read manually on 2026-11-14)"}
        ctx.extra["keep_rule"] = KEEP_RULE

        # ---- enumerate
        candidates: dict[str, dict] = {}  # lower-case path -> info, insertion order = newest first
        listing_pages = 0
        listing_failed: list[dict] = []
        for base in LISTINGS:
            for page in range(MAX_LISTING_PAGES):
                url = f"{base}?page={page}"
                try:
                    html, raw = f.get_text(url)
                except PoliteFetcher.Unreachable as e:
                    listing_failed.append({"url": url, "error": str(e)[:120]})
                    continue
                f.save_gz(f"listing/{safe_name(base.rsplit('/', 1)[-1])}_{page:03d}.html", raw)
                paths = parse_listing(html)
                listing_pages += 1
                ctx.log(f"listing {base.rsplit('/', 1)[-1]} page {page}: {len(paths)} items")
                if not paths:
                    break
                for p in paths:
                    candidates.setdefault(p.lower(), {"path": p, "summary": "", "published": "", "title": ""})
        feed_items = 0
        for feed in FEEDS:
            xml, raw = f.get_text(feed)
            f.save_gz(f"feed/{safe_name(feed.rsplit('/', 1)[-1])}.xml", raw)
            for it in parse_rss(xml):
                feed_items += 1
                key = it["url"].replace(SITE, "").lower()
                c = candidates.setdefault(key, {"path": it["url"].replace(SITE, ""), "summary": "", "published": "",
                                                "title": ""})
                c.update({k: it[k] for k in ("summary", "published", "title")})
        order = list(candidates.values())[:MAX_ARTICLES]
        enum_sha = hashlib.sha256("\n".join(c["path"] for c in order).encode()).hexdigest()
        ctx.upstream["sha256"] = enum_sha
        ctx.upstream["enumeration_sha256"] = enum_sha
        ctx.extra["enumeration"] = (f"listing pages ({listing_pages} fetched: current + archived, ?page=N until empty) "
                                    f"plus RSS feeds ({feed_items} items); {len(order)} advisory/alert pages")
        ctx.log(f"{len(order)} candidate pages from {listing_pages} listing pages")

        # ---- fetch articles
        failed, kept, skipped = [], [], 0
        mismatched: list[dict] = []
        for i, c in enumerate(order, 1):
            url = SITE + c["path"] if c["path"].startswith("/") else c["path"]
            try:
                html, final_url, raw = f.get_page(url)
            except PoliteFetcher.Gone as e:
                failed.append({"url": url, "error": str(e)[:120]})
                continue
            f.save_gz(f"pages/{safe_name(c['path'].rsplit('/', 1)[-1])}.html", raw)
            art = parse_article(html)
            problem = page_identity_problem(url, final_url, art["text"], canonical_link(html), art["title"])
            if problem:  # one re-fetch rules out a transient mix-up; a repeat is dropped, never stored under this id
                try:
                    html, final_url, raw = f.get_page(url)
                    art = parse_article(html)
                    problem = page_identity_problem(url, final_url, art["text"], canonical_link(html), art["title"])
                except PoliteFetcher.Gone:
                    pass
            if problem:
                mismatched.append({"url": url, "final_url": final_url, "page_title": art["title"], "reason": problem})
                ctx.log(f"DROPPED {url}: {problem}")
                continue
            rec = build_record(SPEC.name, doc_type_of(url), url, art, c, ctx.cves)
            if rec is None:
                skipped += 1
            else:
                kept.append(rec)
            if i % 25 == 0:
                ctx.log(f"{i}/{len(order)} fetched, {len(kept)} kept")
        ctx.extra.update({"listing_pages_unreachable": listing_failed, "pages_fetched": len(order) - len(failed), "pages_gone": failed, "pages_dropped_identity_mismatch": mismatched,
                          "pages_dropped_by_keep_rule": skipped, "http_requests": f.requests})
        if len(failed) > max(5, len(order) // 10):
            raise SourceUnavailable(f"{len(failed)} of {len(order)} advisory pages were not retrievable", "unavailable")
        kept.sort(key=lambda r: (r["published"], r["url"]), reverse=True)
        yield from kept
    finally:
        f.close()
