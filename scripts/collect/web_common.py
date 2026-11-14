"""Polite web-collection helpers shared by the national-CERT advisory collectors (B1b).

* `PoliteFetcher`: honest User-Agent, robots.txt check, at most one request per second, retries with
  backoff. A refusal (401/403) or a bot-challenge page raises `SourceUnavailable`; it is never worked around.
* `parse_rss`, `parse_sitemap`: feed and sitemap readers.
* `extract_page`: reduce an HTML page to title, first `<time>` date and boilerplate-free plain text.
* `actor_mentions`, `keep_reason`: the rule that decides which advisories are kept.

Standard library plus httpx only.
"""
from __future__ import annotations

import email.utils
import gzip
import hashlib
import html as _html
import re
import time
import urllib.robotparser
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from collect_common import USER_AGENT, CollectError, SourceUnavailable, _backoff, find_cves

MIN_INTERVAL = 1.0  # seconds between requests, per fetcher

# --------------------------------------------------------------------------
# Keep rule
# --------------------------------------------------------------------------
_ACTOR = re.compile(
    r"\b(threat actors?|cyber actors?|malicious (?:cyber )?actors?|APT ?\d{1,3}|"
    r"state[- ](?:sponsored|backed|linked|supported|affiliated)|nation[- ]state|"
    r"ransomware (?:group|gang|actor|operator|affiliate)s?|espionage|threat groups?|intrusion sets?|"
    r"threat activity|cyber espionage)\b",
    re.IGNORECASE)
ACTOR_MIN_MENTIONS = 2

KEEP_RULE = ("keep an advisory when its text mentions at least one well-formed CVE id, OR mentions "
             f"threat-actor activity at least {ACTOR_MIN_MENTIONS} times (terms: threat/cyber/malicious actor(s), "
             "APTnn, state-sponsored/linked/backed/supported, nation-state, ransomware group/gang/actor, "
             "espionage, threat group, intrusion set, threat activity); keep_reason is 'cve', 'actor' or 'cve+actor'")


def actor_mentions(text: str) -> int:
    return len(_ACTOR.findall(text or ""))


def keep_reason(text: str, cves: list[str]) -> str | None:
    actor = actor_mentions(text) >= ACTOR_MIN_MENTIONS
    if cves and actor:
        return "cve+actor"
    if cves:
        return "cve"
    if actor:
        return "actor"
    return None


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------
def parse_rss(xml_text: str) -> list[dict]:
    """RSS 2.0 -> [{title, url, published (YYYY-MM-DD or ''), summary}] in feed order."""
    root = ET.fromstring(xml_text.lstrip("﻿").encode("utf-8"))
    out = []
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        if not link:
            continue
        out.append({"title": (item.findtext("title") or "").strip(), "url": link,
                    "published": rfc822_to_date(item.findtext("pubDate")),
                    "summary": (item.findtext("description") or "").strip()})
    return out


def rfc822_to_date(value: str | None) -> str:
    if not value or not value.strip():
        return ""
    try:
        dt = email.utils.parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return ""
    return dt.date().isoformat()


def parse_sitemap(xml_text: str) -> list[tuple[str, str]]:
    """Sitemap or sitemap index -> [(loc, lastmod or '')]."""
    root = ET.fromstring(xml_text.lstrip("﻿").encode("utf-8"))
    out = []
    for el in root:
        loc = lastmod = ""
        for child in el:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "loc":
                loc = (child.text or "").strip()
            elif tag == "lastmod":
                lastmod = (child.text or "").strip()
        if loc:
            out.append((loc, lastmod))
    return out


_SKIP = {"script", "style", "nav", "header", "footer", "aside", "form", "button", "svg", "noscript",
         "dialog", "select", "iframe"}
_BLOCK = {"p", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "div", "section", "table", "ul", "ol",
          "blockquote", "pre", "dt", "dd"}
_BOILERPLATE_LINES = re.compile(
    r"^(Download (?:&|and) print article PDF|Share|Print|Listen|Back to top|Skip to (?:main )?content|"
    r"Was this page helpful\??|Yes|No|Contents|On this page|Last updated.*|Related (?:content|links|advice).*)$",
    re.IGNORECASE)


class _PageParser(HTMLParser):
    """Collect <h1>, first <time datetime> and block-structured text inside the first root element."""

    def __init__(self, roots: tuple[str, ...]):
        super().__init__(convert_charrefs=True)
        self.roots = roots
        self.root_tag: str | None = None
        self.root_depth = 0
        self.done = False
        self.skip = 0
        self.parts: list[str] = []
        self.h1: list[str] = []
        self._in_h1 = 0
        self.time: str | None = None
        self.title_tag: list[str] = []
        self._in_title = False
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta":
            key = a.get("property") or a.get("name")
            if key and a.get("content"):
                self.meta.setdefault(key, a["content"])
            return
        if tag == "title":
            self._in_title = True
        if self.done:
            return
        if self.root_tag is None:
            if tag in self.roots:
                self.root_tag, self.root_depth = tag, 1
            return
        if tag == self.root_tag:
            self.root_depth += 1
        if tag == "time" and self.time is None and a.get("datetime"):
            self.time = a["datetime"]
        if tag in _SKIP:
            self.skip += 1
            return
        if tag == "h1":
            self._in_h1 += 1
        if tag in _BLOCK and not self.skip:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if self.done or self.root_tag is None:
            return
        if tag in _SKIP and self.skip:
            self.skip -= 1
            return
        if tag == "h1" and self._in_h1:
            self._in_h1 -= 1
        if tag in _BLOCK and not self.skip:
            self.parts.append("\n")
        if tag == self.root_tag:
            self.root_depth -= 1
            if self.root_depth == 0:
                self.done = True

    def handle_data(self, data):
        if self._in_title:
            self.title_tag.append(data)
        if self.done or self.root_tag is None:
            return
        if self._in_h1:
            self.h1.append(data)
        if not self.skip:
            self.parts.append(data)


_TAIL_MARKER = re.compile(r"^(Was this (?:article|page|post) helpful\??|Also see|Downloads|Share and print this article|Share on ?\w*|Related (?:content|links))$",
                          re.IGNORECASE)
_LEAD_TAG = re.compile(r"^(News|Report|Blog post|Guidance|Advisory|Alert|Speech|Paper)$", re.IGNORECASE)


def _clean(parts: list[str], title: str = "") -> str:
    text = "".join(parts).replace("\xa0", " ")
    lines = [re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in text.split("\n")]
    for i, ln in enumerate(lines):  # drop page furniture after the body (feedback widget, related links)
        if i > 3 and _TAIL_MARKER.match(ln):
            lines = lines[:i]
            break
    keep = [ln for ln in lines if not _BOILERPLATE_LINES.match(ln) and not (title and ln == title)]
    while keep and (not keep[0] or _LEAD_TAG.match(keep[0])):
        keep.pop(0)
    return re.sub(r"\n\s*\n+", "\n\n", "\n".join(keep)).strip()


def extract_page(html: str, roots: tuple[str, ...] = ("article", "main"), title_suffix: str = "") -> dict:
    """HTML -> {title, published (YYYY-MM-DD or ''), text}. `roots` lists candidate content elements, in order
    of preference; the first root that exists and yields text is used. Navigation, headers, footers, sidebars,
    forms, scripts and SVG inside it are dropped."""
    result = {"title": "", "published": "", "text": ""}
    for root in roots:
        p = _PageParser((root,))
        p.feed(html)
        title = re.sub(r"\s+", " ", "".join(p.h1)).strip()
        text = _clean(p.parts, title)
        if not title:
            title = (p.meta.get("og:title") or "".join(p.title_tag)).strip()
            if title_suffix and title.endswith(title_suffix):
                title = title[: -len(title_suffix)].strip()
        pub = ""
        if p.time:
            m = re.match(r"\d{4}-\d{2}-\d{2}", p.time)
            pub = m.group(0) if m else ""
        if not pub:
            m = re.match(r"\d{4}-\d{2}-\d{2}", p.meta.get("article:published_time", ""))
            pub = m.group(0) if m else ""
        if text:
            return {"title": _html.unescape(title), "published": pub, "text": text}
        result = {"title": _html.unescape(title), "published": pub, "text": ""}
    return result


_CHALLENGE = re.compile(r"(just a moment\.\.\.|attention required|access denied|verify you are (?:a )?human|"
                        r"captcha|checking your browser|bot (?:detection|protection))", re.IGNORECASE)


def looks_like_challenge(text: str) -> bool:
    """True for bot-challenge / access-denied interstitials (checked against <title> and a short head only)."""
    m = re.search(r"<title[^>]*>(.*?)</title>", text[:20000], re.S | re.IGNORECASE)
    title = m.group(1) if m else ""
    return bool(_CHALLENGE.search(title)) or (len(text) < 3000 and bool(_CHALLENGE.search(text)))


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------
class PoliteFetcher:
    """GET with robots.txt compliance, >= MIN_INTERVAL between requests, retry/backoff.

    Raises SourceUnavailable on 401/403 or a challenge page (no workaround is attempted) and
    FetchGone on 404/410 (the single page is simply skipped by callers).
    """

    class Gone(CollectError):
        pass

    class Unreachable(Gone):
        """Retries exhausted (5xx, timeouts): the single page is skipped and recorded in the manifest."""

    def __init__(self, site: str, raw_dir: Path, retries: int = 5, timeout: float = 90.0,
                 min_interval: float = MIN_INTERVAL):
        import httpx

        self.site = site.rstrip("/")
        self.raw_dir = raw_dir
        self.retries = retries
        self.min_interval = min_interval
        self._last = 0.0
        self.requests = 0
        self.timeout = timeout
        self.client = httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": USER_AGENT})
        self.robots: urllib.robotparser.RobotFileParser | None = None
        self.robots_info: dict[str, Any] = {}

    def close(self) -> None:
        self.client.close()

    def _wait(self) -> None:
        dt = time.monotonic() - self._last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last = time.monotonic()

    def _get(self, url: str, check_robots: bool = True):
        import httpx

        if check_robots and self.robots is not None and not self.robots.can_fetch(USER_AGENT, url):
            raise SourceUnavailable(f"robots.txt disallows {url} for our user agent; not fetched")
        last = "unknown error"
        for attempt in range(self.retries):
            self._wait()
            self.requests += 1
            try:
                r = self.client.get(url)
            except httpx.HTTPError as e:
                last = f"{type(e).__name__}: {e}"
                self.client.close()  # a stalled keep-alive connection must not be reused
                self.client = httpx.Client(follow_redirects=True, timeout=self.timeout, headers={"User-Agent": USER_AGENT})
            else:
                if r.status_code in (401, 403):
                    raise SourceUnavailable(
                        f"{self.site} answered HTTP {r.status_code} to an automated request for {url}; "
                        "treated as a block and not circumvented (no other user agents, proxies or caches tried).")
                if r.status_code in (404, 410):
                    raise PoliteFetcher.Gone(f"GET {url}: HTTP {r.status_code}")
                if r.status_code == 429 or r.status_code >= 500:
                    last = f"HTTP {r.status_code}"
                elif r.status_code >= 400:
                    raise CollectError(f"GET {url} failed: HTTP {r.status_code}")
                else:
                    if "text" in r.headers.get("content-type", "text/html") and looks_like_challenge(r.text):
                        raise SourceUnavailable(
                            f"{self.site} served a bot-challenge/access-denied page for {url}; not circumvented.")
                    return r
            if attempt < self.retries - 1:
                wait = _backoff(attempt)
                print(f"  retry {attempt + 1}/{self.retries - 1} for {url} in {wait:.0f}s ({last})", flush=True)
                time.sleep(wait)
        raise PoliteFetcher.Unreachable(f"GET {url} failed after {self.retries} attempts: {last}")

    # ---- public API
    def check_robots(self) -> dict[str, Any]:
        """Fetch and parse robots.txt (200 = parse, 404 = no restrictions per RFC 9309). 401/403 = blocked."""
        url = self.site + "/robots.txt"
        try:
            r = self._get(url, check_robots=False)
        except PoliteFetcher.Gone:
            self.robots = urllib.robotparser.RobotFileParser()
            self.robots.parse([])
            self.robots_info = {"url": url, "http_status": 404, "result": "no robots.txt (404): no restrictions",
                                "sha256": None, "disallow_rules": 0}
            return self.robots_info
        body = r.content
        self.robots = urllib.robotparser.RobotFileParser()
        self.robots.parse(r.text.splitlines())
        n_dis = len(re.findall(r"^\s*disallow\s*:\s*\S", r.text, re.IGNORECASE | re.MULTILINE))
        (self.raw_dir).mkdir(parents=True, exist_ok=True)
        (self.raw_dir / "robots.txt").write_bytes(body)
        self.robots_info = {"url": url, "http_status": r.status_code, "sha256": hashlib.sha256(body).hexdigest(),
                            "disallow_rules": n_dis,
                            "result": "fetched and parsed; every URL requested is checked against it"}
        return self.robots_info

    def get_text(self, url: str) -> tuple[str, bytes]:
        text, _, raw = self.get_page(url)
        return text, raw

    def get_page(self, url: str) -> tuple[str, str, bytes]:
        """-> (decoded text, final URL after redirects, raw bytes)."""
        r = self._get(url)
        return self._decode(r), str(getattr(r, "url", url)), r.content

    @staticmethod
    def _decode(r) -> str:
        return decode_body(r.content, r.headers.get("content-type", ""))

    def save_gz(self, rel: str, content: bytes) -> dict[str, Any]:
        """Store a raw page gzip-compressed under raw/<rel>.gz; return {path, bytes, sha256 of the raw body}."""
        dest = self.raw_dir / (rel + ".gz")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(gzip.compress(content, 6, mtime=0))
        return {"path": rel + ".gz", "sha256": hashlib.sha256(content).hexdigest()}


_META_CHARSET = re.compile(rb"""<meta[^>]+?charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.IGNORECASE)
_HDR_CHARSET = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9_.:-]+)", re.IGNORECASE)


def decode_body(content: bytes, content_type: str = "") -> str:
    """Bytes -> text without ever producing U+FFFD from a mis-guessed charset.

    Order: BOM, HTTP Content-Type charset, `<meta charset>` in the first 4 KiB, then UTF-8. A declared charset
    that cannot decode the bytes falls back to UTF-8, then Windows-1252 (smart quotes), then per-byte Latin-1
    for bytes cp1252 leaves undefined. Declared latin-1/ASCII is read as Windows-1252, as browsers do.
    """
    import codecs

    if content.startswith(codecs.BOM_UTF8):
        return content[3:].decode("utf-8", "replace")
    declared = None
    m = _HDR_CHARSET.search(content_type or "")
    if m:
        declared = m.group(1)
    else:
        m2 = _META_CHARSET.search(content[:4096])
        if m2:
            declared = m2.group(1).decode("ascii", "ignore")
    candidates: list[str] = []
    if declared:
        d = declared.lower()
        if d in ("iso-8859-1", "latin1", "latin-1", "us-ascii", "ascii", "windows-1252", "cp1252"):
            d = "cp1252"
        try:
            codecs.lookup(d)
            candidates.append(d)
        except LookupError:
            pass
    candidates += ["utf-8", "cp1252"]
    for enc in candidates:
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    return "".join(_cp1252_byte(b) for b in content)


def _cp1252_byte(b: int) -> str:
    try:
        return bytes([b]).decode("cp1252")
    except UnicodeDecodeError:
        return chr(b)


def slug_of(url: str) -> str:
    return url.split("#", 1)[0].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]


def page_identity_problem(listed_url: str, final_url: str, text: str, canonical: str = "", title: str = "") -> str | None:
    """Reason string when a fetched page does not belong to the listed advisory, else None.

    Checks (case-insensitive): the final URL's slug equals the listed slug (no redirect to another page); the
    canonical link, when present, has the same slug; and a CVE id embedded in the slug appears in the page text.
    """
    want = slug_of(listed_url).lower()
    got = slug_of(final_url).lower()
    if got != want:
        return f"redirected to a different page: listed slug {want!r}, final URL {final_url}"
    if canonical and slug_of(canonical).lower() != want:
        return f"canonical link {canonical} does not match listed slug {want!r}"
    slug_cves = {c.upper() for c in re.findall(r"cve-\d{4}-\d{4,}", want)}
    if slug_cves:
        haystack = f"{title}\n{text or ''}"  # tolerate "CVE 2023-4966" and a CVE named only in the title
        page_cves = {f"CVE-{y}-{n}" for y, n in re.findall(r"CVE[-\s](\d{4})-(\d{4,})", haystack, re.IGNORECASE)}
        missing = sorted(slug_cves - page_cves)
        if missing:
            return (f"slug names {', '.join(missing)} but neither the page title nor text mentions it "
                    "(page content belongs to another advisory)")
    return None


def canonical_link(html: str) -> str:
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]*href=["\']([^"\']+)', html[:200000], re.IGNORECASE)
    return m.group(1) if m else ""


def safe_name(slug: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", slug)[:150]


def build_record(source: str, doc_type: str, url: str, extracted: dict, fallback: dict, cves_fn) -> dict | None:
    """Apply the keep rule; returns the record dict or None."""
    text = extracted["text"]
    cves = cves_fn(find_cves(text))
    reason = keep_reason(text, cves)
    if reason is None:
        return None
    slug = url.rstrip("/").rsplit("/", 1)[-1]
    return {
        "advisory_id": slug, "doc_type": doc_type, "source": source, "url": url,
        "title": extracted["title"] or fallback.get("title", ""),
        "published": extracted["published"] or fallback.get("published", ""),
        "summary": fallback.get("summary", ""),
        "text": text, "cve_ids": cves, "keep_reason": reason,
    }

