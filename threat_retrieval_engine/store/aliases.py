"""Alias extraction for the C1 document store.

An alias is a short human name for a CVE taken from public exploit and advisory metadata. Allowed inputs
(the leakage firewall of plan 6.1 / 4.3):

* ``exploitdb``          - Exploit-DB titles
* ``metasploit_modules`` - Metasploit module names, plus "known as X" phrases in module descriptions
* ``nuclei_templates``   - nuclei template names
* ``kev``                - CISA KEV vulnerability names
* ``cve_list``           - CVE List (CNA) titles
* ``cve_description``    - "aka X" / "known as X" phrases in the CVE's own English description

Benchmark query sources (ghsa_reviewed, et_open_rules, sigma_rules, acsc_advisories, ncsc_uk_advisories,
cisa_advisories) and anything under data/benchmark/ are never read: `candidates_from_record` refuses any
source outside `ALLOWED_SOURCES`, and a test proves no alias row can come from a query-side source.

Kinds of alias row:

* ``nickname``    - a coined vulnerability name ("EternalBlue", "Dirty COW", "Log4Shell") found in a
  nickname position: a quoted or parenthesised span, a CamelCase / letter-digit compound token, or an
  "aka X" / "known as X" phrase;
* ``advisory_id`` - a vendor bulletin identifier used as a name (Microsoft "MS17-010");
* ``title``       - an exploit source's own name for the CVE (Exploit-DB title, Metasploit module name,
  nuclei template name), kept when it says more than generic flaw words and the CVE's own vendor/product.

No nickname list is written by hand: names come only from the sources. What is written by hand is the
vocabulary that makes a span generic (flaw words, exploit-site packaging, platforms, connectives). The
rest is decided from the data, in two steps:

1. per CVE (in the build worker, which has the CVE's records): is the candidate one of the CVE's own
   vendor/product/package/module names, and does the CVE's own description name it as a component
   ("via the Name parameter", "the DirectWrite component") rather than as a nickname ("aka Heartbleed")?
2. corpus-wide (in the build master): a nickname must not spread over many CVEs (product names do), the
   CVEs it names must cluster in time (a coined name belongs to one disclosure), a bare CamelCase token
   must not be a known CPE product name, and a CVE that only shares a multi-CVE exploit record with the
   CVE the name really belongs to is dropped (relative support).
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .text import alias_norm, clean_text, find_span

ALLOWED_SOURCES = ("exploitdb", "metasploit_modules", "nuclei_templates", "kev", "cve_list", "cve_description")
QUERY_SIDE_SOURCES = frozenset({"ghsa_reviewed", "et_open_rules", "sigma_rules", "acsc_advisories",
                                "ncsc_uk_advisories", "cisa_advisories"})
TITLE_KIND_SOURCES = frozenset({"exploitdb", "metasploit_modules", "nuclei_templates"})

# Thresholds (recorded in the build manifest).
MAX_NICKNAME_SPREAD = 12        # a name attached to more CVEs than this is a product or component name
YEAR_WINDOW = 2                 # the CVEs a nickname names must fall inside 2 consecutive ID years ...
MIN_WINDOW_SHARE = 0.75         # ... for at least this share of them
MIN_RELATIVE_SUPPORT = 0.3      # support of a CVE relative to the best-supported CVE of the same name
MIN_ALIAS_CHARS = 3
MAX_ALIAS_CHARS = 40
MAX_ALIAS_TOKENS = 4
MAX_TITLE_CHARS = 200

GENERIC_WORDS = frozenset("""
a an the and or of in on for to by via with without from into over under against at as is are be
remote local remotely locally unauthenticated authenticated unauth auth pre post preauth postauth
code command commands execution execute exec rce lfi rfi xss csrf ssrf xxe sqli sql nosql ssti idor dos ddos
injection inject overflow underflow buffer heap stack pool kernel memory corruption leak disclosure
information info sensitive data exposure denial service crash hang bypass bypasses escalation elevation
privilege privileges privesc admin administrator root user users account accounts password passwords
credential credentials authentication authorization access control traversal directory path file files
arbitrary read write delete upload download inclusion include race condition use after free double
null pointer dereference integer signedness format string type confusion cross site scripting request
forgery redirect open xml external entity deserialization deserialisation unsafe insecure improper
missing weak hardcoded hard coded default configuration misconfiguration vulnerability vulnerabilities
vuln vulns exploit exploits exploitation exploited poc proof concept metasploit module modules scanner
scan check checker detection detect detector collector gather enumeration enum fingerprint version
versions multiple various several unspecified unknown generic issue issues flaw flaws bug bugs attack
attacks payload payloads shell webshell reverse bind spawn method methods technique variant variants
universal persistent stored reflected dom blind error based time boolean union stacked second order
plugin plugins component components extension extensions theme themes addon addons widget
server servers client clients service services daemon application app apps web website portal panel
interface api library framework system systems device devices router routers camera firmware appliance
windows linux unix macos osx bsd solaris aix android x86 x64 amd64 arm arm64 mips ppc
powerpc sparc win32 win64 32bit 64bit dll exe php asp aspx jsp cgi perl python ruby java javascript
html http https tcp udp ftp smtp dns ssh tls ssl smb rdp ldap xp vista nt me r2 sp
new old latest beta alpha final full partial edition pro professional enterprise community free
part one two three dtls support supported add adding added remove change manipulation products product
url uri argument arguments array session sessions activex control controls listener manager console
""".split())
_ID_LIKE = re.compile(r"\d.*\d.*\d")    # a token with three or more digits is an identifier, not a name
_SERVICE_PACK = re.compile(r"^(?:sp\d+|r\d|v\d+[a-z]?|build\d*|rc\d*|update\d*)$", re.IGNORECASE)

GENERIC_PHRASES = frozenset(alias_norm(p) for p in (
    "Metasploit", "PoC", "Proof of Concept", "Authenticated", "Unauthenticated", "Denial of Service", "DoS",
    "Remote Code Execution", "Remote", "Local", "Privilege Escalation", "Arbitrary File Read",
    "Arbitrary File Upload", "SQL Injection", "Cross-Site Scripting", "Information Disclosure",
    "Authentication Bypass", "Command Injection", "Code Execution", "Buffer Overflow", "Scanner",
    "Windows", "Linux", "Multiple Vulnerabilities", "Multiple", "Exploit", "x86", "x64", "Python",
    "Ruby", "Perl", "Bash", "via", "PHP", "SEH", "Egghunter", "DEP Bypass", "ASLR Bypass", "ROP",
))

_IDENTIFIER = re.compile(r"^(?:CVE|CAN|CWE|EDB|OSVDB|BID|GHSA|ZDI|ZSL|KB|RHSA|DSA|USN|APSB|CNVD|CNNVD|JVN|"
                         r"VU|ICSA|TALOS|SA|JSA|NTAP|HPSBUX|cpe)[-_ :#]?[\dA-Z]", re.IGNORECASE)
_BULLETIN = re.compile(r"\bMS(\d{2})-(\d{3})\b")
_QUOTED = re.compile(r"(?:(?<![A-Za-z0-9])'([^'\n]{2,80})'(?![A-Za-z0-9])|\"([^\"\n]{2,80})\"|"
                     r"\u2018([^\u2019\n]{2,80})\u2019|\u201c([^\u201d\n]{2,80})\u201d)")
_PAREN = re.compile(r"\(([^()]{2,80})\)")
_CAMEL = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z][a-z]+(?:[A-Z0-9]+[a-z]+)+|[A-Z][a-z]*\d+[A-Za-z]*[A-Z][a-z]+)"
                    r"(?![A-Za-z0-9])")
_TRIGGER = (r"(?<!\()(?i:\b(?:also known as|known as|dubbed|nicknamed|codenamed|code-named|a\.k\.a\.?|aka|"
            r"also called|referred to as))\s+(?i:the\s+)?")
# quoted: the whole quoted text must be the name ('aka "Dirty COW."'); unquoted: a short capitalised run that
# is called a bug/attack/issue/flaw/vulnerability ("aka the Heartbleed bug"). "(aka X)" right after a product
# name is a product alias, not a nickname, and is not matched.
_KNOWN_AS_QUOTED = re.compile(_TRIGGER + r"[\"'\u201c\u2018]([^\"'\u201d\u2019]{2,60}?)[.,]?[\"'\u201d\u2019]")
_KNOWN_AS_BARE = re.compile(_TRIGGER + r"([A-Z0-9][A-Za-z0-9+]*(?:[- ][A-Z0-9][A-Za-z0-9+]*){0,2})"
                            r"\s+(?i:bug|attack|issue|flaw|vulnerability|exploit)\b")
# words that mark a vendor's descriptive vulnerability title ("Netlogon Elevation of Privilege
# Vulnerability"), not a coined name
_TITLE_WORDS = frozenset("""elevation execution disclosure corruption bypass injection overflow spoofing tampering
denial escalation information feature vulnerability vulnerabilities remote security privilege memory code
""".split())
_BAD_CHARS = re.compile(r"[/\\_.=?&$%<>@#:;{}\[\]()|*~^`]")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9+'\u2019-]*")
_LEAD_STRIP = re.compile(r"^(?:via|aka|a\.k\.a\.?|the|so-called|so called|dubbed|known as)\s+", re.IGNORECASE)
_HAS_UPPER = re.compile(r"[A-Z]")
_VERSIONISH = re.compile(r"^v?\d+(?:[.\-]\d+)*[a-z]?$", re.IGNORECASE)
_YEAR = re.compile(r"^CVE-(\d{4})-")


@dataclass(frozen=True)
class Candidate:
    cve_id: str
    alias: str
    norm: str
    kind: str            # nickname | advisory_id | title
    source: str          # one of ALLOWED_SOURCES
    record_id: str
    position: str        # quoted | paren | camel | known_as | bulletin | title
    record_cves: int     # number of CVEs the source record names


def _tokens(span: str) -> list[str]:
    return _TOKEN.findall(span)


def _generic_token(t: str, extra: frozenset[str]) -> bool:
    t = t.strip("'\u2019-").lower()
    return (not t or t in GENERIC_WORDS or t in extra or t.isdigit() or bool(_VERSIONISH.match(t))
            or bool(_SERVICE_PACK.match(t)))


def is_generic_tokens(tokens: Iterable[str], extra_generic: frozenset[str] = frozenset()) -> bool:
    toks = list(tokens)
    return not toks or all(_generic_token(t, extra_generic) for t in toks)


def clean_span(span: str) -> str | None:
    """Turn a quoted/parenthesised span into a name candidate, or None.

    Keeps the leading run of name-like words ("Dirty COW /proc/self/mem" -> "Dirty COW"), strips
    connectives ("via Log4Shell" -> "Log4Shell") and rejects file names, parameters, function names,
    paths, versions and identifiers."""
    s = clean_text(span).strip(" -,;:")
    for _ in range(2):
        s = _LEAD_STRIP.sub("", s)
    kept: list[str] = []
    for w in s.split(" "):
        if not w or _BAD_CHARS.search(w) or w.startswith("-"):
            break
        kept.append(w)
        if len(kept) > MAX_ALIAS_TOKENS:
            return None
    s = " ".join(kept).strip(" -,'")
    while s.lower().startswith("the "):
        s = s[4:]
    if not (MIN_ALIAS_CHARS <= len(s) <= MAX_ALIAS_CHARS):
        return None
    if not _HAS_UPPER.search(s) or _IDENTIFIER.match(s) or _VERSIONISH.match(s):
        return None
    if not re.search(r"[A-Za-z]{2}", s):
        return None
    toks = _tokens(s)
    if not toks or len(toks) > MAX_ALIAS_TOKENS:
        return None
    if len(toks) == 1 and s[0].islower():
        return None  # parameter-like ('id', 'page')
    if any(_ID_LIKE.search(t) for t in toks) or re.search(r"\bBug ID\b", s, re.IGNORECASE):
        return None  # bug tracker or build identifiers ("Bug ID CSCtq52661")
    return s


def nickname_spans(title: str) -> list[tuple[str, str]]:
    """(span, position) nickname candidates of a source title, before any vocabulary filtering."""
    out: list[tuple[str, str]] = []
    if not title:
        return out
    for m in _QUOTED.finditer(title):
        raw = next(g for g in m.groups() if g is not None)
        c = clean_span(raw)
        if c:
            out.append((c, "quoted"))
    for m in _PAREN.finditer(title):
        for part in re.split(r"\s*(?:/|,|;|\+| or | and )\s*", m.group(1)):
            c = clean_span(part)
            if c:
                out.append((c, "paren"))
    for m in _CAMEL.finditer(title):
        out.append((m.group(0), "camel"))
    return out


def known_as_spans(text: str) -> list[tuple[str, str]]:
    out = []
    text = text or ""
    for rx in (_KNOWN_AS_QUOTED, _KNOWN_AS_BARE):
        for m in rx.finditer(text):
            raw = clean_text(m.group(1)).rstrip(".,")
            c = clean_span(raw)
            if not c or c != raw:
                continue  # the whole quoted text must be a clean name
            toks = _tokens(c)
            if is_generic_tokens(toks) or any(t.lower() in _TITLE_WORDS for t in toks):
                continue
            out.append((c, "known_as"))
    return out


def bulletin_ids(text: str) -> list[str]:
    return sorted({f"MS{m.group(1)}-{m.group(2)}" for m in _BULLETIN.finditer(text or "")})


_TITLE_PACKAGING = re.compile(r"\s*\((?:Metasploit|PoC|Authenticated|Unauthenticated|\d+|[A-Za-z]{1,3}\d?|"
                              r"Windows[^)]*|Linux[^)]*|x86[^)]*|x64[^)]*|Python[^)]*|Ruby[^)]*|Perl[^)]*)\)",
                              re.IGNORECASE)


def clean_title(title: str) -> str:
    """Source title without exploit-site packaging such as "(Metasploit)", "(PoC)", "(2)"."""
    s = clean_text(title)
    prev = None
    while prev != s:
        prev = s
        s = _TITLE_PACKAGING.sub("", s).strip()
    return s


def _check_source(source: str) -> None:
    if source not in ALLOWED_SOURCES:
        raise ValueError(f"alias source {source!r} is not an allowed expansion source")


def candidates_from_record(source: str, record_id: str, cve_ids: list[str], title: str,
                           description: str = "") -> list[Candidate]:
    """All raw candidates of one source record, for every CVE it names. Filtering happens later, once the
    CVE's own records and corpus-wide statistics are known."""
    _check_source(source)
    title = clean_text(title)
    if not title or not cve_ids:
        return []
    n = len(cve_ids)
    found: dict[tuple[str, str], tuple[str, str]] = {}
    spans = nickname_spans(title)
    if source == "metasploit_modules" and description:
        spans += known_as_spans(description)
    for span, pos in spans:
        if _BULLETIN.fullmatch(span):
            continue
        key = alias_norm(span)
        if key and (key, "nickname") not in found:
            found[(key, "nickname")] = (span, pos)
    for b in bulletin_ids(title):
        found.setdefault((alias_norm(b), "advisory_id"), (b, "bulletin"))
    if source in TITLE_KIND_SOURCES:
        t = clean_title(title)[:MAX_TITLE_CHARS]
        if t:
            found.setdefault((alias_norm(t), "title"), (t, "title"))
    return [Candidate(cid, span, key, kind, source, record_id, pos, n)
            for cid in cve_ids for (key, kind), (span, pos) in found.items()]


def description_candidates(cve_id: str, desc_texts: list[str]) -> list[Candidate]:
    """'aka X' / 'known as X' nicknames in the CVE's own English description(s)."""
    out: dict[str, Candidate] = {}
    for i, d in enumerate(desc_texts):
        for span, pos in known_as_spans(d):
            if _BULLETIN.fullmatch(span):
                continue
            k = alias_norm(span)
            if k and k not in out:
                out[k] = Candidate(cve_id, span, k, "nickname", "cve_description", f"{cve_id}#d{i}", pos, 1)
    return list(out.values())


def own_name_tokens(names: Iterable[str]) -> frozenset[str]:
    """Lower-case tokens of a CVE's own vendor and product names (CPE slugs, CNA/KEV names)."""
    toks: set[str] = set()
    for n in names:
        for t in re.findall(r"[A-Za-z0-9]+", (n or "").replace("_", " ")):
            toks.add(t.lower())
    return frozenset(toks)


def local_decision(c: Candidate, own_tokens: frozenset[str], own_keys: frozenset[str],
                   desc_texts: list[str], desc_nick_norms: frozenset[str]) -> str:
    """Per-CVE decision for one candidate: 'keep' or the rejection reason."""
    toks = _tokens(c.alias)
    if c.kind == "advisory_id":
        return "keep"
    if c.kind == "title":
        if c.norm in GENERIC_PHRASES or c.norm in own_keys or is_generic_tokens(toks, own_tokens):
            return "generic_title"
        return "keep"
    if c.norm in GENERIC_PHRASES:
        return "generic_phrase"
    if c.norm in own_keys:
        return "own_vendor_or_product"
    if is_generic_tokens(toks, own_tokens):
        return "generic_words"
    if not (MIN_ALIAS_CHARS <= len(c.norm) <= MAX_ALIAS_CHARS):
        return "length"
    if c.source != "cve_description" and c.norm not in desc_nick_norms:
        low = [t.lower() for t in toks]
        if any(find_span(low, d) for d in desc_texts):
            return "named_in_description"  # the CVE's own text uses it as a component/parameter name
    return "keep"


@dataclass
class Selection:
    rows: list[Candidate]
    reasons: dict[str, int]
    rejected_names: dict[str, str]


def _year(cve_id: str) -> int:
    m = _YEAR.match(cve_id)
    return int(m.group(1)) if m else 0


def select(candidates: list[tuple[Candidate, str]], product_vocabulary: frozenset[str]) -> Selection:
    """Corpus-wide selection over (candidate, local decision) pairs. Returns the accepted alias rows."""
    reasons: dict[str, int] = defaultdict(int)
    rejected_names: dict[str, str] = {}
    keep: list[Candidate] = []
    nick: dict[str, list[Candidate]] = defaultdict(list)
    for c, d in candidates:
        if d != "keep":
            reasons[d] += 1
            continue
        if c.kind == "nickname":
            nick[c.norm].append(c)
        else:
            keep.append(c)
            reasons[f"accepted_{c.kind}"] += 1
    for norm, cs in nick.items():
        positions = {c.position for c in cs}
        if positions == {"camel"} and norm in product_vocabulary:
            reasons["product_name"] += len(cs)
            rejected_names[norm] = "product_name"
            continue
        cves = sorted({c.cve_id for c in cs})
        if len(cves) > MAX_NICKNAME_SPREAD:
            reasons["spread_too_wide"] += len(cs)
            rejected_names[norm] = "spread_too_wide"
            continue
        years = [_year(x) for x in cves]
        best_lo, best_n = years[0], -1
        for lo in sorted(set(years)):
            n = sum(1 for y in years if lo <= y < lo + YEAR_WINDOW)
            if n > best_n:
                best_lo, best_n = lo, n
        if best_n / len(years) < MIN_WINDOW_SHARE:
            reasons["spread_over_years"] += len(cs)
            rejected_names[norm] = "spread_over_years"
            continue
        support: dict[str, float] = defaultdict(float)
        seen: set[tuple[str, str, str]] = set()
        for c in cs:
            k = (c.cve_id, c.source, c.record_id)
            if k not in seen:
                seen.add(k)
                support[c.cve_id] += 1.0 / max(1, c.record_cves)
        top = max(support.values())
        for c in cs:
            y = _year(c.cve_id)
            if not (best_lo <= y < best_lo + YEAR_WINDOW):
                reasons["outside_year_window"] += 1
            elif support[c.cve_id] < MIN_RELATIVE_SUPPORT * top:
                reasons["low_relative_support"] += 1
            else:
                keep.append(c)
                reasons["accepted_nickname"] += 1
    keep.sort(key=lambda c: (c.cve_id, c.kind, c.norm, c.source, c.record_id))
    return Selection(keep, dict(reasons), rejected_names)


def thresholds() -> dict:
    return {"max_nickname_spread": MAX_NICKNAME_SPREAD, "year_window": YEAR_WINDOW,
            "min_window_share": MIN_WINDOW_SHARE, "min_relative_support": MIN_RELATIVE_SUPPORT,
            "alias_chars": [MIN_ALIAS_CHARS, MAX_ALIAS_CHARS], "max_alias_tokens": MAX_ALIAS_TOKENS,
            "max_title_chars": MAX_TITLE_CHARS}
