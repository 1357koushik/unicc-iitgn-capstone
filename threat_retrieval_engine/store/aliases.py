"""Alias extraction for the C1 document store.

An alias is a short human name for a CVE taken from public exploit and advisory metadata. Allowed inputs
(the leakage firewall of plan 6.1 / 4.3):

* ``exploitdb``          - Exploit-DB titles
* ``metasploit_modules`` - Metasploit module names, plus "known as X" phrases in module descriptions
* ``nuclei_templates``   - nuclei template names
* ``kev``                - CISA KEV vulnerability names
* ``cve_list``           - CVE List (CNA) titles
* ``cve_description``    - "aka X" / "known as X" phrases in the CVE's own English description
* ``poc_in_github``      - PoC-in-GitHub repository names and descriptions (community naming; untrusted, so
                           only as corroborated evidence, see below)
* ``cve_references``     - words of the CVE's own reference URLs (dedicated sites such as drownattack.com,
                           exploit-archive slugs, write-up slugs; only as corroborated evidence)

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

Nicknames are gazetteer-vetted. The build proposes candidates (deterministic rules below), writes them
with their evidence to the store's ``alias_candidates`` table and to ``nickname_candidates.jsonl``, and
serves a nickname only when the committed verdict file (store/data/nickname_verdicts.jsonl, written by
model judges from that file) accepts exactly that (alias_norm, CVE set) with a matching evidence hash.
Everything else stays 'pending' and is never served. Titles and bulletin IDs keep their structured rules
and are served directly.

No nickname list is written by hand: names come only from the sources. What is written by hand is the
vocabulary that makes a span generic (flaw words, exploit-site packaging, platforms, connectives). The
rest is decided from the data, in two steps:

1. per CVE (in the build worker, which has the CVE's records): is the candidate one of the CVE's own
   vendor/product/package/module names, and does the CVE's own description name it as a component
   ("via the Name parameter", "the DirectWrite component") rather than as a nickname ("aka Heartbleed")?
2. corpus-wide (in the build master): a nickname must not spread over many CVEs (product names do), the
   CVEs it names must cluster in time (a coined name belongs to one disclosure), a bare CamelCase token
   must not be a known CPE product name, and a CVE whose only evidence is multi-CVE exploit records shared
   with a much better supported CVE is dropped (relative support); a CVE with its own single-CVE evidence
   is kept.

Every nickname needs at least two independent units of evidence for the same CVE, from at least two
different families (a kernel function quoted in an exploit title and repeated in the matching Metasploit
module, or a class named in a CNA title, is not a nickname). Units: each Exploit-DB record, Metasploit
module, nuclei template and KEV row; the CNA's title and description together; each distinct reference
domain; each distinct PoC-in-GitHub owner. Families: ``exploit`` (Exploit-DB, Metasploit, nuclei and
exploit-archive references such as Packet Storm), ``cna`` (also the assigning CNA's own advisory pages,
which repeat its title), ``kev``, ``poc``, ``refs`` (other reference domains) and ``site`` (a dedicated
site, see below).
PoC-in-GitHub names and reference-URL words are weak evidence: anyone can name a repository, and a URL
word may be a product, a person or a page title. A name attested only by weak evidence must also be rare
in the corpus (every word in at most DF_MAX CVE descriptions, one word in at most DF_RARE), unless one of
its units is a dedicated site (a domain cited by at most DEDICATED_DOMAIN_MAX_CVES CVEs, such as
drownattack.com); a two-word weak name must be written capitalised in at least one unit
("Citrix-Bleed"), and researcher handles in code-hosting paths are skipped.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .text import alias_norm, clean_text, find_span

ALLOWED_SOURCES = ("exploitdb", "metasploit_modules", "nuclei_templates", "kev", "cve_list", "cve_description",
                   "poc_in_github", "cve_references")
WEAK_SOURCES = frozenset({"poc_in_github", "cve_references"})
WEAK_POSITIONS = frozenset({"camel", "poc_repo", "reference", "reference_cna", "reference_host",
                            "reference_site"})
MIN_UNITS = 2                   # independent evidence units a nickname needs for one CVE
MIN_WEAK_UNITS = MIN_UNITS
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
MAX_HEAD_TOKENS = 3

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
spoofing tampering leakage leak leaks hijack hijacking takeover weakening connection token tokens
toctou xsrf bxss lpe sqlinj premium limited lite secure object providers success
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
    raw_head = title.split(" - ", 1)[0] if " - " in title else ""
    # "Name - description" title head ("Citrix Bleed - Leaking Session Tokens"); a head with a version number
    # ("PHP 4.4.6 - ...", "Linux Kernel 2.6.22 < 3.9 - ...") names a product, not a flaw
    if raw_head and not re.search(r"\d\.\d|<|>|/", raw_head):
        head = clean_span(raw_head)
        if head and len(_tokens(head)) <= MAX_HEAD_TOKENS and not any(t.isdigit() for t in _tokens(head)):
            out.append((head, "head"))
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


# --------------------------------------------------------------------------- weak evidence
URL_STOP = frozenset("""
www com org net edu gov io co uk de fr jp cn ru kr au in br it es nl eu info html htm shtml php asp aspx jsp do
cgi pl txt pdf md xml json rss index default home main en us en-us view show details detail display article
articles post posts blog blogs news story stories entry entries page pages wiki docs doc documentation help kb
knowledgebase support security securityadvisories advisory advisories alert alerts bulletin bulletins notice
notices note notes bug bugs bugzilla issue issues ticket tickets pull pulls commit commits compare blob tree
master main raw src source sources files file download downloads release releases changelog changes archive
archives lists list mailing msg message messages thread threads forum forums topic topics discussion
question questions cve cves nvd vuln vulns vulndb vulnerability vulnerabilities exploit exploits packetstorm
packetstormsecurity securityfocus bid osvdb exploitdb edb seclists fulldisclosure bugtraq oss openwall
securitytracker xforce proof concept concepts poc readme summary writeup research analysis report reports
paper whitepaper presentation slides video watch tag tags category categories update updates patch patches
fix fixed fixes version versions critical high medium low important moderate disclosure disclosed
the of in and for a an to with on by from via its is how what why new about our your this that
""".split())
HOSTING = frozenset({"github.com", "gitlab.com", "bitbucket.org", "blogspot.com", "wordpress.com", "medium.com",
                     "github.io", "gitlab.io", "sourceforge.net", "twitter.com", "x.com", "youtube.com",
                     "google.com", "pastebin.com", "gist.github.com", "substack.com", "linkedin.com",
                     "reddit.com", "hackerone.com", "huntr.dev", "huntr.com", "gitee.com", "notion.site"})
_HANDLE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "twitter.com", "x.com", "medium.com", "gitee.com",
                 "huntr.dev", "huntr.com", "hackerone.com", "youtube.com", "linkedin.com")
# code hosting: only the repository name is used (file paths and class names are not names of a flaw)
_CODE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "gitee.com", "gist.github.com")
EXPLOIT_ARCHIVE_DOMAINS = frozenset({"packetstormsecurity.com", "packetstorm.news", "exploit-db.com",
                                     "0day.today", "cxsecurity.com"})
_SEG_SPLIT = re.compile(r"[-_+.~,;=%\s]+")
_WEAK_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_HEXISH = re.compile(r"^[0-9a-f]{7,}$", re.IGNORECASE)
_MONTHS = frozenset("january february march april may june july august september october november december "
                    "jan feb mar apr jun jul aug sep sept oct nov dec".split())


def _weak_ok(tok: str, min_len: int = 4) -> bool:
    t = tok.lower()
    if len(t) < min_len or not _WEAK_TOKEN.match(tok) or sum(ch.isdigit() for ch in t) > 2:
        return False
    if _HEXISH.match(t) or t in URL_STOP or t in GENERIC_WORDS or t in _MONTHS:
        return False
    return sum(ch.isalpha() for ch in t) >= 3


def _display(tok: str) -> str:
    return tok if any(ch.isupper() for ch in tok) else tok[:1].upper() + tok[1:]


def _phrases(tokens: list[str]) -> list[str]:
    """Unigrams and bigrams of a token run that may be names, in their original case. Bigram words are both
    name-like (no generic or URL words), so "review-and" or "sql-injection" never form a name."""
    out = [t for t in tokens if _weak_ok(t)]
    for a, b in zip(tokens, tokens[1:]):
        if _weak_ok(a, 2) and _weak_ok(b, 2) and (len(a) >= 4 or len(b) >= 4):
            out.append(f"{a} {b}")
    return out


_HOST_STOP = frozenset("""www1 www2 www3 ww2 web web2 m mobile cdn static assets img images media portal portals
support supportportal help kb docs doc lists list mail email forum forums community answers bugs bug bugzilla
jira issues tracker git svn cvs code dev developer developers download downloads ftp security sec secure psirt
cert csirt advisories advisory alerts blog blogs news research labs lab wiki go app apps api my login account
customer customers partner partners service services status tools en us de jp cn fr kr""".split())
_SITE_SUFFIX = re.compile(r"^([a-z0-9]+?)-?(?:attacks?|bugs?|vuln|exploit|flaw)$")
_SECOND_LEVEL = frozenset({"co", "com", "ac", "org", "net", "gov", "edu", "ne", "or", "go"})


def registrable_domain(host: str) -> str:
    """Approximate registrable domain: last two labels, or three under a second-level label (co.uk, com.au)."""
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_ADVISORY_SEGMENT = re.compile(r"^(?:GHSA|PYSEC|GO|RUSTSEC|OSV|SNYK)-", re.IGNORECASE)


def url_phrases(url: str) -> tuple[str, list[str]]:
    """(registrable-domain unit, candidate phrases) of one reference URL."""
    unit, tagged = url_phrases_tagged(url)
    return unit, [p for p, _ in tagged]


def url_phrases_tagged(url: str) -> tuple[str, list[tuple[str, str]]]:
    """(registrable-domain unit, [(phrase, 'site' | 'host' | 'path')]). 'site' marks a host label of a
    URL that is the root of its site (https://www.krackattacks.com/), the shape of a dedicated site."""
    from urllib.parse import unquote, urlsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        return "", []
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return "", []
    labels = host.split(".")
    phrases: list[tuple[str, str]] = []
    reg = registrable_domain(host)
    segs = [unquote(x) for x in parts.path.split("/") if x]
    root = not segs or (len(segs) == 1 and re.fullmatch(r"index\.\w+", segs[0]) is not None)
    if reg not in HOSTING and host not in HOSTING and len(labels) >= 2:
        for lab in labels[:-1]:
            if lab in URL_STOP or lab in _HOST_STOP:
                continue
            m = _SITE_SUFFIX.match(lab)
            tag = "site" if (root or m) else "host"
            phrases += [(x, tag) for x in _phrases(_SEG_SPLIT.split(lab))]
            if m and len(m.group(1)) >= 4:
                phrases.append((m.group(1), tag))  # krackattacks.com -> krack
    if any(host == h or host.endswith("." + h) for h in _HANDLE_HOSTS) and segs:
        segs = segs[1:]  # skip the account / researcher handle
        if host in _CODE_HOSTS:
            segs = segs[:1]
    unit = reg
    for seg in segs:
        if _ADVISORY_SEGMENT.match(seg):
            continue  # GHSA-w3hj-x5rv-... identifiers, never names
        seg = re.sub(r"\.(?:html?|php|aspx?|jsp|txt|pdf|md|shtml|cgi)$", "", seg, flags=re.IGNORECASE)
        phrases += [(x, "path") for x in _phrases([t for t in _SEG_SPLIT.split(seg) if t])]
    return unit, phrases


def poc_phrases(full_name: str, description: str) -> list[str]:
    name = (full_name or "").split("/", 1)[-1]
    out = _phrases([t for t in _SEG_SPLIT.split(name) if t])
    out += [span for span, _ in nickname_spans(description or "") + known_as_spans(description or "")]
    return out


def weak_candidates(cve_id: str, ref_urls: list[str], pocs: list[tuple[str, str]],
                    strong_norms: frozenset[str], assigner: str = "") -> list[Candidate]:
    """Corroborated weak-evidence candidates for one CVE: a name needs MIN_WEAK_UNITS independent units
    (distinct PoC owners, distinct reference hosts; a strong-source candidate of the same key counts as one)."""
    units: dict[str, set[str]] = defaultdict(set)
    rows: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
    akey = alias_norm(assigner or "")
    site_norms: set[str] = set()
    for url in ref_urls:
        host, phrases = url_phrases_tagged(url)
        label = alias_norm(host.split(".")[0]) if host else ""
        # the assigning CNA's own advisory page repeats the CNA title: same source, not corroboration
        cna_page = bool(akey and len(label) >= 3 and (label in akey or akey in label))
        for ph, tag in dict.fromkeys(phrases):
            k = alias_norm(ph)
            if MIN_ALIAS_CHARS <= len(k) <= MAX_ALIAS_CHARS:
                pos = "reference_cna" if cna_page else {"site": "reference_site", "host": "reference_host",
                                                         "path": "reference"}[tag]
                units[k].add("cna" if cna_page else f"ref:{host}")
                rows[k].append((ph, "cve_references", url, pos))
                if pos == "reference_site":
                    site_norms.add(k)
    for full_name, desc in pocs:
        owner = (full_name or "").split("/", 1)[0].lower()
        for ph in dict.fromkeys(poc_phrases(full_name, desc)):
            k = alias_norm(ph)
            if MIN_ALIAS_CHARS <= len(k) <= MAX_ALIAS_CHARS:
                units[k].add(f"poc:{owner}")
                rows[k].append((ph, "poc_in_github", full_name, "poc_repo"))
    out = []
    for k, us in units.items():
        n = len(us) + (1 if k in strong_norms else 0)
        if n < MIN_WEAK_UNITS and k not in site_norms:
            continue
        seen: set[tuple[str, str]] = set()
        for ph, src, rid, pos in rows[k]:
            if (src, rid) in seen:
                continue
            seen.add((src, rid))
            out.append(Candidate(cve_id, ph, k, "nickname", src, rid, pos, 1))
    return out


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


def evidence_unit(c: Candidate) -> str:
    """The independent unit of evidence a candidate row represents."""
    if c.source in ("cve_list", "cve_description"):
        return "cna"
    if c.source == "cve_references" and c.position == "reference_cna":
        return "cna"
    if c.source == "cve_references":
        from urllib.parse import urlsplit
        try:
            host = (urlsplit(c.record_id).hostname or "").lower()
        except ValueError:
            host = ""
        return "ref:" + registrable_domain(host[4:] if host.startswith("www.") else host)
    if c.source == "poc_in_github":
        return "poc:" + c.record_id.split("/", 1)[0].lower()
    return f"{c.source}:{c.record_id}"


# positions that make a single unit enough to propose a candidate (structured nickname evidence)
STRONG_POSITIONS = frozenset({"quoted", "paren", "head", "known_as"})
EXPLOIT_SOURCES = frozenset({"exploitdb", "metasploit_modules", "nuclei_templates"})
# positions exempt from the dictionary-word filter: a quoted exploit-title name, an "aka" phrase, a dedicated site
DICTIONARY_EXEMPT = frozenset({"quoted", "known_as", "reference_site"})
_IDENT_PREFIX = re.compile(r"^(?:apsb|apsa|ghsa|rhsa|rhba|dsa|dla|usn|glsa|kb|ms|cve|cwe|jvn|jvndb|vu|icsa|zdi|zsl|"
                           r"tra|ntap|sa|sb|osvdb|bid|edb|cnvd|cnnvd|hpsbux|ibm|tsb|vmsa|ciscosa|esa|alas|elsa)\d",
                           re.IGNORECASE)
_SHORT_ALNUM = re.compile(r"^(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{2,6}$")   # w3hj, x5rv, g8ph, apsb20


def _stop_words() -> frozenset[str]:
    try:
        from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
        return frozenset(ENGLISH_STOP_WORDS)
    except ImportError:  # pragma: no cover - sklearn is in requirements-retrieval.lock
        return frozenset()


STOP_WORDS = _stop_words()


@dataclass(frozen=True)
class Vocabulary:
    """Deterministic prefilter vocabularies, all lower-case.

    dictionary: English words, taken from the corpus itself: words that occur written in lower case in at
        least DICTIONARY_MIN_DOCS CVE descriptions (proper names such as "Heartbleed" are written
        capitalised), plus the scikit-learn English stop words and the generic and URL word lists;
    names: CPE vendor and product names as alias keys ("debian", "freebsd", "ubuntulinux");
    name_tokens: words of CPE vendor names and of operating-system product names ("ubuntu", "desktop")."""
    dictionary: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    name_tokens: frozenset[str] = frozenset()


DICTIONARY_MIN_DOCS = 3


def prefilter(c: Candidate, positions: set[str], voc: Vocabulary) -> str | None:
    """Deterministic rejection reason for a nickname candidate key, or None."""
    toks = [t.lower() for t in _tokens(c.alias)]
    if not toks:
        return "empty"
    if any(_IDENT_PREFIX.match(t) or _SHORT_ALNUM.match(t) or _HEXISH.match(t) for t in toks):
        return "identifier_fragment"
    named = [t in voc.name_tokens or t in voc.names for t in toks]
    if c.norm in voc.names or (any(named) and all(n or t in GENERIC_WORDS or t in URL_STOP or t in STOP_WORDS
                                                  for t, n in zip(toks, named))):
        return "vendor_product_vocabulary"
    if not positions & DICTIONARY_EXEMPT and all(t in voc.dictionary or t in STOP_WORDS or t in GENERIC_WORDS
                                                 or t in URL_STOP for t in toks):
        return "dictionary_word"
    return None


@dataclass(frozen=True)
class NickGroup:
    """One nickname candidate: a name key and the sorted set of CVEs it is proposed for, with evidence."""
    norm: str
    alias: str
    cve_ids: tuple[str, ...]
    rows: tuple[Candidate, ...]
    evidence_sha256: str


def evidence_sha256(rows: Iterable[Candidate]) -> str:
    import hashlib
    import json
    ev = sorted({(c.cve_id, c.source, c.record_id, c.position, c.alias) for c in rows})
    return hashlib.sha256(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def display_alias(rows: Iterable[Candidate]) -> str:
    """Display form: from a structured source first, then a form with inner capitals, then the shortest."""
    best = max(rows, key=lambda c: (c.source not in WEAK_SOURCES, c.position in STRONG_POSITIONS,
                                    any(ch.isupper() for ch in c.alias[1:]), -len(c.alias), c.alias))
    a = best.alias
    return a if any(ch.isupper() for ch in a) else " ".join(w[:1].upper() + w[1:] for w in a.split())


@dataclass
class Selection:
    rows: list[Candidate]               # served non-nickname aliases (titles, bulletin IDs)
    groups: list[NickGroup]             # nickname candidates for vetting; served only with an accept verdict
    reasons: dict[str, int]
    rejected_names: dict[str, str]


def _year(cve_id: str) -> int:
    m = _YEAR.match(cve_id)
    return int(m.group(1)) if m else 0


def dedicated_domains(domain_info: dict[str, list[int]]) -> frozenset[str]:
    """Registrable domains cited by at most MAX_NICKNAME_SPREAD CVEs whose ID years span at most YEAR_WINDOW
    years: the shape of a site about one disclosure (krackattacks.com: 10 CVEs, all 2017)."""
    return frozenset(d for d, (n, lo, hi) in domain_info.items()
                     if 0 < n <= MAX_NICKNAME_SPREAD and hi - lo < YEAR_WINDOW)


def select(candidates: list[tuple[Candidate, str]], voc: Vocabulary,
           domain_info: dict[str, list[int]] | None = None) -> Selection:
    """Corpus-wide selection over (candidate, local decision) pairs.

    Titles and bulletin IDs that passed the local rules are served directly. Nickname candidates go through
    deterministic prefilters, the evidence rule and the corpus-wide spread rules, and come out as
    NickGroups for vetting; none is served here."""
    dedicated = dedicated_domains(domain_info or {})
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
    groups: list[NickGroup] = []
    for norm, cs in nick.items():
        # a host-label row is a dedicated-site row only if its domain has that shape
        cs = [c if c.position != "reference_site" or evidence_unit(c)[4:] in dedicated
              else Candidate(c.cve_id, c.alias, c.norm, c.kind, c.source, c.record_id, "reference_host",
                             c.record_cves) for c in cs]
        why = prefilter(cs[0], {c.position for c in cs}, voc)
        if why:
            reasons[why] += len(cs)
            rejected_names[norm] = why
            continue
        # evidence rule per CVE: one structured unit, or two independent units
        by_cve: dict[str, list[Candidate]] = defaultdict(list)
        for c in cs:
            by_cve[c.cve_id].append(c)
        ok_cs: list[Candidate] = []
        for cid, ccs in by_cve.items():
            structured = any(c.position in STRONG_POSITIONS or c.position == "reference_site"
                             or (c.position == "camel" and c.source in EXPLOIT_SOURCES) for c in ccs)
            if structured or len({evidence_unit(c) for c in ccs}) >= MIN_UNITS:
                ok_cs.extend(ccs)
            else:
                reasons["single_unit"] += len(ccs)
        if not ok_cs:
            rejected_names.setdefault(norm, "insufficient_evidence")
            continue
        cs = ok_cs
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
        single: dict[str, int] = defaultdict(int)
        seen: set[tuple[str, str]] = set()
        for c in cs:
            k = (c.cve_id, evidence_unit(c))
            if k not in seen:
                seen.add(k)
                support[c.cve_id] += 1.0 / max(1, c.record_cves)
                single[c.cve_id] += c.record_cves <= 1
        top = max(support.values())
        kept: list[Candidate] = []
        for c in cs:
            y = _year(c.cve_id)
            if not (best_lo <= y < best_lo + YEAR_WINDOW):
                reasons["outside_year_window"] += 1
            elif not single[c.cve_id] and support[c.cve_id] < MIN_RELATIVE_SUPPORT * top:
                reasons["low_relative_support"] += 1  # only co-listed in multi-CVE records
            else:
                kept.append(c)
        if not kept:
            continue
        kept.sort(key=lambda c: (c.cve_id, c.source, c.record_id, c.position, c.alias))
        groups.append(NickGroup(norm, display_alias(kept), tuple(sorted({c.cve_id for c in kept})), tuple(kept),
                                evidence_sha256(kept)))
        reasons["nickname_candidate_rows"] += len(kept)
    keep.sort(key=lambda c: (c.cve_id, c.kind, c.norm, c.source, c.record_id))
    groups.sort(key=lambda g: (g.norm, g.cve_ids))
    return Selection(keep, groups, dict(reasons), rejected_names)


def candidate_words(candidates: list[tuple[Candidate, str]]) -> set[str]:
    """Lower-case words of kept nickname candidates (for the corpus dictionary pass)."""
    out: set[str] = set()
    for c, d in candidates:
        if d == "keep" and c.kind == "nickname":
            out.update(t.lower() for t in _tokens(c.alias))
    return out


# --------------------------------------------------------------------------- vetting (verdict file)
VERDICT_FIELDS = ("alias_norm", "cve_ids", "verdict", "judge", "adjudicator", "date", "evidence_sha256")


def load_verdicts(path) -> dict[tuple[str, tuple[str, ...]], dict]:
    """Verdicts keyed by (alias_norm, sorted CVE IDs). Raises ValueError on a malformed or conflicting record.
    The file is written by the model judges from nickname_candidates.jsonl; it is never derived from
    benchmark queries, and a verdict can only serve a name the build itself proposed from expansion sources."""
    import json
    out: dict[tuple[str, tuple[str, ...]], dict] = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            if not line.strip():
                continue
            v = json.loads(line)
            missing = [k for k in VERDICT_FIELDS if not v.get(k)]
            if missing or v["verdict"] not in ("accept", "reject") or not isinstance(v["cve_ids"], list):
                raise ValueError(f"{path}:{n}: malformed verdict (missing {missing} or bad verdict/cve_ids)")
            extra = set(v) - set(VERDICT_FIELDS) - {"alias", "rationale", "notes"}
            if extra:
                raise ValueError(f"{path}:{n}: unexpected fields {sorted(extra)}")
            key = (v["alias_norm"], tuple(sorted(v["cve_ids"])))
            if key in out and out[key]["verdict"] != v["verdict"]:
                raise ValueError(f"{path}:{n}: conflicting verdicts for {key}")
            out[key] = v
    return out


def apply_verdicts(groups: list[NickGroup], verdicts: dict) -> dict[tuple[str, tuple[str, ...]], str]:
    """Status per group: accepted | rejected (verdict with matching evidence hash), stale (a verdict exists
    but the evidence changed), pending (no verdict). Only 'accepted' groups are served."""
    status = {}
    for g in groups:
        v = verdicts.get((g.norm, g.cve_ids))
        if v is None:
            status[(g.norm, g.cve_ids)] = "pending"
        elif v["evidence_sha256"] != g.evidence_sha256:
            status[(g.norm, g.cve_ids)] = "stale"
        else:
            status[(g.norm, g.cve_ids)] = "accepted" if v["verdict"] == "accept" else "rejected"
    return status


def thresholds() -> dict:
    return {"min_units": MIN_UNITS, "structured_positions": sorted(STRONG_POSITIONS),
            "dictionary_min_docs": DICTIONARY_MIN_DOCS, "dictionary_exempt_positions": sorted(DICTIONARY_EXEMPT),
            "dedicated_domain": f"<= {MAX_NICKNAME_SPREAD} citing CVEs within {YEAR_WINDOW} ID years",
            "max_nickname_spread": MAX_NICKNAME_SPREAD, "year_window": YEAR_WINDOW,
            "min_window_share": MIN_WINDOW_SHARE, "min_relative_support": MIN_RELATIVE_SUPPORT,
            "alias_chars": [MIN_ALIAS_CHARS, MAX_ALIAS_CHARS], "max_alias_tokens": MAX_ALIAS_TOKENS,
            "max_title_chars": MAX_TITLE_CHARS}
