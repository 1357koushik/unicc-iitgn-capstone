"""Tokenisation, normalisation and overlap measures shared by the builder and the leakage tests."""
from __future__ import annotations

import re
import unicodedata

CVE_FIND_RE = re.compile(r"(?<![A-Za-z0-9])CVE[-_ ]?(\d{4})[-_ ](\d{4,})(?!\d)", re.IGNORECASE)
CVE_CANON_FIND_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,}(?!\d)", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*")
_DASHES = {"‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-"}

STOPWORDS = frozenset("""
a about above after again against all also am an and any are aren as at be because been before being below between
both but by can cannot could did didn do does doesn doing don down during each either else etc ever every few for from
further had has hasn have haven having he her here hers herself him himself his how i if in into is isn it its itself
just let me more most my myself no nor not now of off on once only or other ought our ours ourselves out over own per
please same shall she should so some such than that the their theirs them themselves then there these they this those
through to too under until up upon us very via was wasn we were weren what when where which while who whom why will
with within without would you your yours yourself yourselves tell know want need any anything something whether
""".split())


def nfkc(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "")
    for k, v in _DASHES.items():
        s = s.replace(k, v)
    return s


def strip_cve_ids(s: str) -> str:
    return CVE_FIND_RE.sub(" ", nfkc(s))


def _light_stem(t: str) -> str:
    if len(t) > 4 and t.endswith("ies"):
        return t[:-3] + "y"
    if len(t) > 4 and t.endswith("s") and not t.endswith("ss") and not t[-2].isdigit():
        return t[:-1]
    return t


def tokens(s: str) -> list[str]:
    """Lower-cased word tokens; dotted versions such as 2.3.15 stay one token; light plural stemming."""
    return [_light_stem(t) for t in _TOKEN_RE.findall(nfkc(s).lower())]


def token_set(s: str) -> set[str]:
    return set(tokens(s))


def content_tokens(s: str) -> set[str]:
    """Query content tokens: CVE identifiers removed, stopwords and single letters dropped."""
    out = set()
    for t in tokens(strip_cve_ids(s)):
        if t in STOPWORDS:
            continue
        if len(t) == 1 and not t.isdigit():
            continue
        out.add(t)
    return out


def overlap(query: str, doc_tokens: set[str]) -> float:
    """Share of the query's content tokens that occur in the document text (plan 6.4 step 2, 60% rule)."""
    q = content_tokens(query)
    if not q:
        return 0.0
    return len(q & doc_tokens) / len(q)


def normalize(s: str) -> str:
    """Normalised form for exact-match comparisons: NFKC, lower case, non-alphanumerics collapsed."""
    return " ".join(re.findall(r"[a-z0-9]+", nfkc(s).lower()))


def near_duplicate(q: set[str], r: set[str]) -> float:
    """Token overlap |Q∩R| / max(|Q|,|R|): 1.0 means the two texts use the same content words."""
    if not q or not r:
        return 0.0
    return len(q & r) / max(len(q), len(r))


def name_key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", nfkc(s).lower())


def contains_name(name: str, text_tokens: list[str]) -> bool:
    """True when `name` occurs as a run of 1-4 consecutive tokens (joined form compared)."""
    key = name_key(name)
    if not key:
        return False
    n = len(text_tokens)
    for i in range(n):
        acc = ""
        for j in range(i, min(n, i + 4)):
            acc += text_tokens[j]
            if acc == key:
                return True
            if len(acc) >= len(key):
                break
    return False


def raw_tokens(s: str) -> list[str]:
    """Unstemmed alphanumeric tokens, for name matching."""
    return re.findall(r"[a-z0-9]+", nfkc(s).lower())


def first_sentence(s: str, max_chars: int = 300) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip())
    m = re.search(r"(?<=[a-z0-9\)\]])[.!?](?=\s+[A-Z])", s)
    out = s[: m.start() + 1] if m else s
    return out[:max_chars].strip()


def sentences(s: str) -> list[str]:
    s = re.sub(r"\s+", " ", (s or "").strip())
    if not s:
        return []
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\[(])", s)
    return [p.strip() for p in parts if p.strip()]
