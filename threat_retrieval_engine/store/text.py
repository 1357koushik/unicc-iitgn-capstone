"""Text helpers for the C1 document store: cleaning, placeholder detection, CVE-ID stripping,
product-name matching and humanised vendor/product labels.

Standard library only. The product-name matching (`slug_tokens`, `find_span`) follows the rule the
benchmark builder uses for its vulnerable-only CPE filter (benchmarks_v2/build/slice_products.py), so the
store and the benchmark agree on what "the product is named" means; the code is re-implemented here so the
runtime package does not import the benchmark builder.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Iterable

CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
# no left boundary: source tables glued into descriptions produce "AnyCVE-2025-41233"
CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,}(?![0-9])", re.IGNORECASE)
_WS = re.compile(r"\s+")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WORD = re.compile(r"[A-Za-z0-9]+")
_ALPHA_WORD = re.compile(r"[A-Za-z]{2,}")

NA_VALUES = frozenset({"", "n/a", "na", "n.a.", "none", "unknown", "unspecified", "not applicable", "-", "*",
                       "all", "?", "tbd", "null", "undefined"})


def normalize_cve_id(value: object) -> str | None:
    """Canonical `CVE-YYYY-NNNN+` or None when malformed (year must be 1999 or later)."""
    if not isinstance(value, str):
        return None
    s = value.strip().upper().replace("‑", "-").replace("–", "-")
    m = CVE_ID_RE.match(s)
    if not m or int(m.group(1)) < 1999:
        return None
    return s


def cve_sort_key(cve_id: str) -> tuple[int, int]:
    _, y, n = cve_id.split("-")
    return int(y), int(n)


def clean_text(value: object) -> str:
    """NFC-normalise, drop control characters, collapse whitespace. The source wording is otherwise kept."""
    if value is None:
        return ""
    s = unicodedata.normalize("NFC", str(value))
    s = _CTRL.sub(" ", s)
    return _WS.sub(" ", s).strip()


def is_na(value: object) -> bool:
    return clean_text(value).casefold() in NA_VALUES


# --------------------------------------------------------------------------- placeholders
_RESERVED = re.compile(r"^\*\*\s*RESERVED\s*\*\*", re.IGNORECASE)
_REJECTED = re.compile(r"^(?:\*\*\s*REJECT(?:ED)?\s*\*\*|Rejected reason:)", re.IGNORECASE)
_UNUSED = re.compile(r"^\*\*\s*(?:UNUSED|NOT USED)\s*\*\*", re.IGNORECASE)
_PLACEHOLDER_EXACT = frozenset({
    "n/a", "na", "none", "tbd", "todo", "test", "testing", "description", "no description",
    "no description available", "placeholder", "reserved", "rejected", "not used", "unused", "null",
    "undefined", "-", ".", "...", "?",
})
MIN_USABLE_WORDS = 3


def description_kind(text: str) -> str:
    """'reserved' | 'rejected' | 'placeholder' | 'empty' | 'ok' for a cleaned description."""
    t = clean_text(text)
    if not t:
        return "empty"
    if _RESERVED.match(t):
        return "reserved"
    if _REJECTED.match(t):
        return "rejected"
    if _UNUSED.match(t) or t.casefold().strip(" .") in _PLACEHOLDER_EXACT:
        return "placeholder"
    if len(_ALPHA_WORD.findall(t)) < MIN_USABLE_WORDS:
        return "placeholder"
    return "ok"


# --------------------------------------------------------------------------- dense-text cleanup
_DISPUTED = re.compile(r"^\*\*\s*DISPUTED\s*\*\*\s*", re.IGNORECASE)
_EMPTY_PARENS = re.compile(r"\(\s*(?:[,;/]|and|or|aka|a\.k\.a\.|see|also)?\s*\)", re.IGNORECASE)
_DANGLING_LIST = re.compile(r"(?:\s*(?:,|;|\band\b|\bor\b))+\s*(?=[.,;)])", re.IGNORECASE)
_SPACE_PUNCT = re.compile(r"\s+([.,;:)])")
_DOUBLE_PUNCT = re.compile(r"([.,;:])\s*(?:[.,;:]\s*)+")


def strip_cve_ids(text: str) -> str:
    """Remove CVE IDs from free text and tidy what they leave behind (empty brackets, dangling list
    separators). Used for dense_text only; the stored description keeps the source wording."""
    if not text or not CVE_IN_TEXT.search(text):
        return text
    s = CVE_IN_TEXT.sub("", text)
    for _ in range(3):
        s = _EMPTY_PARENS.sub("", s)
        s = _DANGLING_LIST.sub("", s)
        s = re.sub(r"\(\s*(?:,|;|and|or)\s*", "(", s)
    s = _SPACE_PUNCT.sub(r"\1", s)
    s = _DOUBLE_PUNCT.sub(r"\1 ", s)
    s = _WS.sub(" ", s).strip()
    return s


def strip_disputed_marker(text: str) -> str:
    return _DISPUTED.sub("", text)


# --------------------------------------------------------------------------- product names
PACKAGING_WORDS = frozenset({"firmware"})


def unescape_cpe(slug: str) -> str:
    return slug.replace("\\", "")


def slug_tokens(slug: str) -> list[str]:
    """Lower-case alphanumeric tokens of a CPE vendor/product slug; trailing packaging words dropped."""
    toks = [t.lower() for t in _WORD.findall(unescape_cpe(slug).replace("_", " "))]
    while len(toks) > 1 and toks[-1] in PACKAGING_WORDS:
        toks.pop()
    return toks


def find_span(phrase: list[str], text: str) -> str | None:
    """Original-case span of `text` whose alphanumeric tokens, joined, equal the joined phrase tokens
    ("e-studio 6525" matches "e-STUDIO6525"). None when the phrase is not named in the text."""
    key = "".join(phrase)
    if not key or not text:
        return None
    toks = [(m.group(0).lower(), m.start(), m.end()) for m in _WORD.finditer(text)]
    n = len(toks)
    for i in range(n):
        if not key.startswith(toks[i][0]):
            continue
        acc = ""
        for j in range(i, min(n, i + len(phrase) + 3)):
            acc += toks[j][0]
            if acc == key:
                return text[toks[i][1]:toks[j][2]]
            if len(acc) >= len(key) or not key.startswith(acc):
                break
    return None


def display_name(value: str) -> str:
    """Humanised display form: underscores become spaces, CPE escapes removed, whitespace collapsed."""
    return clean_text(unescape_cpe(value).replace("_", " "))


def name_key(value: str) -> str:
    """Comparison key for vendor/product names: lower-case alphanumerics only."""
    return "".join(t.lower() for t in _WORD.findall(display_name(value or "")))


def vendor_product_label(vendor: str | None, product: str) -> str:
    """'Vendor Product', without repeating a vendor the product name already starts with or contains."""
    p = display_name(product)
    v = display_name(vendor) if vendor else ""
    if not v or v.casefold() in NA_VALUES:
        return p
    pk, vk = name_key(p), name_key(v)
    if not pk:
        return v
    if pk.startswith(vk) or vk in pk:
        return p
    return f"{v} {p}"


def alias_norm(value: str) -> str:
    """Normalised alias key: accents folded, lower-case alphanumerics only ("Dirty COW" -> "dirtycow")."""
    s = unicodedata.normalize("NFKD", value or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return "".join(t.lower() for t in _WORD.findall(s))


def word_tokens(text: str) -> list[str]:
    return _WORD.findall(text or "")


def dedupe_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out
