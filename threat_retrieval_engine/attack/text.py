"""Text helpers for ATT&CK content: description cleaning, ID patterns, name tokenisation.

Standard library only. Names are normalised with the C1 store's `alias_norm` (accents folded, lower-case
alphanumerics), so a CVE alias and an ATT&CK name compare the same way everywhere in the engine.
"""
from __future__ import annotations

import re

from threat_retrieval_engine.store.text import CVE_IN_TEXT, alias_norm, clean_text, strip_cve_ids

__all__ = ["ATTACK_ID_RE", "ATTACK_ID_IN_TEXT", "alias_norm", "clean_description", "dense_strip_ids",
           "fine_tokens", "fine_token_spans", "normalize_attack_id", "CVE_IN_TEXT"]

# ATT&CK object IDs of the kinds this build stores (and tactics / data sources, which are only stripped).
ATTACK_ID_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|C\d{4})$")
ATTACK_ID_IN_TEXT = re.compile(r"(?<![A-Za-z0-9])(T\d{4}(?:[./]\d{3})?|G\d{4}|S\d{4}|M\d{4}|C\d{4})(?![A-Za-z0-9])",
                               re.IGNORECASE)
_ANY_ATTACK_ID = re.compile(r"(?<![A-Za-z0-9])(?:T\d{4}(?:\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|M\d{4}|C\d{4}|DS\d{4}|"
                            r"DC\d{4}|DET\d{4}|AN\d{4})(?![A-Za-z0-9])")


def normalize_attack_id(value: object) -> str | None:
    """Canonical ATT&CK ID (upper case; "T1059/001" -> "T1059.001") or None when malformed."""
    if not isinstance(value, str):
        return None
    s = value.strip().upper().replace("/", ".")
    if s.startswith("ATTACK:"):
        s = s[7:]
    return s if ATTACK_ID_RE.match(s) else None


# --------------------------------------------------------------------------- description cleaning
_HTML_TAGS = ("code", "b", "i", "em", "strong", "br", "p", "sup", "sub", "u", "a", "span", "div", "ul", "ol",
              "li", "pre", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "table", "thead", "tbody", "tr",
              "td", "th", "kbd", "samp", "tt")
_HTML = re.compile(r"</?(?:" + "|".join(_HTML_TAGS) + r")\b[^<>]*>", re.IGNORECASE)
# [text](url): the URL may contain one level of parentheses (Wikipedia style)
_MD_LINK = re.compile(r"\[([^\[\]]+)\]\((?:[^()\s]|\([^()\s]*\))+\)")
_MD_EMPH = re.compile(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1")
_MD_BULLET = re.compile(r"(?m)^\s*(?:[*\-+]|\d+\.)\s+")
_MD_HEADING = re.compile(r"(?m)^\s*#{1,6}\s+")
_BACKTICK = re.compile(r"`([^`]*)`")
_SPACE_PUNCT = re.compile(r"\s+([.,;:)\]])")
_OPEN_SPACE = re.compile(r"([(\[])\s+")


def _strip_citations(s: str) -> str:
    """Remove every "(Citation: ...)" with balanced parentheses inside the citation name."""
    out = []
    i = 0
    marker = "(citation:"
    low = s.lower()
    while True:
        j = low.find(marker, i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        depth = 0
        k = j
        while k < len(s):
            if s[k] == "(":
                depth += 1
            elif s[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        i = k + 1
    return "".join(out)


def clean_description(text: object) -> str:
    """ATT&CK markdown to plain text: link text kept and URL dropped, "(Citation: ...)" removed, HTML tags,
    emphasis, bullets and backticks removed, whitespace collapsed (C1 `clean_text`). Wording is otherwise
    the source's."""
    if not text:
        return ""
    s = str(text)
    s = _strip_citations(s)
    for _ in range(2):  # a link inside emphasis, or emphasis inside a link
        s = _MD_LINK.sub(r"\1", s)
        s = _MD_EMPH.sub(r"\2", s)
    s = _HTML.sub("", s)
    s = _MD_HEADING.sub("", s)
    s = _MD_BULLET.sub("", s)
    s = _BACKTICK.sub(r"\1", s)
    s = clean_text(s)
    s = _SPACE_PUNCT.sub(r"\1", s)
    s = _OPEN_SPACE.sub(r"\1", s)
    return s


_EMPTY_BRACKETS = re.compile(r"\(\s*(?:[,;/]|and|or)?\s*\)|\[\s*\]", re.IGNORECASE)
_DANGLING = re.compile(r"(?:\s*(?:,|;|\band\b|\bor\b))+\s*(?=[.,;)])", re.IGNORECASE)
_DOUBLE_PUNCT = re.compile(r"([.,;:])\s*(?:[.,;:]\s*)+")
_WS = re.compile(r"\s+")


def dense_strip_ids(text: str) -> str:
    """Remove ATT&CK IDs and CVE IDs from text meant for the dense encoder, tidying what they leave
    behind. The stored description keeps them."""
    if not text:
        return text
    s = strip_cve_ids(text)
    if _ANY_ATTACK_ID.search(s):
        s = _ANY_ATTACK_ID.sub("", s)
        for _ in range(3):
            s = _EMPTY_BRACKETS.sub("", s)
            s = _DANGLING.sub("", s)
        s = _SPACE_PUNCT.sub(r"\1", s)
        s = _DOUBLE_PUNCT.sub(r"\1 ", s)
        s = _WS.sub(" ", s).strip()
    return s


# --------------------------------------------------------------------------- name tokens
# "Fine" tokens: runs of letters or of digits. "APT 29", "APT29" and "apt-29" all give [apt, 29];
# "BADNEWS" gives [badnews] while "bad news" gives [bad, news].
_FINE = re.compile(r"[^\W\d_]+|\d+")


def _norm_token(t: str) -> str:
    return t.lower() if t.isascii() else alias_norm(t)


def fine_tokens(text: str) -> list[str]:
    return [k for k in (_norm_token(t) for t in _FINE.findall(text or "")) if k]


def fine_token_spans(text: str) -> list[tuple[str, int, int]]:
    """(normalised token, start, end) for each letter run or digit run of `text`."""
    out = []
    for m in _FINE.finditer(text or ""):
        k = _norm_token(m.group(0))
        if k:
            out.append((k, m.start(), m.end()))
    return out
