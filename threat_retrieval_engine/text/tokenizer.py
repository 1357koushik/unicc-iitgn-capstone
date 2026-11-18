"""Shared domain tokenizer for retrieval (plan 4.5). Standard library only.

One function, ``tokenize(text, config)``, is used for the lexical index (C2), for lexical queries, and by
anything else that needs terms (the query parser C4). Index and query text go through the same code, and the
tokens are written into SQLite FTS5 pre-tokenized (see ``fts5_tokenize_option``), so the two sides can never
tokenize differently.

Pipeline
--------
1. Unicode: NFKC, case folding, NFKC again. Every Unicode dash becomes ``-``, a backslash becomes ``/``
   (Windows paths), apostrophes inside words are dropped (``attacker's`` -> ``attackers``).
2. Identifier normalisation: CVE and CWE identifiers written with spaces, underscores or missing dashes
   (``CVE 2021 44228``, ``cve_2021_44228``, ``CWE79``) become the canonical ``cve-2021-44228`` and ``cwe-79``.
3. Raw tokens are maximal runs of word characters (letters, digits, combining marks, underscore) joined by
   single ``-``, ``.``, ``/`` or ``_`` characters: ``2.15.0``, ``1.0.1g``, ``log4j-core``,
   ``/etc/passwd``, ``mysql_real_escape_string``, ``org.apache.log4j``, ``185.123.45.10``. Leading and
   trailing joiners are stripped.
4. Each raw token is emitted whole (the *compound*) and, when it has joiners, also as its parts (the *split
   form*), so ``log4j-core`` matches both ``log4j-core`` and ``log4j``. CVE and CWE IDs, version strings
   and IPv4 addresses are only emitted whole: their parts (``2021``, ``15``, ``0``) are noise.
   Pure-digit parts are dropped from split forms for the same reason.
5. Trailing-digit variant: a letters-then-digits word such as ``log4j2``, ``windows10``, ``http2`` also
   emits the word without its trailing digits (``log4j``, ``windows``, ``http``), when at least three
   characters remain and the remainder ends in a letter.
6. English stemming (Porter2) of purely alphabetic ASCII tokens; identifiers and compounds are never stemmed.

Which of steps 4-6 are on, and the query-side stop words, were decided by measurement on the benchmark's
train and dev splits; the measured settings are ``DEFAULT_CONFIG`` and the numbers are in the C2 entry of
docs/RETRIEVAL_V2_PLAN.md section 12.

Every token consists only of lower-case letters, digits, combining marks, underscore and the joiners
``-./`` (``TOKEN_RE``); it never contains a quote, space or any other ASCII punctuation. That property is
what makes the FTS5 side safe and exact: the ``ascii`` FTS5 tokenizer with ``tokenchars '-./_'`` treats
exactly these characters as token characters (all non-ASCII characters are token characters in the ascii
tokenizer), so a space-joined token list is re-tokenized into the same list, and a token wrapped in double
quotes is a single FTS5 string term.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, replace
from functools import lru_cache

from .porter2 import stem as porter2_stem

TOKENIZER_NAME = "tre-domain"
# Bump when tokenize() output can change for any input; the lexical index refuses a different version.
TOKENIZER_VERSION = "1"
JOINERS = "-./_"
FTS5_TOKENCHARS = JOINERS  # characters FTS5 must treat as part of a token


def _mark_class() -> str:
    """Regex character class body for every combining mark (Unicode category M*) in this Python's Unicode
    database, so scripts that use vowel signs (Devanagari, Thai, ...) keep whole words."""
    ranges = []
    start = prev = None
    # Combining marks live in U+0300..U+1FFFF and the variation selectors supplement (U+E0100..U+E01EF);
    # scanning only those keeps import time low.
    for cp in (*range(0x300, 0x20000), *range(0xE0100, 0xE01F0)):
        if unicodedata.category(chr(cp))[0] == "M":
            if start is None:
                start = prev = cp
            elif cp == prev + 1:
                prev = cp
            else:
                ranges.append((start, prev))
                start = prev = cp
    if start is not None:
        ranges.append((start, prev))
    return "".join(f"\\U{a:08x}" if a == b else f"\\U{a:08x}-\\U{b:08x}" for a, b in ranges)


_MARKS = _mark_class()
_W = r"[\w" + _MARKS + r"]"  # \w already includes letters, digits and underscore
_RAW_TOKEN = re.compile(_W + r"+(?:[-./]" + _W + r"+)*")
_ASCII_TOKEN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789" + JOINERS)

_DASHES = re.compile(r"[‐-―−⸺⸻﹘﹣－֊־᠆⁓]")
_APOS_IN_WORD = re.compile(r"(?<=\w)['’ʼ‘](?=\w)")
_CVE_VARIANT = re.compile(r"(?<![a-z0-9])cve[\s_\-:#]*(\d{4})[\s_\-:#]*(\d{4,7})(?![0-9])")
_CWE_VARIANT = re.compile(r"(?<![a-z0-9])cwe[\s_\-:#]*(\d{1,5})(?![0-9])")
_CVE_ID = re.compile(r"^cve-\d{4}-\d{4,7}$")
_CWE_ID = re.compile(r"^cwe-\d{1,5}$")
_VERSION = re.compile(r"^v?\d+(?:\.\d+)+[a-z]{0,2}\d{0,2}$")  # 2.15.0, 1.0.1g, v3.2, 7.1.0rc1
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SPLIT = re.compile(r"[-./_]+")
_TRAILING_DIGITS = re.compile(r"^([a-z][a-z0-9]*[a-z])(\d+)$")
_ASCII_ALPHA = re.compile(r"^[a-z]+$")
_DIGITS = re.compile(r"^\d+$")

STEMMERS = ("none", "porter2")

# Query-side stop words: the Lucene / Snowball English stop set (articles, auxiliaries, pronouns,
# prepositions). Applied to queries only; the index keeps every token so document lengths are true.
ENGLISH_STOP_WORDS = frozenset("""
a an and are as at be but by for if in into is it no not of on or such that the their then there these
they this to was will with
i me my we our you your he him his she her its them what which who whom those am been being have has had
do does did doing would should could can may might must shall from about above after again against all
any before below between both down during each few further here how more most other out over own same so
some than too under until up very when where why while off once only nor just now
""".split())


@dataclass(frozen=True)
class TokenizerConfig:
    split_compounds: bool = True   # emit the parts of joined tokens as well as the whole
    trailing_digits: bool = True   # log4j2 -> also log4j
    stemmer: str = "porter2"       # none | porter2

    def __post_init__(self):
        if self.stemmer not in STEMMERS:
            raise ValueError(f"stemmer must be one of {STEMMERS}")

    def as_dict(self) -> dict:
        return {"name": TOKENIZER_NAME, "version": TOKENIZER_VERSION, **asdict(self)}

    def key(self) -> str:
        return (f"{TOKENIZER_NAME}-{TOKENIZER_VERSION}-split{int(self.split_compounds)}"
                f"-td{int(self.trailing_digits)}-{self.stemmer}")

    def with_(self, **kw) -> "TokenizerConfig":
        return replace(self, **kw)


DEFAULT_CONFIG = TokenizerConfig()


def fts5_tokenize_option() -> str:
    """The FTS5 ``tokenize`` option under which pre-tokenized text re-tokenizes to the same tokens."""
    return f"ascii tokenchars '{FTS5_TOKENCHARS}'"


def normalize(text: str) -> str:
    """Unicode and identifier normalisation (steps 1-2)."""
    s = unicodedata.normalize("NFKC", text)
    s = unicodedata.normalize("NFKC", s.casefold())
    s = _DASHES.sub("-", s).replace("\\", "/")
    s = _APOS_IN_WORD.sub("", s)
    if "cve" in s:
        s = _CVE_VARIANT.sub(lambda m: f" cve-{m.group(1)}-{m.group(2)} ", s)
    if "cwe" in s:
        s = _CWE_VARIANT.sub(lambda m: f" cwe-{int(m.group(1))} ", s)
    return s


def _strip_joiners(tok: str) -> str:
    return tok.strip(JOINERS)


@lru_cache(maxsize=200_000)
def _stem_cached(word: str) -> str:
    return porter2_stem(word)


def _finish(tok: str, cfg: TokenizerConfig) -> str:
    if cfg.stemmer == "porter2" and _ASCII_ALPHA.match(tok):
        return _stem_cached(tok)
    return tok


def _expand(raw: str, cfg: TokenizerConfig, out: list[str]) -> None:
    tok = _strip_joiners(raw)
    if not tok:
        return
    if _CVE_ID.match(tok) or _CWE_ID.match(tok) or _IPV4.match(tok):
        out.append(tok)
        return
    if _VERSION.match(tok):
        out.append(tok[1:] if tok.startswith("v") else tok)
        return
    has_joiner = any(j in tok for j in JOINERS)
    if not has_joiner:
        out.append(_finish(tok, cfg))
        _trailing(tok, cfg, out)
        return
    out.append(tok)  # the compound is never stemmed
    if cfg.split_compounds:
        for part in _SPLIT.split(tok):
            if not part or _DIGITS.match(part):
                continue
            out.append(_finish(part, cfg))
            _trailing(part, cfg, out)


def _trailing(tok: str, cfg: TokenizerConfig, out: list[str]) -> None:
    if not cfg.trailing_digits:
        return
    if len(tok) > 20:  # hashes and other long alphanumerics: no variant
        return
    m = _TRAILING_DIGITS.match(tok)
    if m and len(m.group(1)) >= 3:
        out.append(_finish(m.group(1), cfg))


def tokenize(text: str | None, config: TokenizerConfig = DEFAULT_CONFIG) -> list[str]:
    """Tokens of ``text`` in reading order (a compound is followed by its split forms)."""
    if not text:
        return []
    s = normalize(text)
    out: list[str] = []
    for m in _RAW_TOKEN.finditer(s):
        _expand(m.group(0), config, out)
    return out


def is_valid_token(tok: str) -> bool:
    """True when ``tok`` has the shape every emitted token has: non-empty, ASCII characters only from
    ``[a-z0-9]`` and the joiners, no joiner at either end. The FTS5 query builder checks this before placing
    a token inside a quoted MATCH string, so no character with a meaning in the FTS5 query syntax (quotes,
    parentheses, ``*``, ``^``, ``:``, ``+``, ``-`` at a term start, whitespace) can ever reach it."""
    if not tok or tok[0] in JOINERS or tok[-1] in JOINERS:
        return False
    return all(c in _ASCII_TOKEN_CHARS if ord(c) < 128 else not c.isspace() for c in tok)
