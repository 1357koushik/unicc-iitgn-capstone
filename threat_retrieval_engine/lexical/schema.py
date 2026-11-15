"""Layout of a C2 lexical index build (one SQLite file, ``lexical.sqlite``, plus ``manifest.json``).

Tables
------
``lex``     FTS5, contentless (``content=''``), ``detail=full``, one row per searchable document. Every column
            holds pre-tokenized text: the domain tokenizer's tokens joined by single spaces. The FTS5
            tokenizer is ``ascii`` with the tokenizer's joiners as token characters, under which such text
            re-tokenizes to exactly the same tokens (verified for every term at build time).
``docs``    rowid -> doc_id, doc_kind, number of tokens per column (JSON), sha256 of the indexed text.
``vocab``   term -> document frequency, collection frequency (from ``fts5vocab``) and the term's row in the
            impact matrix. Read by the query builder.

Impact matrix (``impact_indptr/indices/data/rowids.npy``): row ``tid`` holds, for every document containing
the term, its bm25() contribution under the build's column weights (``meta.impact_weights``), computed as
FTS5 computes it; ``indices`` are document positions (insertion order: kinds in build order, doc_id order
inside a kind), ``rowids`` maps a position to its rowid. ``meta.kind_doc_range`` gives each kind's positions.
``meta``    key/value: format version, tokenizer key, counts, hashes.

Document kinds and rowids
-------------------------
A CVE's rowid is derived from its ID (``year * 10**9 + number``), so it is stable across builds and an
incremental update (D1) can address a CVE without a lookup. Other kinds (ATT&CK objects, C9) get rowids
``base + ordinal`` in doc_id order inside their own range; a search can be restricted to one kind by a rowid
range, which FTS5 evaluates inside the index.

Columns
-------
``ids``             the document's own identifier (CVE ID; ATT&CK ID). Kept apart from the prose so a query
                    naming a CVE ranks that CVE first and not the CVEs whose text merely cites it.
``title``           CNA title (ATT&CK: object name)
``aliases``         nicknames and advisory IDs (C1 ``aliases`` field; ATT&CK: aliases)
``vendor_product``  humanised vendor/product labels
``description``     best English description
``weakness``        CWE IDs with names and CNA problem types
``kev_text``        KEV vulnerability name and short description
``exploit_titles``  distinct Exploit-DB / Metasploit / nuclei titles that name the CVE (C1 aliases of kind
                    ``title``); these are store expansion sources, never benchmark query sources
"""
from __future__ import annotations

LEXICAL_FORMAT = "c2-lexical-1"

COLUMNS = ("ids", "title", "aliases", "vendor_product", "description", "weakness", "kev_text", "exploit_titles")

KIND_RANGES: dict[str, tuple[int, int]] = {
    # kind: (first rowid, last rowid) inclusive
    "cve": (1999 * 10**9, 2999 * 10**9 + 10**9 - 1),
    "attack": (10**14, 2 * 10**14 - 1),
}

CVE_NUMBER_LIMIT = 10**9
# impact matrix files next to the index (impact_<name>.npy): term-major CSR of bm25 contributions
IMPACT_FILES = ("indptr", "indices", "data", "rowids")
BM25_K1 = 1.2  # fixed inside FTS5 bm25()
BM25_B = 0.75


def cve_rowid(cve_id: str) -> int:
    _, y, n = cve_id.split("-")
    year, num = int(y), int(n)
    if not 1999 <= year <= 2999 or num >= CVE_NUMBER_LIMIT:
        raise ValueError(f"{cve_id}: outside the CVE rowid scheme")
    return year * 10**9 + num


def cve_id_from_rowid(rowid: int) -> str:
    year, num = divmod(rowid, 10**9)
    return f"CVE-{year}-{num:04d}"


def kind_of_rowid(rowid: int) -> str | None:
    for kind, (lo, hi) in KIND_RANGES.items():
        if lo <= rowid <= hi:
            return kind
    return None


def ddl(tokenize_option: str) -> str:
    cols = ", ".join(COLUMNS)
    tok = tokenize_option.replace('"', '""')
    return f"""
CREATE VIRTUAL TABLE lex USING fts5({cols}, content='', detail=full, columnsize=1, tokenize="{tok}");
CREATE TABLE docs (
    rowid        INTEGER PRIMARY KEY,
    doc_id       TEXT NOT NULL UNIQUE,
    doc_kind     TEXT NOT NULL,
    column_tokens TEXT NOT NULL,   -- JSON list: tokens per column, in COLUMNS order
    text_sha256  TEXT NOT NULL     -- sha256 of the indexed (pre-tokenized) text of all columns
);
CREATE TABLE vocab (
    term TEXT PRIMARY KEY,
    df   INTEGER NOT NULL,         -- documents containing the term (any column)
    cf   INTEGER NOT NULL,         -- occurrences of the term in the index
    tid  INTEGER NOT NULL          -- row of the term in the impact matrix (terms in sorted order)
) WITHOUT ROWID;
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"""
