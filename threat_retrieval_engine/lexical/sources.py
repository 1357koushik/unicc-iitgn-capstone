"""Document sources for the lexical index.

A source yields ``(doc_id, {column: raw text})`` in doc_id order and describes its inputs for the manifest.
The CVE source reads the C1 store through ``store.Store``; ATT&CK documents (package C9) plug in through
``RowSource`` with the rows of C9's ``iter_searchable()`` (``doc_id``, ``title``, ``aliases``,
``description``; ``dense_text`` is not indexed lexically because it repeats the other fields).
"""
from __future__ import annotations

import hashlib
from typing import Callable, Iterable, Iterator, Protocol

from .schema import COLUMNS

CVE_FIELDS = ("title", "aliases", "vendor_product", "description", "weakness", "kev_text")


class DocumentSource(Protocol):
    kind: str

    def describe(self) -> dict: ...

    def count(self) -> int: ...

    def iter_documents(self) -> Iterator[tuple[str, dict[str, str]]]: ...


class CveStoreSource:
    """Searchable CVE rows of a C1 store build."""

    kind = "cve"

    def __init__(self, store):
        self.store = store

    def describe(self) -> dict:
        m = self.store.manifest
        return {"kind": self.kind, "store_build_id": self.store.build_id, "store_path": str(self.store.path),
                "store_version": m.get("store_version"), "store_inputs_sha256": m.get("inputs_sha256"),
                "store_searchable": self.store.count(searchable=True)}

    def count(self) -> int:
        return self.store.count(searchable=True)

    def iter_documents(self) -> Iterator[tuple[str, dict[str, str]]]:
        for row in self.store.iter_searchable(columns=("cve_id",) + CVE_FIELDS):
            cid = row["cve_id"]
            cols = {c: row.get(c) or "" for c in CVE_FIELDS}
            cols["ids"] = cid
            titles = sorted({a["alias"] for a in self.store.aliases(cid, kinds=("title",))})
            cols["exploit_titles"] = "; ".join(titles)
            yield cid, cols


class RowSource:
    """Any document kind given as rows with ``doc_id`` and text fields mapped onto index columns.

    ``fields`` maps an index column to a row key or to a callable ``row -> str``; ``ids`` defaults to the
    part of ``doc_id`` after the kind prefix (``attack:G0032`` -> ``G0032``)."""

    def __init__(self, kind: str, rows: Callable[[], Iterable[dict]], fields: dict[str, str | Callable],
                 describe: dict | None = None):
        bad = [c for c in fields if c not in COLUMNS]
        if bad:
            raise ValueError(f"unknown index columns {bad}")
        self.kind = kind
        self._rows = rows
        self.fields = dict(fields)
        self._describe = dict(describe or {})

    def _docs(self) -> list[tuple[str, dict[str, str]]]:
        out = []
        for row in self._rows():
            did = row["doc_id"]
            cols = {}
            for col, f in self.fields.items():
                v = f(row) if callable(f) else row.get(f)
                if isinstance(v, (list, tuple)):
                    v = "; ".join(str(x) for x in v)
                cols[col] = v or ""
            cols.setdefault("ids", did.split(":", 1)[1] if ":" in did else did)
            out.append((did, cols))
        out.sort(key=lambda d: d[0])
        return out

    def describe(self) -> dict:
        h = hashlib.sha256()
        n = 0
        for did, cols in self._docs():
            n += 1
            h.update(did.encode())
            for c in COLUMNS:
                h.update(b"\x1f" + (cols.get(c) or "").encode())
        return {"kind": self.kind, "documents": n, "rows_sha256": h.hexdigest(), **self._describe}

    def count(self) -> int:
        return len(self._docs())

    def iter_documents(self) -> Iterator[tuple[str, dict[str, str]]]:
        yield from self._docs()


def attack_source(attack_store) -> RowSource:
    """ATT&CK documents from C9's reader (``iter_searchable()`` rows with doc_id/title/aliases/description)."""
    return RowSource("attack", attack_store.iter_searchable,
                     {"title": "title", "aliases": "aliases", "description": "description"},
                     describe={"source": type(attack_store).__name__})
