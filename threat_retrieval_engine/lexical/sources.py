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


class AttackSqliteReader:
    """Minimal read-only reader of a C9 ATT&CK build (``attack.sqlite``), used when C9's package is not on the
    path: the ``objects`` table, active and searchable rows, in doc_id order. With C9's code present,
    ``threat_retrieval_engine.attack.reader.AttackStore`` is used instead (same rows)."""

    def __init__(self, build_dir):
        import sqlite3
        from pathlib import Path
        p = Path(build_dir)
        if (p / "LATEST").is_file() and not (p / "attack.sqlite").is_file():
            p = p / (p / "LATEST").read_text(encoding="utf-8").strip()
        self.build_dir = p
        self.path = p / "attack.sqlite"
        if not self.path.is_file():
            raise FileNotFoundError(f"no C9 ATT&CK build (attack.sqlite) at {build_dir}")
        self._db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
        meta = dict(self._db.execute("SELECT key, value FROM meta"))
        self.build_id = meta.get("build_id", p.name)

    def iter_searchable(self):
        import json
        for doc_id, title, aliases, description in self._db.execute(
                "SELECT doc_id, title, aliases, description FROM objects WHERE searchable = 1 AND state = 'active' "
                "ORDER BY doc_id"):
            if isinstance(aliases, str) and aliases.startswith("["):
                aliases = json.loads(aliases)
            yield {"doc_id": doc_id, "title": title, "aliases": aliases, "description": description}


def open_attack(build_dir) -> RowSource:
    """RowSource over a C9 build: C9's reader when importable, else ``AttackSqliteReader``."""
    try:
        from ..attack.reader import AttackStore  # type: ignore[import-not-found]
        store = AttackStore.open(build_dir)
        rows = lambda: (r for r in store.iter_searchable(columns=("doc_id", "title", "aliases", "description",
                                                                     "state")) if r.get("state", "active") == "active")
        bid = store.build_id
    except ImportError:
        store = AttackSqliteReader(build_dir)
        rows, bid = store.iter_searchable, store.build_id
    return RowSource("attack", rows, {"title": "title", "aliases": "aliases", "description": "description"},
                     describe={"attack_build_id": bid, "attack_path": str(build_dir), "reader": type(store).__name__})

