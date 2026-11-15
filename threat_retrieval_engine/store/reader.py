"""Read API for a built C1 document store.

    from threat_retrieval_engine.store import Store
    with Store.open() as s:                       # newest build under data/store (or $TRE_STORE_DIR)
        row = s.get("CVE-2021-44228")             # dict, JSON columns decoded; None if not in the universe
        for row in s.iter_searchable(columns=("cve_id", "dense_text", "content_hash")):
            ...
        s.find_alias("Log4Shell")                 # [(cve_id, alias, kind, source), ...]

The store is opened read-only. Later packages (lexical index C2, dense index C3, parser C4, pipeline C6,
incremental update D1) use this API instead of reading the SQLite schema directly.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

from .schema import CVE_COLUMNS, JSON_COLUMNS
from .text import alias_norm, normalize_cve_id

DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "store"


def default_root() -> Path:
    env = os.environ.get("TRE_STORE_DIR")
    return Path(env) if env else DEFAULT_ROOT


def resolve_build(path: Path | str | None = None) -> Path:
    """A build directory from: a build dir, a store.sqlite path, or a store root holding LATEST."""
    p = Path(path) if path is not None else default_root()
    if p.is_file() and p.name == "store.sqlite":
        return p.parent
    if (p / "store.sqlite").is_file():
        return p
    latest = p / "LATEST"
    if latest.is_file():
        d = p / latest.read_text(encoding="utf-8").strip()
        if (d / "store.sqlite").is_file():
            return d
    raise FileNotFoundError(f"no C1 store build found at {p}")


class Store:
    def __init__(self, build_dir: Path | str):
        self.build_dir = resolve_build(build_dir)
        self.path = self.build_dir / "store.sqlite"
        self._db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
        self._manifest: dict | None = None

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def open(cls, path: Path | str | None = None) -> "Store":
        return cls(resolve_build(path))

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ metadata
    @property
    def manifest(self) -> dict:
        if self._manifest is None:
            mp = self.build_dir / "manifest.json"
            self._manifest = json.loads(mp.read_text(encoding="utf-8")) if mp.is_file() else {}
        return self._manifest

    @property
    def build_id(self) -> str:
        row = self._db.execute("SELECT value FROM meta WHERE key = 'build_id'").fetchone()
        return row[0] if row else self.build_dir.name

    def count(self, searchable: bool | None = None) -> int:
        if searchable is None:
            return self._db.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        return self._db.execute("SELECT COUNT(*) FROM cve WHERE searchable = ?", (int(searchable),)).fetchone()[0]

    # ------------------------------------------------------------------ rows
    @staticmethod
    def _decode(cols: Iterable[str], values: tuple) -> dict:
        out = {}
        for c, v in zip(cols, values):
            out[c] = json.loads(v) if c in JSON_COLUMNS and v is not None else v
        return out

    def _cols(self, columns: Iterable[str] | None) -> list[str]:
        cols = list(columns) if columns else list(CVE_COLUMNS)
        bad = [c for c in cols if c not in CVE_COLUMNS]
        if bad:
            raise ValueError(f"unknown columns {bad}")
        return cols

    def get(self, cve_id: str, columns: Iterable[str] | None = None) -> dict | None:
        cid = normalize_cve_id(cve_id)
        if cid is None:
            return None
        cols = self._cols(columns)
        row = self._db.execute(f"SELECT {', '.join(chr(34) + c + chr(34) for c in cols)} FROM cve WHERE cve_id = ?",
                               (cid,)).fetchone()
        return self._decode(cols, row) if row else None

    def get_many(self, cve_ids: Iterable[str], columns: Iterable[str] | None = None) -> dict[str, dict]:
        cols = self._cols(columns)
        if "cve_id" not in cols:
            cols = ["cve_id"] + cols
        ids = sorted({c for c in (normalize_cve_id(x) for x in cve_ids) if c})
        out: dict[str, dict] = {}
        qc = ", ".join(chr(34) + c + chr(34) for c in cols)
        for i in range(0, len(ids), 500):
            part = ids[i:i + 500]
            for row in self._db.execute(f"SELECT {qc} FROM cve WHERE cve_id IN ({','.join('?' * len(part))})", part):
                d = self._decode(cols, row)
                out[d["cve_id"]] = d
        return out

    def iter_rows(self, columns: Iterable[str] | None = None, searchable_only: bool = False,
                  batch: int = 2000) -> Iterator[dict]:
        """Rows in CVE ID (text) order; streamed, so the whole store is never in memory."""
        cols = self._cols(columns)
        qc = ", ".join(chr(34) + c + chr(34) for c in cols)
        where = "WHERE searchable = 1" if searchable_only else ""
        cur = self._db.execute(f"SELECT {qc} FROM cve {where} ORDER BY cve_id")
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                return
            for r in rows:
                yield self._decode(cols, r)

    def iter_searchable(self, columns: Iterable[str] | None = None, batch: int = 2000) -> Iterator[dict]:
        return self.iter_rows(columns, searchable_only=True, batch=batch)

    def changed_since(self) -> dict[str, str]:
        """cve_id -> added|changed|removed against the --previous build (empty if none was given)."""
        return dict(self._db.execute("SELECT cve_id, change FROM changes"))

    # ------------------------------------------------------------------ aliases
    def aliases(self, cve_id: str, kinds: Iterable[str] = ("nickname", "advisory_id", "title")) -> list[dict]:
        cid = normalize_cve_id(cve_id)
        kinds = list(kinds)
        rows = self._db.execute(
            f"SELECT alias, alias_norm, kind, source, source_record_id, position, record_cves FROM aliases "
            f"WHERE cve_id = ? AND kind IN ({','.join('?' * len(kinds))}) ORDER BY kind, alias_norm, source",
            [cid, *kinds]).fetchall()
        keys = ("alias", "alias_norm", "kind", "source", "source_record_id", "position", "record_cves")
        return [dict(zip(keys, r)) for r in rows]

    def find_alias(self, name: str, kinds: Iterable[str] = ("nickname", "advisory_id")) -> list[tuple[str, str, str, str]]:
        """CVEs carrying an alias whose normalised form equals that of `name`."""
        kinds = list(kinds)
        return self._db.execute(
            f"SELECT DISTINCT cve_id, alias, kind, source FROM aliases WHERE alias_norm = ? "
            f"AND kind IN ({','.join('?' * len(kinds))}) ORDER BY cve_id, source",
            [alias_norm(name), *kinds]).fetchall()

    def rejected_records(self, source: str | None = None) -> list[tuple[str, str, str, str]]:
        if source:
            return self._db.execute("SELECT source, record_id, reason, detail FROM rejected_records WHERE source = ?",
                                    (source,)).fetchall()
        return self._db.execute("SELECT source, record_id, reason, detail FROM rejected_records").fetchall()
