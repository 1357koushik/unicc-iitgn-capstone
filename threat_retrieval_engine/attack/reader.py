"""Read API for a built C9 ATT&CK store.

    from threat_retrieval_engine.attack import AttackStore
    with AttackStore.open() as a:                     # newest build under data/attack (or $TRE_ATTACK_DIR)
        a.get("attack:G0016")                         # dict, JSON columns decoded; None if absent
        a.get("T1086")                                # ATT&CK IDs work too (no redirection)
        a.resolve_id("T1086")                         # the active document, following revocation
        for row in a.iter_searchable(columns=("doc_id", "title", "aliases", "description", "dense_text")):
            ...                                       # the fields C1 CVE rows also carry, same meaning
        a.find_name("Cozy Bear")                      # [{doc_id, doc_kind, name, surface, origin, policy, ...}]
        a.edges("attack:G0016", direction="out")      # graph edges with ATT&CK IDs and STIX relationship IDs
        a.cve_links("attack:T1190"); a.docs_for_cve("CVE-2021-44228")
        a.gazetteer().match("APT29 used Cobalt Strike")

The store is opened read-only. The parser (C4), lexical index (C2), dense index (C3) and pipeline (C6)
use this API instead of reading the SQLite schema directly.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Iterable, Iterator

from .gazetteer import Gazetteer
from .schema import JSON_COLUMNS, OBJECT_COLUMNS
from .text import alias_norm, normalize_attack_id

DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "attack"
EDGE_COLUMNS = ("rel_stix_id", "rel_type", "src_doc_id", "dst_doc_id", "src_attack_id", "dst_attack_id",
                "description", "orig_src_doc_id", "orig_dst_doc_id", "redirected", "created", "modified")


def default_root() -> Path:
    env = os.environ.get("TRE_ATTACK_DIR")
    return Path(env) if env else DEFAULT_ROOT


def resolve_attack_build(path: Path | str | None = None) -> Path:
    """A build directory from: a build dir, an attack.sqlite path, or a root holding LATEST."""
    p = Path(path) if path is not None else default_root()
    if p.is_file() and p.name == "attack.sqlite":
        return p.parent
    if (p / "attack.sqlite").is_file():
        return p
    latest = p / "LATEST"
    if latest.is_file():
        d = p / latest.read_text(encoding="utf-8").strip()
        if (d / "attack.sqlite").is_file():
            return d
    raise FileNotFoundError(f"no C9 ATT&CK build found at {p}")


def to_doc_id(identifier: str) -> str | None:
    """'attack:T1059.001', 'T1059.001' or 't1059/001' -> 'attack:T1059.001'; None when not an ATT&CK ID."""
    aid = normalize_attack_id(identifier)
    return f"attack:{aid}" if aid else None


class AttackStore:
    def __init__(self, build_dir: Path | str):
        self.build_dir = resolve_attack_build(build_dir)
        self.path = self.build_dir / "attack.sqlite"
        self._db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
        self._lock = threading.RLock()
        self._manifest: dict | None = None
        self._meta = dict(self._q("SELECT key, value FROM meta"))
        # small, hot fields of every object, held in memory for resolution and labels
        self._brief: dict[str, dict] = {}
        for r in self._q("SELECT doc_id, attack_id, doc_kind, name, title, state, searchable, revoked_by FROM objects"):
            self._brief[r[0]] = dict(zip(("doc_id", "attack_id", "doc_kind", "name", "title", "state", "searchable",
                                          "revoked_by"), r))
        self._gazetteer: Gazetteer | None = None
        self._adj: tuple[dict, dict] | None = None

    # ------------------------------------------------------------------ lifecycle
    @classmethod
    def open(cls, path: Path | str | None = None) -> "AttackStore":
        return cls(resolve_attack_build(path))

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "AttackStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _q(self, sql: str, params: Iterable = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchall()

    # ------------------------------------------------------------------ metadata
    @property
    def manifest(self) -> dict:
        if self._manifest is None:
            mp = self.build_dir / "manifest.json"
            self._manifest = json.loads(mp.read_text(encoding="utf-8")) if mp.is_file() else {}
        return self._manifest

    @property
    def build_id(self) -> str:
        return self._meta.get("build_id", self.build_dir.name)

    @property
    def attack_version(self) -> str | None:
        return self._meta.get("attack_version")

    @property
    def c1_store_build_id(self) -> str | None:
        return self._meta.get("c1_store_build_id")

    @property
    def gazetteer_policy(self) -> dict:
        return json.loads(self._meta["gazetteer_policy"])

    def count(self, searchable: bool | None = None, kind: str | None = None) -> int:
        return sum(1 for b in self._brief.values()
                   if (searchable is None or b["searchable"] == int(searchable)) and (kind is None or b["doc_kind"] == kind))

    # ------------------------------------------------------------------ documents
    @staticmethod
    def _decode(cols: Iterable[str], values: tuple) -> dict:
        return {c: (json.loads(v) if c in JSON_COLUMNS and v is not None else v) for c, v in zip(cols, values)}

    @staticmethod
    def _cols(columns: Iterable[str] | None) -> list[str]:
        cols = list(columns) if columns else list(OBJECT_COLUMNS)
        bad = [c for c in cols if c not in OBJECT_COLUMNS]
        if bad:
            raise ValueError(f"unknown columns {bad}")
        return cols

    def brief(self, identifier: str) -> dict | None:
        """{doc_id, attack_id, doc_kind, name, title, state, searchable, revoked_by} from memory."""
        d = to_doc_id(identifier)
        return dict(self._brief[d]) if d in self._brief else None

    def get(self, identifier: str, columns: Iterable[str] | None = None) -> dict | None:
        """The stored document for a doc_id or ATT&CK ID, whatever its state (no redirection)."""
        d = to_doc_id(identifier)
        if d is None or d not in self._brief:
            return None
        cols = self._cols(columns)
        row = self._q(f"SELECT {', '.join(cols)} FROM objects WHERE doc_id = ?", (d,))
        return self._decode(cols, row[0]) if row else None

    def get_many(self, identifiers: Iterable[str], columns: Iterable[str] | None = None) -> dict[str, dict]:
        cols = self._cols(columns)
        if "doc_id" not in cols:
            cols = ["doc_id"] + cols
        ids = sorted({d for d in (to_doc_id(x) for x in identifiers) if d and d in self._brief})
        out: dict[str, dict] = {}
        for i in range(0, len(ids), 500):
            part = ids[i:i + 500]
            for row in self._q(f"SELECT {', '.join(cols)} FROM objects WHERE doc_id IN ({','.join('?' * len(part))})",
                               part):
                d = self._decode(cols, row)
                out[d["doc_id"]] = d
        return out

    def resolve_id(self, identifier: str) -> dict | None:
        """The active document an ATT&CK ID stands for: itself when active, its replacement when revoked,
        None when unknown or deprecated. The result carries `resolved_from` when redirected."""
        b = self.brief(identifier)
        if b is None:
            return None
        if b["state"] == "active":
            return b
        if b["state"] == "revoked" and b["revoked_by"] in self._brief:
            out = dict(self._brief[b["revoked_by"]])
            out["resolved_from"] = b["doc_id"]
            return out
        return None

    def iter_searchable(self, columns: Iterable[str] | None = None, kinds: Iterable[str] | None = None,
                        batch: int = 500) -> Iterator[dict]:
        """Searchable documents in doc_id order (streamed)."""
        cols = self._cols(columns)
        where = "searchable = 1"
        params: list = []
        if kinds:
            ks = list(kinds)
            where += f" AND doc_kind IN ({','.join('?' * len(ks))})"
            params += ks
        with self._lock:
            rows = self._db.execute(f"SELECT {', '.join(cols)} FROM objects WHERE {where} ORDER BY doc_id",
                                    params).fetchall()
        for i in range(0, len(rows), batch):
            for r in rows[i:i + batch]:
                yield self._decode(cols, r)

    def iter_rows(self, columns: Iterable[str] | None = None) -> Iterator[dict]:
        cols = self._cols(columns)
        for r in self._q(f"SELECT {', '.join(cols)} FROM objects ORDER BY doc_id"):
            yield self._decode(cols, r)

    # ------------------------------------------------------------------ names
    def gazetteer(self) -> Gazetteer:
        with self._lock:
            if self._gazetteer is None:
                ents = [dict(zip(("key", "doc_id", "doc_kind", "surface", "origin", "fine_tokens"), r)) for r in
                        self._db.execute("SELECT key, doc_id, doc_kind, surface, origin, fine_tokens FROM gazetteer")]
                keys = [dict(zip(("key", "n_docs", "kinds", "policy", "reason", "df_cve"), r)) for r in
                        self._db.execute("SELECT key, n_docs, kinds, policy, reason, df_cve FROM gazetteer_keys")]

                def rid(aid: str):
                    r = self.resolve_id(aid)
                    return (r["doc_id"], r["doc_kind"], "revoked_id" if "resolved_from" in r else "id") if r else None

                self._gazetteer = Gazetteer.from_rows(ents, keys, self.gazetteer_policy, rid)
            return self._gazetteer

    def find_name(self, name: str, kinds: Iterable[str] | None = None) -> list[dict]:
        """Exact normalised name/alias lookup: every match, with its kind, ATT&CK name, the spelling that
        matched, how (name | qualified_name | alias | revoked_name), the key's policy and ambiguity."""
        g = self.gazetteer()
        key = alias_norm(name)
        info = g.key_info.get(key, {})
        out = []
        for c in g.lookup(name, kinds):
            b = self._brief[c.doc_id]
            out.append({"doc_id": c.doc_id, "attack_id": b["attack_id"], "doc_kind": c.doc_kind, "name": b["name"],
                        "title": b["title"], "surface": c.surface, "origin": c.origin,
                        "policy": info.get("policy"), "ambiguous": info.get("n_docs", 1) > 1})
        return out

    # ------------------------------------------------------------------ graph
    def _adjacency(self) -> tuple[dict, dict]:
        with self._lock:
            if self._adj is None:
                out: dict[str, list[dict]] = {}
                inc: dict[str, list[dict]] = {}
                for r in self._db.execute(f"SELECT {', '.join(EDGE_COLUMNS)} FROM edges ORDER BY rel_stix_id"):
                    e = dict(zip(EDGE_COLUMNS, r))
                    out.setdefault(e["src_doc_id"], []).append(e)
                    inc.setdefault(e["dst_doc_id"], []).append(e)
                self._adj = (out, inc)
            return self._adj

    def edges(self, identifier: str, direction: str = "out", rel_type: str | None = None) -> list[dict]:
        """Edges at a document (as stored; no redirection of `identifier`). Each edge carries both ATT&CK IDs,
        the relationship type, the STIX relationship ID and the cleaned relationship description."""
        d = to_doc_id(identifier)
        if d is None:
            return []
        out, inc = self._adjacency()
        es = (out.get(d, []) if direction in ("out", "both") else []) + \
             (inc.get(d, []) if direction in ("in", "both") else [])
        return [dict(e) for e in es if rel_type is None or e["rel_type"] == rel_type]

    def edge_count(self) -> int:
        return self._q("SELECT COUNT(*) FROM edges")[0][0]

    def iter_edges(self) -> Iterator[dict]:
        out, _ = self._adjacency()
        for es in out.values():
            for e in es:
                yield dict(e)

    def has_edge(self, src: str, rel_type: str, dst: str) -> bool:
        s, d = to_doc_id(src), to_doc_id(dst)
        return any(e["dst_doc_id"] == d and e["rel_type"] == rel_type for e in self._adjacency()[0].get(s, []))

    # ------------------------------------------------------------------ CVE links
    def cve_links(self, identifier: str) -> list[dict]:
        d = to_doc_id(identifier)
        cols = ("doc_id", "cve_id", "evidence_kind", "evidence_ref", "role", "detail")
        return [{**dict(zip(cols, r)), "detail": json.loads(r[5])} for r in
                self._q(f"SELECT {', '.join(cols)} FROM cve_links WHERE doc_id = ? ORDER BY cve_id, evidence_kind, "
                        "evidence_ref, role", (d,))]

    def docs_for_cve(self, cve_id: str) -> list[dict]:
        cols = ("doc_id", "cve_id", "evidence_kind", "evidence_ref", "role", "detail")
        return [{**dict(zip(cols, r)), "detail": json.loads(r[5])} for r in
                self._q(f"SELECT {', '.join(cols)} FROM cve_links WHERE cve_id = ? ORDER BY doc_id, evidence_kind, "
                        "evidence_ref, role", ((cve_id or "").strip().upper(),))]

    def rejected(self, source: str | None = None) -> list[tuple[str, str, str, str]]:
        if source:
            return self._q("SELECT source, record_id, reason, detail FROM rejected WHERE source = ?", (source,))
        return self._q("SELECT source, record_id, reason, detail FROM rejected")
