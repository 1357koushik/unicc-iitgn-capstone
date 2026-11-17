"""Export the dense vectors v1 already computed (BGE-M3, Qdrant embedded storage) as a C3 build.

    python -m threat_retrieval_engine.dense.export_v1 rows   --qdrant <qdrant_storage> --out v1_rows.npz
    python -m threat_retrieval_engine.dense.export_v1 build  --rows v1_rows.npz --collapse max [--store ...] \\
        [--restrict reduced.jsonl] [--out data/dense] [--no-latest]

``rows`` reads v1's Qdrant embedded-mode storage (``collection/threat_intelligence_kb/storage.sqlite``)
strictly read-only (SQLite ``mode=ro&immutable=1``; nothing is written next to it, no Qdrant client and no
lock). Each point is a pickled ``PointStruct``; it is decoded by a restricted unpickler that resolves only the
two Qdrant model classes into plain state holders (any other global in a pickle is refused), so no code from
the file can run and the Qdrant client is not needed. Every point gives one row: its ``dense`` vector (1,024
floats, stored as float32, as BGE-M3 produced them) and its payload ``doc_id`` (``CVE-2021-44228``,
``CVE-2021-44228_KEV``, ``CVE-..._EPSS``, ...). The row file records the source file's sha256.

``build`` maps rows onto the searchable CVEs of a C1 store build (the CVE ID is the ``doc_id`` before any
``_SUFFIX``, the harness's ``cve_prefix`` rule) and collapses a CVE's rows:

* ``max``: every row kept; a CVE's score is the maximum cosine over its rows (``groups.npy``), which is how v1
  itself turned row hits into CVE hits;
* ``mean``: the normalised mean of the CVE's unit row vectors;
* ``primary``: the row whose doc_id is the bare CVE ID (v1's NVD/CVE-List row), else the first of KEV, EPSS,
  other suffixes in that order.

Rows whose CVE is not a searchable store CVE are dropped and counted (rejected since v1, or not a CVE ID);
searchable store CVEs without any v1 row are counted (coverage); v1 had no ATT&CK vectors.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import pickle
import re
import sqlite3
import sys
import time
from pathlib import Path

import numpy as np

from .build import DEFAULT_OUT, environment, sha256_file, write_build
from .index import GROUPS_FILE
from .models import MODELS, V1_VECTORS

CVE_PREFIX_RE = re.compile(r"^(CVE-\d{4}-\d{4,})(?:_([A-Za-z0-9]+))*$", re.IGNORECASE)
STORAGE_REL = "collection/threat_intelligence_kb/storage.sqlite"
ALLOWED = {("qdrant_client.http.models.models", "PointStruct"), ("qdrant_client.http.models.models", "SparseVector")}
SUFFIX_RANK = {"": 0, "KEV": 1, "EPSS": 2}


class _State:
    """Plain holder for a pickled pydantic model's state (no behaviour, no validation)."""

    def __setstate__(self, state):
        self.__dict__["_state"] = state

    def field(self, name):
        st = self.__dict__.get("_state")
        if isinstance(st, dict) and "__dict__" in st:
            return st["__dict__"].get(name)
        if isinstance(st, tuple) and st and isinstance(st[0], dict):
            return st[0].get(name)
        if isinstance(st, dict):
            return st.get(name)
        return None


class _PointStruct(_State):
    pass


class _SparseVector(_State):
    pass


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in ALLOWED:
            raise pickle.UnpicklingError(f"refusing global {module}.{name}")
        return _PointStruct if name == "PointStruct" else _SparseVector


def loads(blob: bytes):
    return RestrictedUnpickler(io.BytesIO(blob)).load()


def read_rows(qdrant_dir: Path, progress=print) -> dict:
    p = Path(qdrant_dir)
    db_path = p / STORAGE_REL if (p / STORAGE_REL).is_file() else p
    if not db_path.is_file():
        raise FileNotFoundError(f"no Qdrant storage at {qdrant_dir}")
    sha = sha256_file(db_path)
    db = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro&immutable=1", uri=True)
    n = db.execute("SELECT COUNT(*) FROM points").fetchone()[0]
    vecs = np.zeros((n, 1024), dtype=np.float32)
    doc_ids, chunk_ids, point_ids = [], [], []
    t0 = time.time()
    i = 0
    for pid, blob in db.execute("SELECT id, point FROM points ORDER BY id"):
        pt = loads(blob)
        vec = pt.field("vector")
        payload = pt.field("payload") or {}
        dense = vec.get("dense") if isinstance(vec, dict) else None
        if not isinstance(dense, list) or len(dense) != 1024:
            raise ValueError(f"point {pid}: no 1024-d dense vector")
        vecs[i] = np.asarray(dense, dtype=np.float32)
        doc_ids.append(str(payload.get("doc_id")))
        chunk_ids.append(str(payload.get("chunk_id")))
        point_ids.append(int(RestrictedUnpickler(io.BytesIO(base64.b64decode(pid))).load()))
        i += 1
        if i % 50000 == 0:
            progress(f"[v1] {i:,}/{n:,} points ({time.time() - t0:.0f} s)")
    db.close()
    if i != n:
        raise ValueError(f"read {i} of {n} points")
    return {"vectors": vecs, "doc_ids": np.asarray(doc_ids), "chunk_ids": np.asarray(chunk_ids),
            "point_ids": np.asarray(point_ids, dtype=np.uint64), "source_sha256": sha, "source_path": str(db_path),
            "points": n}


def cve_and_suffix(doc_id: str) -> tuple[str | None, str]:
    m = CVE_PREFIX_RE.match(doc_id.strip())
    if not m:
        return None, ""
    cid = m.group(1).upper()
    suffix = doc_id.strip()[len(cid):].lstrip("_").upper()
    return cid, suffix


def collapse(rows: dict, searchable: list[str], how: str) -> dict:
    """Map v1 rows onto ``searchable`` (sorted store CVE IDs). Returns vectors, doc_ids, groups (for max)."""
    pos = {c: i for i, c in enumerate(searchable)}
    by_cve: dict[str, list[tuple[int, str, int]]] = {}
    dropped: dict[str, int] = {"not_a_cve_id": 0, "cve_not_searchable_in_store": 0}
    suffixes: dict[str, int] = {}
    for r, d in enumerate(rows["doc_ids"].tolist()):
        cid, suf = cve_and_suffix(d)
        suffixes[suf or "(none)"] = suffixes.get(suf or "(none)", 0) + 1
        if cid is None:
            dropped["not_a_cve_id"] += 1
            continue
        if cid not in pos:
            dropped["cve_not_searchable_in_store"] += 1
            continue
        by_cve.setdefault(cid, []).append((SUFFIX_RANK.get(suf, 9), d, r))
    cves = sorted(by_cve)
    multi = sum(1 for c in cves if len(by_cve[c]) > 1)
    V = rows["vectors"]
    if how == "max":
        order, groups = [], []
        for c in cves:
            groups.append(len(order))
            order.extend(r for _, _, r in sorted(by_cve[c]))
        vec = V[np.asarray(order, dtype=np.int64)]
        g = np.asarray(groups, dtype=np.int64)
    elif how == "mean":
        vec = np.zeros((len(cves), V.shape[1]), dtype=np.float32)
        for i, c in enumerate(cves):
            rs = [r for _, _, r in by_cve[c]]
            m = V[rs].astype(np.float64)
            m /= np.linalg.norm(m, axis=1, keepdims=True)
            v = m.mean(axis=0)
            vec[i] = (v / np.linalg.norm(v)).astype(np.float32)
        g = None
    elif how == "primary":
        vec = V[np.asarray([sorted(by_cve[c])[0][2] for c in cves], dtype=np.int64)]
        g = None
    else:
        raise ValueError(f"unknown collapse {how!r}")
    if how != "mean":  # Qdrant stores cosine vectors normalised; renormalise in float64 to remove drift
        n = np.linalg.norm(vec.astype(np.float64), axis=1, keepdims=True)
        vec = (vec.astype(np.float64) / n).astype(np.float32)
    covered = set(cves)
    return {"vectors": np.ascontiguousarray(vec), "doc_ids": cves, "groups": g,
            "stats": {"points": int(len(rows["doc_ids"])), "rows_used": int(vec.shape[0]), "cves": len(cves),
                      "cves_with_several_rows": multi, "row_suffixes": dict(sorted(suffixes.items())),
                      "dropped_rows": dropped, "store_searchable": len(searchable),
                      "store_searchable_without_v1_vector": len(searchable) - len(covered)}}


def build_from_rows(rows_path: Path, how: str, store_path=None, out_root: Path = DEFAULT_OUT,
                    restrict: Path | None = None, set_latest: bool = True, progress=print) -> Path:
    from ..store import Store
    z = np.load(rows_path, allow_pickle=False)
    rows = {k: z[k] for k in z.files}
    meta = json.loads(str(rows["meta"]))
    with Store.open(store_path) as s:
        searchable = [r["cve_id"] for r in s.iter_searchable(columns=("cve_id",))]
        store_info = {"build_id": s.build_id, "path": str(s.build_dir), "searchable": len(searchable)}
    selection = {"rule": "all searchable store CVEs with a v1 vector"}
    if restrict is not None:
        from .sources import DocumentSet
        red = DocumentSet.read(restrict)
        if red.inputs.get("store", {}).get("build_id") != store_info["build_id"]:
            raise ValueError("restriction set comes from another store build")
        keep = set(red.doc_ids)
        searchable = [c for c in searchable if c in keep]
        selection = {"rule": "reduced corpus (CVE part) with a v1 vector", "restrict_documents_sha256": red.sha256(),
                     "restrict_file": str(restrict), "reduced_selection": red.selection}
    t0 = time.time()
    c = collapse(rows, sorted(searchable), how)
    spec = MODELS["bge-m3"]
    manifest = {
        "source": "v1_export",
        "collapse": how,
        "model": {**spec.as_dict(), "config_key": "v1-export", **V1_VECTORS,
                  "note": "documents embedded by v1 (Strategy-C context strings, no truncation); queries are encoded "
                          "with BGE-M3 at this revision"},
        "inputs": {"store": store_info, "v1_rows_file": str(rows_path), "v1_rows_sha256": sha256_file(rows_path),
                   "qdrant_storage_sha256": meta["source_sha256"], "qdrant_storage_path": meta["source_path"]},
        "selection": selection,
        "coverage": c["stats"],
    }
    extra = {}
    if c["groups"] is not None:
        manifest["row_groups"] = True
        manifest["rows"] = int(c["vectors"].shape[0])
        extra["groups"] = c["groups"]
    bdir = _write_with_groups(out_root, c, manifest, {"v1": meta["source_sha256"], "collapse": how,
                                                       "store": store_info["build_id"], "sel": selection["rule"]},
                              set_latest, progress)
    progress(f"[v1] {how}: {c['stats']} ({time.time() - t0:.0f} s)")
    return bdir


def _write_with_groups(out_root, c, manifest, key, set_latest, progress):
    if c["groups"] is None:
        return write_build(out_root, c["vectors"], c["doc_ids"], ["cve"] * len(c["doc_ids"]), manifest, key,
                           set_latest=set_latest, progress=progress)
    # multi-row: write_build checks one vector per document, so it is given the documents' first rows and the
    # full row matrix replaces them afterwards (inside the not-yet-published temporary directory)
    import shutil
    from .build import BuildError, validate_vectors
    from .schema import MANIFEST_FILE, VECTORS_FILE
    validate_vectors(c["vectors"])
    first = c["vectors"][c["groups"]]
    tmp_root = Path(out_root) / ".staging"
    tmp_root.mkdir(parents=True, exist_ok=True)
    staged = write_build(tmp_root, first, c["doc_ids"], ["cve"] * len(c["doc_ids"]), manifest, key, set_latest=False,
                         progress=lambda m: None)
    np.save(staged / VECTORS_FILE, c["vectors"], allow_pickle=False)
    np.save(staged / GROUPS_FILE, c["groups"], allow_pickle=False)
    m = json.loads((staged / MANIFEST_FILE).read_text(encoding="utf-8"))
    m["files"][VECTORS_FILE] = sha256_file(staged / VECTORS_FILE)
    m["files"][GROUPS_FILE] = sha256_file(staged / GROUPS_FILE)
    m["files_bytes"] = {n: (staged / n).stat().st_size for n in m["files"]}
    (staged / MANIFEST_FILE).write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                                        newline="\n")
    final = Path(out_root) / staged.name
    if final.exists():
        raise BuildError(f"{final} exists")
    import os
    os.replace(staged, final)
    shutil.rmtree(tmp_root, ignore_errors=True)
    if set_latest:
        from .build import move_pointers
        move_pointers(Path(out_root), staged.name)
    progress(f"[dense] build {staged.name}: {c['vectors'].shape[0]:,} rows for {len(c['doc_ids']):,} documents -> {final}")
    return final


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("rows")
    p.add_argument("--qdrant", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p = sub.add_parser("build")
    p.add_argument("--rows", required=True, type=Path)
    p.add_argument("--collapse", required=True, choices=["max", "mean", "primary"])
    p.add_argument("--store")
    p.add_argument("--restrict", type=Path)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--no-latest", action="store_true")
    a = ap.parse_args(argv)
    log = lambda m: print(m, flush=True)  # noqa: E731
    if a.cmd == "rows":
        r = read_rows(a.qdrant, progress=log)
        meta = {"source_sha256": r["source_sha256"], "source_path": r["source_path"], "points": r["points"],
                "environment": environment()}
        np.savez(a.out, vectors=r["vectors"], doc_ids=r["doc_ids"], chunk_ids=r["chunk_ids"],
                 point_ids=r["point_ids"], meta=np.asarray(json.dumps(meta)))
        log(f"[v1] {r['points']:,} rows -> {a.out} (storage sha256 {r['source_sha256'][:16]}...)")
    else:
        build_from_rows(a.rows, a.collapse, a.store, a.out, a.restrict, set_latest=not a.no_latest, progress=log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
