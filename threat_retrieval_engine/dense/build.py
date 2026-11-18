"""Build a C3 dense index: encode a document set with one model (checkpointed, resumable), then assemble the
build directory.

    # 1. the documents (PC, where the C1 store is): every searchable CVE + ATT&CK document, or a selection
    python -m threat_retrieval_engine.dense.build documents --out docs.jsonl [--store ...] [--attack ...]
    # 2. encode (server, unattended under screen/nohup; resumable; --part i/n splits the work over processes)
    python -m threat_retrieval_engine.dense.build encode --documents docs.jsonl --model bge-m3 --work W [--part 0/2]
    # 3. assemble the build (vectors.npy, doc_ids.txt, documents.jsonl, manifest.json; LATEST/PREVIOUS)
    python -m threat_retrieval_engine.dense.build assemble --documents docs.jsonl --work W --out data/dense

Encoding order. All documents are tokenized first (model tokenizer, cap ``--max-tokens``, default 256); they are
then ordered by token length (longest first, ties by row) and cut into checkpoint chunks of ``--chunk`` (5,000)
documents. Each chunk is encoded in deterministic batches and written atomically as ``chunk_<i>.npy`` with a
small JSON sidecar (rows, sha256). A resumed job skips chunks already on disk after checking their sidecars; a
job directory is bound to one (documents sha256, model, revision, token cap) by ``job.json``.

Assembly checks: every chunk present and verified, vector count = document count, every vector finite with
unit norm (within 1e-3), and the row order is the document set's.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from . import models as M
from .schema import DENSE_FORMAT, DOC_IDS_FILE, DOCUMENTS_FILE, KINDS, MANIFEST_FILE, NORM_TOLERANCE, VECTORS_FILE
from .sources import DocumentSet

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "data" / "dense"
CHUNK = 5000


class BuildError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_array(a: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()


def code_fingerprint() -> dict:
    h = hashlib.sha256()
    pkg = Path(__file__).resolve().parent
    for p in sorted(pkg.glob("*.py")):
        h.update(p.name.encode())
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
    try:
        from ..store.feeds import git_head
        commit = git_head(REPO_ROOT)
    except Exception:  # the server copy of the package has no git checkout
        commit = os.environ.get("TRE_GIT_COMMIT")
    return {"git_commit": commit, "code_sha256": h.hexdigest(), "format": DENSE_FORMAT}


def environment() -> dict:
    env = {"python": platform.python_version(), "platform": platform.platform(), "host": socket.gethostname(),
           "numpy": np.__version__, "cpu_count": os.cpu_count()}
    try:
        import torch
        import transformers
        env.update({"torch": torch.__version__, "transformers": transformers.__version__})
    except ImportError:
        pass
    return env


# --------------------------------------------------------------------------- encode job
def _job_key(docs_sha: str, spec: M.ModelSpec, max_tokens: int, chunk: int) -> dict:
    from .encoder import config_key
    return {"documents_sha256": docs_sha, "model": spec.name, "repo": spec.repo, "revision": spec.revision,
            "max_tokens": max_tokens, "chunk": chunk, "format": DENSE_FORMAT, "config_key": config_key(spec, max_tokens)}


def plan_chunks(lengths: list[int], chunk: int) -> list[list[int]]:
    order = sorted(range(len(lengths)), key=lambda i: (-lengths[i], i))
    return [order[i:i + chunk] for i in range(0, len(order), chunk)]


def encode_job(documents: Path, model: str, work: Path, max_tokens: int = M.DOCUMENT_MAX_TOKENS,
               chunk: int = CHUNK, part: tuple[int, int] = (0, 1), threads: int | None = None,
               batch_size: int = 32, model_root: str | None = None, progress=print) -> dict:
    from .encoder import CHARS_PER_TOKEN, Encoder, _WS
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    ds = DocumentSet.read(documents)
    enc = Encoder.load(model, model_root=model_root, threads=threads, batch_size=batch_size,
                       batch_tokens=batch_size * max_tokens)
    key = _job_key(ds.sha256(), enc.spec, max_tokens, chunk)
    jp = work / "job.json"
    if jp.is_file():
        old = json.loads(jp.read_text(encoding="utf-8"))
        if old["key"] != key:
            raise BuildError(f"{work} belongs to another job: {old['key']} (this one: {key})")
    t0 = time.time()
    ids = enc.tokenize(ds.texts, "passage", max_tokens)
    lengths = [len(x) for x in ids]
    # the character cut must never change a document's tokens: re-tokenize every cut document without it
    cap = CHARS_PER_TOKEN * max_tokens
    cut = [i for i, t in enumerate(ds.texts) if len(_WS.sub(" ", t).strip()) > cap]
    if cut:
        full = enc.tokenizer([enc.spec.passage_prefix + _WS.sub(" ", ds.texts[i]).strip() for i in cut],
                             truncation=True, max_length=max_tokens, padding=False,
                             return_attention_mask=False, return_token_type_ids=False)["input_ids"]
        changed = [ds.doc_ids[i] for i, f in zip(cut, full) if f != ids[i]]
        if changed:
            raise BuildError(f"character cap changes the tokens of {len(changed)} documents, e.g. {changed[:3]}")
    untrunc = enc.untruncated_lengths(ds.texts, "passage", max_tokens)
    chunks = plan_chunks(lengths, chunk)
    tok_s = time.time() - t0
    if not jp.is_file():
        stats = {"documents": len(ds), "mean_tokens": float(np.mean(lengths)) if lengths else 0.0,
                 "at_cap": int(sum(1 for x in untrunc if x > max_tokens)), "max_untruncated_tokens": max(untrunc or [0]),
                 "character_cut_documents": len(cut), "chunks": len(chunks)}
        tmp = jp.with_suffix(".tmp")
        tmp.write_text(json.dumps({"key": key, "stats": stats, "created_utc": _now()}, indent=1), encoding="utf-8")
        os.replace(tmp, jp)
    k, n_parts = part
    mine = [i for i in range(len(chunks)) if i % n_parts == k]
    done_now, skipped = 0, 0
    progress(f"[dense] {model}: {len(ds):,} documents, {len(chunks)} chunks, part {k}/{n_parts} -> {len(mine)} chunks; "
             f"tokenized in {tok_s:.0f} s; threads {enc.threads}")
    for i in mine:
        rows = chunks[i]
        if _chunk_ok(work, i, rows):
            skipped += 1
            continue
        t1 = time.time()
        vec = enc.encode_ids([ids[r] for r in rows])
        np.save(work / f"chunk_{i:05d}.tmp.npy", vec, allow_pickle=False)
        side = {"chunk": i, "rows": rows, "rows_sha256": _rows_sha(rows), "vectors_sha256": sha256_array(vec),
                "seconds": round(time.time() - t1, 2), "host": socket.gethostname(), "threads": enc.threads,
                "created_utc": _now()}
        os.replace(work / f"chunk_{i:05d}.tmp.npy", work / f"chunk_{i:05d}.npy")
        tmp = work / f"chunk_{i:05d}.json.tmp"
        tmp.write_text(json.dumps(side), encoding="utf-8")
        os.replace(tmp, work / f"chunk_{i:05d}.json")
        done_now += 1
        progress(f"[dense] {model} chunk {i + 1}/{len(chunks)}: {len(rows)} docs in {side['seconds']} s "
                 f"({len(rows) / max(side['seconds'], 1e-9):.1f} docs/s), max tokens {lengths[rows[0]]}")
    info = {"part": list(part), "chunks_encoded": done_now, "chunks_skipped": skipped, "seconds": round(time.time() - t0, 1),
            "encoder": enc.info()}
    (work / f"part_{k}_of_{n_parts}.json").write_text(json.dumps(info, indent=1), encoding="utf-8")
    return info


def _rows_sha(rows: list[int]) -> str:
    return hashlib.sha256(np.asarray(rows, dtype=np.int64).tobytes()).hexdigest()


def _chunk_ok(work: Path, i: int, rows: list[int]) -> bool:
    sp, vp = work / f"chunk_{i:05d}.json", work / f"chunk_{i:05d}.npy"
    if not (sp.is_file() and vp.is_file()):
        return False
    side = json.loads(sp.read_text(encoding="utf-8"))
    if side["rows_sha256"] != _rows_sha(rows):
        raise BuildError(f"{sp}: rows differ from the job's plan")
    v = np.load(vp, allow_pickle=False)
    if sha256_array(v) != side["vectors_sha256"] or v.shape[0] != len(rows):
        raise BuildError(f"{vp}: content differs from its sidecar")
    return True


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def assemble_vectors(work: Path, n_docs: int, dim: int) -> tuple[np.ndarray, dict]:
    job = json.loads((Path(work) / "job.json").read_text(encoding="utf-8"))
    out = np.full((n_docs, dim), np.nan, dtype=np.float32)
    seen = np.zeros(n_docs, dtype=bool)
    hosts, secs = set(), 0.0
    for i in range(job["stats"]["chunks"]):
        sp = Path(work) / f"chunk_{i:05d}.json"
        if not sp.is_file():
            raise BuildError(f"{work}: chunk {i} missing (job incomplete)")
        side = json.loads(sp.read_text(encoding="utf-8"))
        v = np.load(Path(work) / f"chunk_{i:05d}.npy", allow_pickle=False)
        if sha256_array(v) != side["vectors_sha256"]:
            raise BuildError(f"chunk {i}: vectors differ from the sidecar")
        rows = np.asarray(side["rows"], dtype=np.int64)
        if seen[rows].any():
            raise BuildError(f"chunk {i}: rows encoded twice")
        out[rows] = v
        seen[rows] = True
        hosts.add(side.get("host"))
        secs += side.get("seconds", 0.0)
    if not seen.all():
        raise BuildError(f"{int((~seen).sum())} documents without a vector")
    return out, {"job": job, "hosts": sorted(h for h in hosts if h), "encode_seconds": round(secs, 1)}


def validate_vectors(vec: np.ndarray) -> dict:
    if vec.dtype != np.float32 or vec.ndim != 2:
        raise BuildError(f"vectors must be a 2-d float32 matrix, got {vec.dtype} {vec.shape}")
    if not np.isfinite(vec).all():
        raise BuildError("non-finite values in the vectors")
    norms = np.linalg.norm(vec.astype(np.float64), axis=1)
    worst = float(np.max(np.abs(norms - 1.0))) if len(norms) else 0.0
    if worst > NORM_TOLERANCE:
        raise BuildError(f"vector norms deviate from 1 by up to {worst:.2e}")
    return {"max_norm_deviation": worst}


def write_build(out_root: Path, vectors: np.ndarray, doc_ids: list[str], kinds: list[str], manifest: dict,
                key_material: dict, documents: DocumentSet | None = None, set_latest: bool = True,
                build_id: str | None = None, progress=print) -> Path:
    """Write one build directory atomically (temporary directory, then rename) and move the pointers."""
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    if len(doc_ids) != vectors.shape[0] or len(kinds) != len(doc_ids):
        raise BuildError(f"{vectors.shape[0]} vectors for {len(doc_ids)} documents")
    from .sources import check_order
    check_order(doc_ids, kinds)
    norm = validate_vectors(vectors)
    key = hashlib.sha256(json.dumps(key_material, sort_keys=True).encode()).hexdigest()[:10]
    bid = build_id or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{key}"
    tmp = out_root / f".tmp-{bid}"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir()
    try:
        np.save(tmp / VECTORS_FILE, np.ascontiguousarray(vectors, dtype=np.float32), allow_pickle=False)
        with open(tmp / DOC_IDS_FILE, "w", encoding="utf-8", newline="\n") as f:
            for d in doc_ids:
                if "\n" in d or "\r" in d:
                    raise BuildError(f"doc_id {d!r} contains a line break")
                f.write(d + "\n")
        ranges: dict[str, list[int]] = {}
        for i, k in enumerate(kinds):
            ranges.setdefault(k, [i, i])[1] = i + 1
        files = {VECTORS_FILE: sha256_file(tmp / VECTORS_FILE), DOC_IDS_FILE: sha256_file(tmp / DOC_IDS_FILE)}
        if documents is not None:
            documents.write(tmp / DOCUMENTS_FILE)
            files[DOCUMENTS_FILE] = sha256_file(tmp / DOCUMENTS_FILE)
        m = {"build_id": bid, "format": DENSE_FORMAT, "created_utc": _now(),
             "dim": int(vectors.shape[1]), "dtype": "float32", "documents": int(vectors.shape[0]),
             "counts": {k: b - a for k, (a, b) in ranges.items()}, "kind_ranges": ranges, "kinds_order": list(KINDS),
             "files": files, "files_bytes": {n: (tmp / n).stat().st_size for n in files},
             "vector_check": norm, **manifest, "code": code_fingerprint(), "environment": environment()}
        (tmp / MANIFEST_FILE).write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                                         newline="\n")
        final = out_root / bid
        if final.exists():
            raise BuildError(f"{final} exists")
        os.replace(tmp, final)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    if set_latest:
        move_pointers(out_root, bid)
    progress(f"[dense] build {bid}: {vectors.shape[0]:,} x {vectors.shape[1]} -> {final}")
    return final


def move_pointers(out_root: Path, bid: str) -> None:
    lf = out_root / "LATEST"
    prev = lf.read_text(encoding="utf-8").strip() if lf.is_file() else None
    tmp = out_root / "LATEST.tmp"
    tmp.write_text(bid + "\n", encoding="utf-8")
    os.replace(tmp, lf)
    if prev and prev != bid:
        tmp = out_root / "PREVIOUS.tmp"
        tmp.write_text(prev + "\n", encoding="utf-8")
        os.replace(tmp, out_root / "PREVIOUS")


# --------------------------------------------------------------------------- retention
DEPENDANT_MANIFEST_GLOBS = ("index/*/manifest.json", "pipeline/*/manifest.json", "calibration/*/manifest.json",
                            "service/*/manifest.json", "release/*/manifest.json")


def retained_builds(out_root: Path, data_root: Path | None = None) -> set[str]:
    """LATEST, PREVIOUS, CURRENT and every dense build ID named in a dependant manifest (pipeline, calibrator)."""
    out_root = Path(out_root)
    builds = {d.name for d in out_root.iterdir() if d.is_dir() and (d / MANIFEST_FILE).is_file()
              and (d / VECTORS_FILE).is_file()}
    keep = set()
    for p in ("LATEST", "PREVIOUS", "CURRENT"):
        f = out_root / p
        if f.is_file():
            keep.add(f.read_text(encoding="utf-8").strip())
    root = Path(data_root) if data_root else out_root.parent
    for pattern in DEPENDANT_MANIFEST_GLOBS:
        for mp in root.glob(pattern):
            try:
                text = mp.read_text(encoding="utf-8")
            except OSError:
                continue
            keep.update(b for b in builds if b in text)
    return keep & builds


def prune_builds(out_root: Path, data_root: Path | None = None, log=print) -> list[str]:
    """Delete dense builds outside the retention policy. Only run with an explicit --prune."""
    keep = retained_builds(out_root, data_root)
    removed = []
    for d in sorted(Path(out_root).iterdir()):
        if d.is_dir() and not d.name.startswith(".") and (d / VECTORS_FILE).is_file() and d.name not in keep:
            shutil.rmtree(d)
            removed.append(d.name)
    log(f"[dense] pruned {len(removed)} build(s): {removed}; kept {sorted(keep)}")
    return removed


# --------------------------------------------------------------------------- assemble
def assemble(documents: Path, work: Path, out_root: Path, set_latest: bool = True, progress=print) -> Path:
    ds = DocumentSet.read(documents)
    job = json.loads((Path(work) / "job.json").read_text(encoding="utf-8"))
    key = job["key"]
    if key["documents_sha256"] != ds.sha256():
        raise BuildError("the job was run on another document set")
    spec = M.get(key["model"])
    vec, info = assemble_vectors(work, len(ds), spec.dim)
    parts = sorted(Path(work).glob("part_*_of_*.json"))
    encoders = [json.loads(p.read_text(encoding="utf-8")).get("encoder") for p in parts]
    manifest = {
        "source": "encoded",
        "model": {**spec.as_dict(), "query_max_tokens": M.QUERY_MAX_TOKENS, "document_max_tokens": key["max_tokens"],
                  "config_key": key["config_key"]},
        "inputs": {**ds.inputs, "documents_sha256": ds.sha256(), "documents_file": str(documents)},
        "selection": ds.selection,
        "encode": {"stats": job["stats"], "hosts": info["hosts"], "encode_seconds": info["encode_seconds"],
                   "chunk": key["chunk"], "encoders": encoders},
    }
    return write_build(out_root, vec, ds.doc_ids, ds.kinds, manifest,
                       {"docs": ds.sha256(), "model": key["config_key"]}, documents=ds, set_latest=set_latest,
                       progress=progress)


# --------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("documents", help="write the document set (all searchable CVE + ATT&CK documents)")
    p.add_argument("--store")
    p.add_argument("--attack")
    p.add_argument("--no-attack", action="store_true")
    p.add_argument("--out", required=True, type=Path)
    p = sub.add_parser("encode", help="encode a document set (resumable)")
    p.add_argument("--documents", required=True, type=Path)
    p.add_argument("--model", required=True, choices=sorted(M.MODELS))
    p.add_argument("--work", required=True, type=Path)
    p.add_argument("--max-tokens", type=int, default=M.DOCUMENT_MAX_TOKENS)
    p.add_argument("--chunk", type=int, default=CHUNK)
    p.add_argument("--part", default="0/1", help="i/n: encode chunks i, i+n, ... (several processes, one job)")
    p.add_argument("--threads", type=int)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--model-root")
    p = sub.add_parser("assemble", help="assemble a finished encode job into a build")
    p.add_argument("--documents", required=True, type=Path)
    p.add_argument("--work", required=True, type=Path)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--no-latest", action="store_true")
    p.add_argument("--prune", action="store_true", help="after assembling, delete builds outside the retention policy")
    a = ap.parse_args(argv)
    log = lambda m: print(m, flush=True)  # noqa: E731
    if a.cmd == "documents":
        from .sources import from_builds
        ds = from_builds(a.store, a.attack, with_attack=not a.no_attack)
        sha = ds.write(a.out)
        log(f"[dense] {len(ds):,} documents ({ds.kind_ranges()}) -> {a.out} (sha256 {sha[:16]}...)")
    elif a.cmd == "encode":
        k, n = (int(x) for x in a.part.split("/"))
        if not 0 <= k < n:
            ap.error("--part must be i/n with 0 <= i < n")
        encode_job(a.documents, a.model, a.work, a.max_tokens, a.chunk, (k, n), a.threads, a.batch_size,
                   a.model_root, progress=log)
    else:
        assemble(a.documents, a.work, a.out, set_latest=not a.no_latest, progress=log)
        if a.prune:
            prune_builds(a.out, log=log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
