"""Shared synthetic fixtures for the B4 evaluation-harness tests (no network, no benchmark data)."""
from __future__ import annotations

import json
from pathlib import Path


def q(qid, text="query text", split="dev", answerable=None, temporal=False, meta=None):
    sl = qid.split("-")[0]
    return {"qid": qid, "slice": sl, "split": split, "text": text,
            "answerable": (sl != "T7") if answerable is None else answerable,
            "temporal_holdout": temporal, "source": {"name": "generated"}, "meta": meta or {}}


def qrel(qid, doc, grade=2, origin="known_item"):
    return {"qid": qid, "doc_id": doc, "grade": grade, "origin": origin}


def rec(qid, docs, variant="sys", abstained=False, latency=100.0, error=None, tiers=None, probs=None, scores=None):
    ranked = []
    for i, d in enumerate(docs):
        ranked.append({"doc_id": d, "score": (scores[i] if scores else float(len(docs) - i)),
                       "tier": tiers[i] if tiers else None, "probability": probs[i] if probs else None})
    return {"qid": qid, "variant": variant, "ranked": ranked, "abstained": abstained, "latency_ms": latency,
            "error": error}


def write_jsonl(path: Path, rows) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path


def make_dataset(tmp: Path, queries, qrels, equivalence=(), manifest=True) -> Path:
    root = Path(tmp) / "bench" / "v0"
    open_q = [x for x in queries if x["split"] != "test"]
    test_q = [x for x in queries if x["split"] == "test"]
    test_ids = {x["qid"] for x in test_q}
    write_jsonl(root / "queries.jsonl", open_q)
    write_jsonl(root / "qrels.jsonl", [r for r in qrels if r["qid"] not in test_ids])
    write_jsonl(root / "equivalence.jsonl", list(equivalence))
    if test_q:
        write_jsonl(root / "sealed" / "queries.jsonl", test_q)
        write_jsonl(root / "sealed" / "qrels.jsonl", [r for r in qrels if r["qid"] in test_ids])
    if manifest:
        from benchmarks_v2.eval.schema import sha256_file
        files = {}
        for rel in ("queries.jsonl", "qrels.jsonl", "equivalence.jsonl", "sealed/queries.jsonl", "sealed/qrels.jsonl"):
            p = root / rel
            if p.exists():
                files[rel] = {"sha256": sha256_file(p)}
        (root / "manifest.json").write_text(json.dumps({"version": "v0", "files": files}), encoding="utf-8")
    return root
