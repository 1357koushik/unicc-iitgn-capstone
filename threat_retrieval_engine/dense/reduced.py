"""The reduced corpus of the embedding-model comparison (plan 4.5 item 2).

    python -m threat_retrieval_engine.dense.reduced --documents all.jsonl --out reduced.jsonl [--store ...]

Members (union), from the searchable documents of the given document set:

1. every target of the benchmark's train and dev splits: each document in the qrels of a train or dev query
   (any grade), and every member of its equivalence set;
2. every CVE that shares a vendor–product label (C1 ``vendor_product``, "; "-separated humanised pairs) with a
   CVE of item 1;
3. 50,000 CVEs drawn uniformly from all searchable CVEs with ``random.Random(SEED).sample`` over the sorted
   CVE IDs (drawn independently of items 1–2, so the union holds fewer than 50,000 extra);
4. every ATT&CK document.

The sealed test split is never read: only the train and dev selections of the dataset are loaded (the loader
refuses the test split without TRE_OPEN_SEALED). Targets that are not searchable documents are counted and
reported.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from .sources import DocumentSet

SEED = 20261117
N_RANDOM = 50_000


def benchmark_targets(dataset_dir: Path) -> tuple[set[str], dict]:
    from benchmarks_v2.eval.schema import load_dataset
    targets: set[str] = set()
    info: dict = {}
    for split in ("train", "dev"):
        ds = load_dataset(Path(dataset_dir), split)
        qids = {q.qid for q in ds.select(split)}
        n0 = len(targets)
        for qid in qids:
            for doc in ds.qrels.get(qid, {}):
                targets.add(doc)
                for m in ds.equivalence.members_of(ds.equivalence.unit(doc)):
                    targets.add(m)
        info[split] = {"queries": len(qids), "new_targets": len(targets) - n0}
        info.setdefault("dataset", {"path": str(dataset_dir), "version": ds.info.get("version"),
                                    "manifest_sha256": ds.info.get("manifest_sha256"),
                                    "files": {k: v["sha256"] for k, v in ds.info["files"].items()}})
    return targets, info


def select(full: DocumentSet, store, dataset_dir: Path, seed: int = SEED, n_random: int = N_RANDOM
           ) -> tuple[DocumentSet, dict]:
    targets, tinfo = benchmark_targets(dataset_dir)
    present = set(full.doc_ids)
    cves = [d for d, k in zip(full.doc_ids, full.kinds) if k == "cve"]
    t_cve = {t for t in targets if t in present and t.startswith("CVE-")}
    t_other = {t for t in targets if t in present and not t.startswith("CVE-")}
    missing = sorted(t for t in targets if t not in present)
    vp: dict[str, list[str]] = {}
    for row in store.iter_searchable(columns=("cve_id", "vendor_product")):
        vp[row["cve_id"]] = [x.strip() for x in (row["vendor_product"] or "").split(";") if x.strip()]
    labels = set()
    for c in t_cve:
        labels.update(vp.get(c, []))
    neighbours = {c for c in cves if any(x in labels for x in vp.get(c, ()))}
    rnd = random.Random(seed)
    sample = set(rnd.sample(sorted(cves), min(n_random, len(cves))))
    attack = {d for d, k in zip(full.doc_ids, full.kinds) if k == "attack"}
    keep = t_cve | t_other | neighbours | sample | attack
    sel = {"rule": "plan 4.5: train+dev targets (+ equivalence members), CVEs sharing a vendor-product label with a "
                   "target CVE, a uniform random sample of CVEs, all ATT&CK documents",
           "seed": seed, "n_random": n_random, "targets": tinfo,
           "counts": {"targets_cve": len(t_cve), "targets_other": len(t_other),
                      "targets_not_searchable": len(missing), "target_vendor_product_labels": len(labels),
                      "vendor_product_neighbours": len(neighbours), "random_sample": len(sample),
                      "random_not_otherwise_selected": len(sample - t_cve - neighbours), "attack": len(attack),
                      "total": len(keep)},
           "targets_not_searchable_examples": missing[:20]}
    return full.subset(keep, sel), sel


def main(argv: list[str] | None = None) -> int:
    from ..store import Store
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--documents", required=True, type=Path, help="full document set (build.py documents)")
    ap.add_argument("--store", help="C1 build the document set came from (default: the one it names)")
    ap.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parents[2] / "data/benchmark/v2.0")
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    full = DocumentSet.read(a.documents)
    with Store.open(a.store or full.inputs["store"]["path"]) as s:
        if s.build_id != full.inputs["store"]["build_id"]:
            raise SystemExit(f"store {s.build_id} is not the document set's {full.inputs['store']['build_id']}")
        red, sel = select(full, s, a.dataset)
    sha = red.write(a.out)
    print(json.dumps(sel["counts"], indent=1))
    print(f"{len(red):,} documents -> {a.out} (sha256 {sha[:16]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
