"""Judging pool export for B3: every (qid, doc_id) in the top ``depth`` of any run whose equivalence unit has
no judgement for that query. Unanswerable queries need no judgements and are skipped. Error records have
no ranking. Abstained records are pooled too (their documents were returned)."""
from __future__ import annotations

import json
from pathlib import Path

from .metrics import DEPTH
from .schema import Dataset, Run


def export_pool(ds: Dataset, runs: list[Run], out_path: Path | None = None, depth: int = DEPTH) -> list[dict]:
    pool: dict[tuple[str, str], dict] = {}
    for run in runs:
        for qid, rec in run.records.items():
            q = ds.queries.get(qid)
            if q is None:
                raise ValueError(f"{run.path}: {qid} is not in the loaded dataset")
            if not q.answerable or rec.error is not None:
                continue
            judged_units = {ds.equivalence.unit(d) for d in ds.qrels.get(qid, {})}
            for rank, r in enumerate(rec.ranked[:depth], 1):
                if ds.equivalence.unit(r.doc_id) in judged_units:
                    continue
                e = pool.setdefault((qid, r.doc_id), {"qid": qid, "doc_id": r.doc_id, "ranks": {}})
                e["ranks"][run.variant] = min(rank, e["ranks"].get(run.variant, rank))
    rows = [pool[k] for k in sorted(pool)]
    for row in rows:
        row["best_rank"] = min(row["ranks"].values())
    if out_path is not None:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    return rows
