"""Compare a C1 store with the frozen v1 corpus (`data/sqlite/corpus_store.db`, opened read-only).

Method for "CVEs the v1 corpus lacks entirely" (no row of any kind: NVD, CVE List, KEV or EPSS stub):

1. ``published_after_v1_build``: the CVE was published after the v1 corpus was built (its newest
   ``inserted_at`` date), so v1 could not contain it;
2. ``v1_skipped_rejected``: v1's CVE List parser skipped REJECTED records, and the CVE has no NVD record;
3. ``v1_text_length_quarantine``: v1 quarantined texts shorter than 15 or longer than 32,000 characters;
4. ``likely_dropped_by_near_duplicate_filter``: the text v1 would have ingested for the CVE (its NVD English
   description, or the CNA description when NVD has no record) collides, in a MinHash LSH index built
   exactly like v1's DuplicateChecker (128 permutations, threshold 0.90, word 3-shingles, datasketch
   "legacy" hashing as used before datasketch 2.0), with a row v1 kept. v1 dropped every record whose
   MinHash collided with an already kept record, and only kept records were indexed, so a collision with
   the kept corpus reproduces v1's decision. The exact Jaccard similarity with the colliding row is also
   computed and reported (``verified_jaccard_ge_0_90``);
5. ``unexplained``: none of the above.
"""
from __future__ import annotations

import re
import sqlite3
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

_TOK = re.compile(r"[a-z0-9]+")
NUM_PERM = 128
THRESHOLD = 0.90


def _shingles(text: str) -> set[bytes]:
    w = _TOK.findall((text or "").lower())
    if len(w) < 3:
        return {" ".join(w).encode("utf-8")}
    return {" ".join(w[i:i + 3]).encode("utf-8") for i in range(len(w) - 2)}


def _mh_values(texts: list[str]) -> list[bytes]:
    from datasketch import MinHash
    out = []
    for t in texts:
        m = MinHash(num_perm=NUM_PERM, scheme="legacy")
        m.update_batch(list(_shingles(t)))
        out.append(np.asarray(m.hashvalues, dtype=np.uint64).tobytes())
    return out


def _signatures(texts: list[str], workers: int) -> list[bytes]:
    chunks = [texts[i:i + 5000] for i in range(0, len(texts), 5000)]
    if workers <= 1:
        return [s for c in chunks for s in _mh_values(c)]
    with ProcessPoolExecutor(max_workers=workers) as ex:
        return [s for res in ex.map(_mh_values, chunks) for s in res]


def _jac(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def compare_v1(store_db: Path, v1_db: Path, kev_rows: dict, epss_rows: dict, nvd_desc: dict[str, str],
               workers: int = 4, log=print) -> dict:
    from datasketch import MinHash, MinHashLSH

    v1 = sqlite3.connect(f"file:{Path(v1_db).as_posix()}?mode=ro", uri=True)
    v1_rows = v1.execute("SELECT doc_id, source_org, text FROM corpus").fetchall()
    v1_built = v1.execute("SELECT max(inserted_at) FROM corpus").fetchone()[0]
    v1.close()
    v1_date = (v1_built or "")[:10]

    def base(doc_id: str) -> str:
        return re.sub(r"_(KEV|EPSS)$", "", doc_id.upper())

    v1_cves = {base(d) for d, _, _ in v1_rows}
    v1_by_source: dict[str, set[str]] = {}
    for d, s, _ in v1_rows:
        v1_by_source.setdefault(s, set()).add(base(d))
    v1_nvd = v1_by_source.get("NVD", set())

    st = sqlite3.connect(f"file:{Path(store_db).as_posix()}?mode=ro", uri=True)
    rows = st.execute("SELECT cve_id, state, searchable, published, sources, description, description_source "
                      "FROM cve").fetchall()
    st.close()
    universe = {r[0]: r for r in rows}
    missing = sorted(c for c in universe if c not in v1_cves)
    log(f"v1 comparison: v1 has {len(v1_cves)} CVEs ({len(v1_rows)} rows, built {v1_date}); "
        f"store universe {len(universe)}; v1 lacks {len(missing)}")

    cls: dict[str, str] = {}
    to_check: list[tuple[str, str]] = []
    for c in missing:
        _, state, searchable, published, sources, desc, dsrc = universe[c]
        has_nvd = "nvd" in sources.split(",")
        if published and published > v1_date:
            cls[c] = "published_after_v1_build"
            continue
        if not has_nvd:
            if state == "rejected":
                cls[c] = "v1_skipped_rejected"
                continue
            if "cve_list" not in sources.split(","):
                cls[c] = "no_nvd_or_cve_list_record"
                continue
            text = desc or ""
        else:
            text = nvd_desc.get(c, "")
        if len(text.strip()) < 15 or len(text) > 32000:
            cls[c] = "v1_text_length_quarantine"
            continue
        to_check.append((c, text))
    log(f"  building v1-style LSH over {len(v1_rows)} v1 rows; {len(to_check)} CVEs to test")
    v1_texts = [t for _, _, t in v1_rows]
    v1_sigs = _signatures(v1_texts, workers)
    lsh = MinHashLSH(threshold=THRESHOLD, num_perm=NUM_PERM)
    for i, sig in enumerate(v1_sigs):
        lsh.insert(i, MinHash(num_perm=NUM_PERM, scheme="legacy", hashvalues=np.frombuffer(sig, dtype=np.uint64)))
    q_sigs = _signatures([t for _, t in to_check], workers)
    verified = 0
    examples = []
    jac_hist = Counter()
    for (c, text), sig in zip(to_check, q_sigs):
        m = MinHash(num_perm=NUM_PERM, scheme="legacy", hashvalues=np.frombuffer(sig, dtype=np.uint64))
        hits = [i for i in lsh.query(m) if base(v1_rows[i][0]) != c]
        if not hits:
            cls[c] = "unexplained"
            continue
        cls[c] = "likely_dropped_by_near_duplicate_filter"
        sh = _shingles(text)
        best_i = max(hits, key=lambda i: _jac(sh, _shingles(v1_texts[i])))
        best = _jac(sh, _shingles(v1_texts[best_i]))
        jac_hist["1.00" if best == 1.0 else ">=0.95" if best >= 0.95 else ">=0.90" if best >= 0.90
                 else ">=0.80" if best >= 0.80 else "<0.80"] += 1
        verified += best >= THRESHOLD
        if len(examples) < 10:
            examples.append({"cve_id": c, "blocked_by_v1_doc": v1_rows[best_i][0], "jaccard": round(best, 3)})
    counts = Counter(cls.values())
    dropped = [c for c, k in cls.items() if k == "likely_dropped_by_near_duplicate_filter"]
    searchable_dropped = sum(1 for c in dropped if universe[c][2])

    def gap(ids: set[str]) -> dict:
        present = [c for c in ids if c in universe]
        return {"count": len(ids), "present_in_store": len(present),
                "searchable_in_store": sum(1 for c in present if universe[c][2]),
                "description_source": dict(Counter(universe[c][6] for c in present))}

    kev_v1_no_nvd = {c for c in v1_by_source.get("CISA", set()) if c not in v1_nvd}
    epss_v1_no_nvd = {c for c in v1_by_source.get("EPSS", set()) if c not in v1_nvd}
    kev_feed_no_v1_nvd = {c for c in kev_rows if c not in v1_nvd}
    epss_feed_no_v1_nvd = {c for c in epss_rows if c not in v1_nvd}
    return {
        "method": __doc__.strip().split("\n\n", 1)[1],
        "v1_corpus": str(v1_db), "v1_built": v1_built, "v1_rows": len(v1_rows), "v1_distinct_cves": len(v1_cves),
        "v1_rows_by_source": {k: len(v) for k, v in sorted(v1_by_source.items())},
        "store_universe": len(universe),
        "store_cves_missing_from_v1": len(missing),
        "missing_by_reason": dict(sorted(counts.items())),
        "likely_near_duplicate_drops": {"count": len(dropped), "searchable_in_store": searchable_dropped,
                                        "verified_jaccard_ge_0_90": verified,
                                        "best_jaccard_histogram": dict(jac_hist), "examples": examples},
        "v1_cves_not_in_store": len(v1_cves - set(universe)),
        "kev_cves_without_v1_nvd_row": {"v1_kev_rows_without_nvd_row": gap(kev_v1_no_nvd),
                                        "current_kev_catalogue": gap(kev_feed_no_v1_nvd)},
        "epss_cves_without_v1_nvd_row": {"v1_epss_rows_without_nvd_row": gap(epss_v1_no_nvd),
                                         "current_epss_file": gap(epss_feed_no_v1_nvd)},
    }
