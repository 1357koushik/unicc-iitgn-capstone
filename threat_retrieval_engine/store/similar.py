"""Near-identical text linking (`similar_group`), replacing v1's near-duplicate removal.

v1 (`search_engine/duplicate_checker.py`) dropped any record whose 3-word-shingle MinHash collided in an
LSH index tuned to Jaccard 0.90 with an earlier record, so distinct CVEs with templated descriptions were
silently lost. Here every CVE is kept and near-identical descriptions are only *linked*:

* text: the stored description, lower-cased alphanumeric tokens, word 3-shingles (v1's shingling);
* exact pass: identical token sequences share a group directly (SHA-1 of the token sequence);
* near pass: one representative per exact class goes into a MinHash LSH index (128 permutations,
  threshold 0.90, datasketch); every LSH candidate pair is verified with the exact Jaccard similarity of
  the shingle sets, and only pairs with Jaccard >= 0.90 are linked;
* grouping is a star around a canonical copy, not a transitive chain: CVEs are visited in ID order and a
  CVE joins the most similar earlier canonical CVE it is linked to (ties: lowest ID), else becomes a
  canonical itself. Every member is therefore >= 0.90 similar to its canonical, and groups cannot grow
  into long chains of loosely related CVEs. The group ID is the canonical CVE ID. A canonical with no
  members gets no group.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Iterable

import numpy as np

NUM_PERM = 128
THRESHOLD = 0.90
SHINGLE = 3
SCHEME = "affine32"          # datasketch 2.x hashing scheme; signatures are stored as uint32
_TOK = re.compile(r"[a-z0-9]+")


def tokens(text: str) -> list[str]:
    return _TOK.findall((text or "").lower())


def shingles(text: str, size: int = SHINGLE) -> set[str]:
    w = tokens(text)
    if len(w) < size:
        return {" ".join(w)}
    return {" ".join(w[i:i + size]) for i in range(len(w) - size + 1)}


def exact_key(text: str) -> str:
    return hashlib.sha1(" ".join(tokens(text)).encode("utf-8")).hexdigest()


def minhash(text: str):
    from datasketch import MinHash
    m = MinHash(num_perm=NUM_PERM, seed=1, scheme=SCHEME)
    m.update_batch([s.encode("utf-8") for s in shingles(text)])
    return m


def signature(text: str) -> bytes:
    return np.asarray(minhash(text).hashvalues, dtype=np.uint32).tobytes()


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def group(items: Iterable[tuple[str, str, bytes]], text_of) -> tuple[dict[str, str], dict]:
    """items: (cve_id, exact_key, signature) for searchable CVEs; text_of(cve_id) -> description.

    Returns ({cve_id: group_id} for grouped CVEs only, statistics)."""
    from datasketch import MinHash, MinHashLSH

    from .text import cve_sort_key

    items = sorted(items, key=lambda x: cve_sort_key(x[0]))
    exact_classes: dict[str, list[str]] = defaultdict(list)
    sig_of: dict[str, bytes] = {}
    for cid, ek, sig in items:
        exact_classes[ek].append(cid)
        sig_of[cid] = sig
    reps = [members[0] for members in exact_classes.values()]
    reps.sort(key=cve_sort_key)
    rep_class = {members[0]: ek for ek, members in exact_classes.items()}

    lsh = MinHashLSH(threshold=THRESHOLD, num_perm=NUM_PERM)
    canon_of: dict[str, str] = {}      # representative -> canonical representative
    is_canonical: set[str] = set()
    sh_cache: dict[str, set[str]] = {}

    def sh(c: str) -> set[str]:
        s = sh_cache.get(c)
        if s is None:
            s = sh_cache[c] = shingles(text_of(c))
        return s

    pairs_checked = pairs_linked = 0
    for c in reps:
        m = MinHash(num_perm=NUM_PERM, seed=1, scheme=SCHEME, hashvalues=np.frombuffer(sig_of[c], dtype=np.uint32))
        best, best_j = None, -1.0
        for other in lsh.query(m):
            pairs_checked += 1
            j = jaccard(sh(c), sh(other))
            if j >= THRESHOLD:
                pairs_linked += 1
                if j > best_j or (j == best_j and cve_sort_key(other) < cve_sort_key(best)):
                    best, best_j = other, j
        if best is None:
            is_canonical.add(c)
            canon_of[c] = c
            lsh.insert(c, m)  # only canonicals are indexed: members attach to a canonical, never chain
        else:
            canon_of[c] = best
        if len(sh_cache) > 200_000:
            sh_cache.clear()
    groups: dict[str, list[str]] = defaultdict(list)
    for rep in reps:
        canon = canon_of[rep]
        groups[canon].extend(exact_classes[rep_class[rep]])
    out: dict[str, str] = {}
    sizes = []
    for canon, members in groups.items():
        if len(members) > 1:
            for m_id in members:
                out[m_id] = canon
            sizes.append(len(members))
    exact_dupe_cves = sum(len(v) for v in exact_classes.values() if len(v) > 1)
    stats = {
        "method": "exact token-sequence hash, then MinHash LSH (128 permutations, threshold 0.90) over word "
                  "3-shingles with exact Jaccard verification; star grouping around the lowest-ID canonical",
        "threshold_jaccard": THRESHOLD, "num_perm": NUM_PERM, "shingle_words": SHINGLE,
        "texts": len(items), "exact_classes": len(exact_classes),
        "cves_in_exact_duplicate_classes": exact_dupe_cves,
        "lsh_pairs_checked": pairs_checked, "lsh_pairs_linked": pairs_linked,
        "groups": len(sizes), "cves_in_groups": sum(sizes), "largest_group": max(sizes) if sizes else 0,
        "group_size_histogram": _hist(sizes),
    }
    return out, stats


def _hist(sizes: list[int]) -> dict[str, int]:
    bins = {"2": 0, "3-5": 0, "6-10": 0, "11-50": 0, "51-200": 0, ">200": 0}
    for s in sizes:
        k = "2" if s == 2 else "3-5" if s <= 5 else "6-10" if s <= 10 else "11-50" if s <= 50 else "51-200" if s <= 200 else ">200"
        bins[k] += 1
    return bins
