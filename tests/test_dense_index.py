"""C3 dense index: exact top-k against brute force, deterministic tie-break, kind restriction, masks, multi-row
documents, build integrity (sha256, counts, norms), pointers and retention, malformed input."""
from __future__ import annotations

import json

import numpy as np
import pytest

from threat_retrieval_engine.dense import build as B
from threat_retrieval_engine.dense.index import DenseIndex, DenseIndexError, top_k
from threat_retrieval_engine.dense.schema import DOC_IDS_FILE, MANIFEST_FILE, VECTORS_FILE

from dense_fixtures import random_unit


def _ids(n_cve, n_att):
    return [f"CVE-2021-{10000 + i}" for i in range(n_cve)] + [f"attack:S{1000 + i}" for i in range(n_att)], \
        ["cve"] * n_cve + ["attack"] * n_att


def _build(tmp_path, n_cve=900, n_att=40, dim=24, seed=0, vec=None, **kw):
    ids, kinds = _ids(n_cve, n_att)
    v = random_unit(len(ids), dim, seed) if vec is None else vec
    return B.write_build(tmp_path, v, ids, kinds, {"source": "test", "model": {"name": "none"}}, {"seed": seed},
                         progress=lambda m: None, **kw)


def test_top_k_exact_with_ties():
    s = np.array([0.5, 0.9, 0.9, 0.1, 0.9, 0.5, -1.0], dtype=np.float32)
    assert top_k(s, 2).tolist() == [1, 2]
    assert top_k(s, 4).tolist() == [1, 2, 4, 0]
    assert top_k(s, 100).tolist() == [1, 2, 4, 0, 5, 3, 6]
    assert top_k(np.zeros(0, dtype=np.float32), 3).tolist() == []
    rnd = np.random.default_rng(5)
    for _ in range(200):
        x = rnd.integers(0, 6, size=rnd.integers(1, 80)).astype(np.float32)  # many ties
        k = int(rnd.integers(1, 90))
        ref = sorted(range(len(x)), key=lambda i: (-x[i], i))[:k]
        assert top_k(x, k).tolist() == ref


def test_search_equals_brute_force(tmp_path):
    bdir = _build(tmp_path)
    ix = DenseIndex.open(bdir, check_norms=True)
    rnd = np.random.default_rng(1)
    for i in range(200):
        q = rnd.standard_normal(ix.dim).astype(np.float32)
        q /= np.linalg.norm(q)
        for kinds in (("cve",), ("attack",), None):
            a = ix.search(q, k=50, kinds=kinds)
            b = ix.brute_force(q, k=50, kinds=kinds)
            assert [d for d, _ in a] == [d for d, _ in b]
            assert max(abs(x - y) for (_, x), (_, y) in zip(a, b)) < 1e-5
    assert all(d.startswith("attack:") for d, _ in ix.search(q, k=10, kinds=("attack",)))
    assert all(d.startswith("CVE-") for d, _ in ix.search(q, k=10, kinds="cve"))
    assert len(ix.search(q, k=5000, kinds=None)) == 940  # k above the count returns everything once


def test_tie_break_by_document_order(tmp_path):
    v = np.zeros((6, 4), dtype=np.float32)
    v[:, 0] = 1.0                       # every document identical: order must be the row order
    ids, kinds = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0010", "attack:G0001", "attack:G0002"], \
        ["cve"] * 4 + ["attack"] * 2
    bdir = B.write_build(tmp_path, v, ids, kinds, {"source": "test"}, {"t": 1}, progress=lambda m: None)
    ix = DenseIndex.open(bdir)
    q = np.array([1, 0, 0, 0], dtype=np.float32)
    assert [d for d, _ in ix.search(q, k=6, kinds=None)] == ids
    assert [d for d, _ in ix.search(q, k=2, kinds=("attack",))] == ids[4:]


def test_mask(tmp_path):
    ix = DenseIndex.open(_build(tmp_path))
    q = ix.vectors[7].copy()
    mask = np.ones(ix.n_docs, dtype=bool)
    mask[7] = False
    hits = ix.search(q, k=10, kinds=None, mask=mask)
    assert ix.doc_ids[7] not in [d for d, _ in hits]
    only = np.zeros(ix.n_docs, dtype=bool)
    only[[3, 900, 901]] = True
    assert sorted(d for d, _ in ix.search(q, k=10, kinds=None, mask=only)) == sorted(ix.doc_ids[i] for i in (3, 900, 901))
    assert [d for d, _ in ix.search(q, k=10, kinds=("attack",), mask=only)] in (
        [ix.doc_ids[900], ix.doc_ids[901]], [ix.doc_ids[901], ix.doc_ids[900]])
    with pytest.raises(ValueError):
        ix.search(q, k=10, mask=np.ones(3, dtype=bool))


def test_malformed_queries(tmp_path):
    ix = DenseIndex.open(_build(tmp_path))
    for bad in (np.zeros(3, dtype=np.float32), np.full(ix.dim, np.nan, dtype=np.float32), np.ones((2, ix.dim)),
                np.array(["a"] * ix.dim), np.full(ix.dim, np.inf)):
        with pytest.raises(ValueError):
            ix.search(bad)
    q = np.ones(ix.dim, dtype=np.float64)
    for k in (0, -1, 1.5, True, "3"):
        with pytest.raises(ValueError):
            ix.search(q, k=k)
    with pytest.raises(ValueError):
        ix.search(q, kinds=("nope",))
    assert len(ix.search(q, k=10**9)) == 900  # capped at MAX_K (1000), then at the number of CVE documents


def test_integrity_refuses_tampering(tmp_path):
    bdir = _build(tmp_path)
    DenseIndex.open(bdir)
    m = json.loads((bdir / MANIFEST_FILE).read_text(encoding="utf-8"))
    assert m["documents"] == 940 and m["counts"] == {"cve": 900, "attack": 40}
    assert m["kind_ranges"] == {"cve": [0, 900], "attack": [900, 940]}
    v = np.load(bdir / VECTORS_FILE)
    v[0, 0] += 0.25
    np.save(bdir / VECTORS_FILE, v)
    with pytest.raises(DenseIndexError, match="sha256"):
        DenseIndex.open(bdir)
    bdir2 = _build(tmp_path / "b", seed=2)
    (bdir2 / DOC_IDS_FILE).write_text("CVE-1\n", encoding="utf-8")
    with pytest.raises(DenseIndexError):
        DenseIndex.open(bdir2)


def test_write_build_rejects_bad_input(tmp_path):
    ids, kinds = _ids(5, 0)
    with pytest.raises(B.BuildError):
        B.write_build(tmp_path, random_unit(4, 8), ids, kinds, {}, {}, progress=lambda m: None)
    bad = random_unit(5, 8)
    bad[2] *= 3
    with pytest.raises(B.BuildError, match="norm"):
        B.write_build(tmp_path, bad, ids, kinds, {}, {}, progress=lambda m: None)
    bad = random_unit(5, 8)
    bad[1, 1] = np.nan
    with pytest.raises(B.BuildError):
        B.write_build(tmp_path, bad, ids, kinds, {}, {}, progress=lambda m: None)
    with pytest.raises(ValueError):
        B.write_build(tmp_path, random_unit(5, 8), list(reversed(ids)), kinds, {}, {}, progress=lambda m: None)
    with pytest.raises(ValueError):
        B.write_build(tmp_path, random_unit(2, 8), ["attack:G1", "CVE-2020-0001"], ["attack", "cve"], {}, {},
                      progress=lambda m: None)
    assert not [p for p in tmp_path.iterdir() if p.name != "LATEST"]  # nothing half-written is left


def test_pointers_and_retention(tmp_path):
    root = tmp_path / "dense"
    a = _build(root, seed=1, build_id="20260101T000000Z-a")
    b = _build(root, seed=2, build_id="20260102T000000Z-b")
    c = _build(root, seed=3, build_id="20260103T000000Z-c")
    d = _build(root, seed=4, build_id="20260104T000000Z-d", set_latest=False)
    assert (root / "LATEST").read_text().strip() == c.name
    assert (root / "PREVIOUS").read_text().strip() == b.name
    assert DenseIndex.open(root).build_id == c.name
    # a dependant manifest naming build a keeps it
    dep = tmp_path / "pipeline" / "x"
    dep.mkdir(parents=True)
    (dep / "manifest.json").write_text(json.dumps({"dense_build": a.name}), encoding="utf-8")
    assert B.retained_builds(root, tmp_path) == {a.name, b.name, c.name}
    removed = B.prune_builds(root, tmp_path, log=lambda m: None)
    assert removed == [d.name] and a.exists() and b.exists() and c.exists() and not d.exists()
    with pytest.raises(B.BuildError):
        _build(root, seed=5, build_id=c.name)  # an existing build is never overwritten


def test_multi_row_groups(tmp_path):
    from threat_retrieval_engine.dense.export_v1 import collapse
    rng = np.random.default_rng(3)
    V = random_unit(9, 16, 7)
    rows = {"vectors": V, "doc_ids": np.asarray(["CVE-2020-0001", "CVE-2020-0001_KEV", "CVE-2020-0002_EPSS",
                                                 "CVE-2020-0002", "CVE-2020-0003_EPSS", "GHSA-xxxx", "CVE-2019-9999",
                                                 "CVE-2020-0004_KEV", "CVE-2020-0004_EPSS"])}
    searchable = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005"]
    mx = collapse(rows, searchable, "max")
    assert mx["doc_ids"] == ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"]
    assert mx["groups"].tolist() == [0, 2, 4, 5]
    st = mx["stats"]
    assert st["dropped_rows"] == {"not_a_cve_id": 1, "cve_not_searchable_in_store": 1}
    assert st["store_searchable_without_v1_vector"] == 1 and st["cves_with_several_rows"] == 3
    pr = collapse(rows, searchable, "primary")
    assert np.allclose(pr["vectors"][1], V[3]) and np.allclose(pr["vectors"][3], V[7])  # bare ID, then KEV
    mean = collapse(rows, searchable, "mean")
    want = (V[0] + V[1]) / np.linalg.norm(V[0] + V[1])
    assert np.allclose(mean["vectors"][0], want, atol=1e-6)
    from threat_retrieval_engine.dense.export_v1 import _write_with_groups
    bdir = _write_with_groups(tmp_path, mx, {"source": "v1_export", "row_groups": True, "rows": 7,
                                             "model": {"name": "bge-m3"}}, {"t": 1}, True, lambda m: None)
    ix = DenseIndex.open(bdir)
    assert ix.vectors.shape[0] == 7 and ix.n_docs == 4
    for _ in range(50):
        q = rng.standard_normal(16).astype(np.float32)
        hits = ix.search(q, k=4)
        ref = ix.brute_force(q, k=4)
        assert [d for d, _ in hits] == [d for d, _ in ref]
        best = max(float(V[r] @ q) for r in (2, 3))  # CVE-2020-0002: rows EPSS and bare
        assert abs(dict(hits)["CVE-2020-0002"] - best) < 1e-5
