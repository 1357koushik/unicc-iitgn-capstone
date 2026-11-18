"""Reduced corpus of the model comparison (plan 4.5): targets with equivalence members, vendor-product
neighbours, a seeded random sample, all ATT&CK documents; the v1 doc_id mapping; the comparison decision rules."""
from __future__ import annotations

import hashlib
import json

import pytest

from threat_retrieval_engine.dense import reduced as R
from threat_retrieval_engine.dense.compare import decide, reembed_decision
from threat_retrieval_engine.dense.export_v1 import RestrictedUnpickler, cve_and_suffix, loads
from threat_retrieval_engine.dense.sources import DocumentSet


class FakeStore:
    def __init__(self, vp):
        self.vp = vp

    def iter_searchable(self, columns=None):
        for c in sorted(self.vp):
            yield {"cve_id": c, "vendor_product": self.vp[c]}


def _docs(n=400):
    ids = [f"CVE-2020-{1000 + i}" for i in range(n)] + ["attack:G0001", "attack:T1059"]
    kinds = ["cve"] * n + ["attack"] * 2
    texts = [f"text {i}" for i in range(len(ids))]
    return DocumentSet(ids, kinds, texts, [hashlib.sha256(t.encode()).hexdigest() for t in texts], {"store": {}})


def test_select(monkeypatch):
    full = _docs()
    vp = {d: "" for d in full.doc_ids if d.startswith("CVE")}
    vp["CVE-2020-1000"] = "Apache HTTP Server; OpenSSL"
    vp["CVE-2020-1100"] = "OpenSSL"
    vp["CVE-2020-1101"] = "openssl"          # labels compare exactly (humanised labels are already normalised)
    vp["CVE-2020-1200"] = "Apache HTTP Server"
    monkeypatch.setattr(R, "benchmark_targets",
                        lambda d: ({"CVE-2020-1000", "CVE-2020-1300", "attack:G0001", "CVE-1999-0001"}, {"t": 1}))
    red, sel = R.select(full, FakeStore(vp), None, seed=5, n_random=50)
    keep = set(red.doc_ids)
    assert {"CVE-2020-1000", "CVE-2020-1300", "CVE-2020-1100", "CVE-2020-1200", "attack:G0001", "attack:T1059"} <= keep
    assert sel["counts"]["targets_not_searchable"] == 1 and sel["counts"]["random_sample"] == 50
    assert sel["counts"]["total"] == len(red)
    red2, _ = R.select(full, FakeStore(vp), None, seed=5, n_random=50)
    assert red2.doc_ids == red.doc_ids  # seeded
    red3, _ = R.select(full, FakeStore(vp), None, seed=6, n_random=50)
    assert red3.doc_ids != red.doc_ids
    assert red.doc_ids == sorted(red.doc_ids[:-2]) + ["attack:G0001", "attack:T1059"]


def test_v1_doc_id_mapping():
    assert cve_and_suffix("CVE-2021-44228") == ("CVE-2021-44228", "")
    assert cve_and_suffix("CVE-2021-44228_KEV") == ("CVE-2021-44228", "KEV")
    assert cve_and_suffix("cve-2021-44228_EPSS") == ("CVE-2021-44228", "EPSS")
    assert cve_and_suffix("GHSA-abcd") == (None, "")
    assert cve_and_suffix("CVE-2021-1") == (None, "")


def test_restricted_unpickler_refuses_other_globals():
    import os
    import pickle
    blob = pickle.dumps(os.getcwd)  # a reference to a function: must be refused
    with pytest.raises(pickle.UnpicklingError):
        loads(blob)

    class Evil:
        def __reduce__(self):
            return (os.system, ("echo hacked",))
    with pytest.raises(pickle.UnpicklingError):
        loads(pickle.dumps(Evil()))
    assert loads(pickle.dumps({"a": [1.0, 2.0]})) == {"a": [1.0, 2.0]}
    assert issubclass(RestrictedUnpickler, pickle.Unpickler)


def _report(tmp, name, variant, split, ref, macro):
    d = {"variant": {"name": variant}, "split": split,
         "comparisons": [{"reference_variant": ref, "direction": f"{variant} - {ref}", "macro": macro,
                          "populations": {}}]}
    (tmp / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp / name).write_text(json.dumps(d), encoding="utf-8")


def _row(r50, n10):
    return {"macro": {"recall@50": {"value": r50}, "ndcg@10": {"value": n10}}}


def test_decision_rules(tmp_path):
    from threat_retrieval_engine.dense.models import COMPARED
    vals = {"bge-m3": (0.70, 0.50), "bge-large-en-v1.5": (0.69, 0.50), "bge-base-en-v1.5": (0.60, 0.40),
            "e5-large-v2": (0.65, 0.45), "gte-large": (0.66, 0.44)}
    dev = {f"cmp_{m}": _row(*vals[m]) for m in COMPARED}
    ni = lambda ok: {"noninferiority": {"noninferior": ok}}  # noqa: E731
    for m in COMPARED:
        if m == "bge-m3":
            continue
        ok = m == "bge-large-en-v1.5"
        _report(tmp_path, f"vsbest/cmp_{m}-dev.json", f"cmp_{m}", "dev", "cmp_bge-m3",
                {"recall@50": ni(ok), "ndcg@10": ni(ok)})
    d = decide(dev, tmp_path, {"bge-m3": 150.0, "bge-large-en-v1.5": 120.0})
    assert d["best"] == "cmp_bge-m3" and set(d["non_inferior_to_best"]) == {"cmp_bge-m3", "cmp_bge-large-en-v1.5"}
    assert d["winner"] == "cmp_bge-large-en-v1.5"  # faster and non-inferior on both metrics
    d = decide(dev, tmp_path, {"bge-m3": 100.0, "bge-large-en-v1.5": 120.0})
    assert d["winner"] == "cmp_bge-m3"
    with pytest.raises(ValueError):
        decide(dev, tmp_path, {})  # a tie needs latency numbers
    # re-embed decision: significant gain on one metric, no significant loss
    cell = lambda diff, lo, hi, b: {"diff": diff, "ci": [lo, hi], "mean_b": b}  # noqa: E731
    for base, mb in (("cmp_v1", 0.5), ("cmp_v1_v1query", 0.45)):
        for tag in ("", "-cveonly"):
            _report(tmp_path, f"vsv1/cmp_bge-m3-vs-{base}{tag}-dev.json", "cmp_bge-m3", "dev", base,
                    {"recall@50": cell(0.05, 0.02, 0.08, mb), "ndcg@10": cell(0.01, -0.01, 0.03, mb)})
    r = reembed_decision("cmp_bge-m3", tmp_path)
    assert r["stronger_v1_baseline"] == "cmp_v1" and r["c3b_needed"] and r["significantly_better_on"] == ["recall@50"]
