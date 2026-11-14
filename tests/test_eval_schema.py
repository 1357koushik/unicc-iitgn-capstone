"""B4 strict loaders and validators for queries, qrels, equivalence sets, run files and the manifest."""
from __future__ import annotations

import json

import pytest

from benchmarks_v2.eval.schema import (ValidationError, load_dataset, load_equivalence, load_qrels, load_queries,
                                       load_run)
from eval_helpers import make_dataset, q, qrel, rec, write_jsonl


def problems(exc):
    return "\n".join(exc.value.problems)


def test_valid_dataset_loads_and_manifest_is_verified(tmp_path):
    root = make_dataset(tmp_path, [q("T1-1"), q("T7-1"), q("T3-4", split="train")],
                        [qrel("T1-1", "CVE-2021-44228"), qrel("T3-4", "attack:T1059.001", 1, "judged") |
                         {"judge": {"round": 1, "first": 1, "second": 1, "adjudicated": False}}],
                        [{"set_id": "s", "members": ["CVE-2014-0160", "CVE-2014-0346"], "reason": "duplicate"}])
    ds = load_dataset(root, "dev")
    assert ds.info["manifest_verified"] is True and ds.info["version"] == "v0"
    assert len(ds.info["manifest_sha256"]) == 64
    assert [x.qid for x in ds.select("dev")] == ["T1-1", "T7-1"]
    assert ds.qrels["T3-4"] == {"attack:T1059.001": 1}
    assert ds.equivalence.unit("CVE-2014-0346") == ds.equivalence.unit("CVE-2014-0160")


def test_manifest_hash_mismatch_is_an_error(tmp_path):
    root = make_dataset(tmp_path, [q("T1-1")], [qrel("T1-1", "CVE-2021-44228")])
    with open(root / "qrels.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(qrel("T1-1", "CVE-2014-0160", 0)) + "\n")
    with pytest.raises(ValidationError) as e:
        load_dataset(root, "dev")
    assert "does not match manifest" in problems(e)


def test_query_validation_errors(tmp_path):
    bad = [
        q("T1-1") | {"extra_field": 1},                       # unknown field
        {k: v for k, v in q("T1-2").items() if k != "meta"},  # missing field
        q("T1-3") | {"slice": "T2"},                          # qid prefix vs slice
        q("T1-4") | {"answerable": False},                    # answerable false outside T7
        q("T7-5") | {"answerable": True},                     # T7 must be unanswerable
        q("T1-6") | {"split": "validation"},
        q("T1-7") | {"temporal_holdout": 0},                  # must be a JSON boolean
        q("X-8"),
        q("T1-9") | {"source": {"name": "github_advisories"}},  # non-generated source needs id and licence
        q("T1-10") | {"text": "  "},
        q("T1-11"), q("T1-11"),                               # duplicate qid
    ]
    p = write_jsonl(tmp_path / "queries.jsonl", bad)
    with pytest.raises(ValidationError) as e:
        load_queries(p)
    msg = problems(e)
    for frag in ("extra_field: unknown field", "meta: missing required field", "does not match slice",
                 "answerable: false is allowed only for T7", "T7 queries must have answerable=false",
                 "split: 'validation'", "temporal_holdout: must be a JSON boolean", "is not of the form",
                 "source.id: required", "source.licence: required", "text: must be a non-empty string",
                 "duplicate 'T1-11'"):
        assert frag in msg, frag
    assert "queries.jsonl:1:" in msg  # file and line are named


def test_qrels_validation_errors(tmp_path):
    qs = {x.qid: x for x in load_queries(write_jsonl(tmp_path / "q.jsonl", [q("T1-1"), q("T7-1")]))}
    bad = [
        qrel("T1-1", "CVE-2021-44228", 3),
        qrel("T1-1", "cve-2021-1", 2),
        qrel("T1-1", "CVE-2014-0160", 2, "judged"),            # judged without judge
        qrel("T1-1", "CVE-2014-0161", 2) | {"judge": {"round": 1}},  # judge only for judged
        qrel("T1-1", "CVE-2014-0162", True),                   # bool is not an int grade
        qrel("T1-1", "CVE-2014-0163", 2, "model"),
        qrel("T9-9", "attack:G0016"),                          # qid not in queries
        qrel("T7-1", "CVE-2014-0164", 2),                      # relevant doc for unanswerable query
        qrel("T1-1", "CVE-2014-0165"), qrel("T1-1", "CVE-2014-0165"),  # duplicate pair
    ]
    with pytest.raises(ValidationError) as e:
        load_qrels(write_jsonl(tmp_path / "qrels.jsonl", bad), qs)
    msg = problems(e)
    for frag in ("grade: 3 must be", "neither an upper-case CVE ID", "judge: required object", "judge: only allowed",
                 "grade: True must be", "origin: 'model'", "'T9-9' is not in the query file",
                 "unanswerable query T7-1", "duplicate judgement for (T1-1, CVE-2014-0165)"):
        assert frag in msg, frag
    # grade 0 for an unanswerable query is fine; ATT&CK ids are accepted
    load_qrels(write_jsonl(tmp_path / "ok.jsonl", [qrel("T7-1", "CVE-2014-0164", 0), qrel("T1-1", "attack:S0154")]), qs)


def test_equivalence_validation(tmp_path):
    bad = [{"set_id": "a", "members": ["CVE-2000-0001"], "reason": "x"},
           {"set_id": "b", "members": ["CVE-2000-0001", "CVE-2000-0001"], "reason": "x"},
           {"set_id": "c", "members": ["CVE-2000-0001", "nope"], "reason": "x"},
           {"set_id": "d", "members": ["CVE-2000-0001", "CVE-2000-0002"]},
           {"set_id": "e", "members": ["CVE-2000-0003", "CVE-2000-0004"], "reason": "x"},
           {"set_id": "e", "members": ["CVE-2000-0005", "CVE-2000-0006"], "reason": "x"}]
    with pytest.raises(ValidationError) as e:
        load_equivalence(write_jsonl(tmp_path / "eq.jsonl", bad))
    msg = problems(e)
    for frag in ("at least two", "duplicate doc_id in set", "'nope' is not a valid", "reason: missing",
                 "set_id: duplicate 'e'"):
        assert frag in msg, frag


def test_run_validation_errors(tmp_path):
    good = rec("T1-1", ["CVE-2021-44228"], tiers=["STRONG"], probs=[0.9])
    bad = [
        rec("T1-2", ["CVE-2021-44228", "CVE-2021-44228"]),                  # not de-duplicated
        rec("T1-3", ["CVE-2021-44228"], tiers=["VERY_STRONG"]),
        rec("T1-4", ["CVE-2021-44228"], probs=[1.2]),
        rec("T1-5", ["CVE-2021-44228"]) | {"note": 1},
        rec("T1-6", ["CVE-2021-44228"], latency=-1),
        rec("T1-7", ["CVE-2021-44228"]) | {"abstained": "no"},
        rec("T1-8", ["CVE-2021-44228"], variant="other"),
        good, good,
    ]
    bad[1]["ranked"][0]["score"] = None  # score must be a number
    with pytest.raises(ValidationError) as e:
        load_run(write_jsonl(tmp_path / "run.jsonl", bad))
    msg = problems(e)
    for frag in ("appears twice; run files must be de-duplicated", "score: must be a finite number",
                 "'VERY_STRONG' is not one of", "probability: 1.2", "note: unknown field",
                 "latency_ms: must be", "abstained: must be a JSON boolean", "must hold one variant",
                 "T1-1 appears twice"):
        assert frag in msg, frag


def test_run_with_nonconforming_doc_id_loads_with_warning(tmp_path):
    run = load_run(write_jsonl(tmp_path / "run.jsonl", [rec("T1-1", ["0467b0eb504d22fe"])]))
    assert run.records["T1-1"].ranked[0].doc_id == "0467b0eb504d22fe"
    assert run.warnings and "can never be judged" in run.warnings[0]


def test_test_split_outside_sealed_is_rejected(tmp_path):
    root = make_dataset(tmp_path, [q("T1-1")], [qrel("T1-1", "CVE-2021-44228")], manifest=False)
    write_jsonl(root / "queries.jsonl", [q("T1-1"), q("T1-2", split="test")])
    with pytest.raises(ValidationError) as e:
        load_dataset(root, "dev")
    assert "test-split query outside sealed/" in problems(e)
