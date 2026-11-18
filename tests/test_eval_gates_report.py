"""B4 end to end: score -> JSON/Markdown report -> gates, plus pool export and gate configuration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from benchmarks_v2.eval import cli
from benchmarks_v2.eval.gates import DEFAULT_GATES, evaluate_gates, load_gates
from eval_helpers import make_dataset, q, qrel, rec, write_jsonl


def build(tmp_path, unjudged=False):
    """T1: 3 identifier queries; T7: 2 unanswerable; T6: 1 noisy query with a T1 parent."""
    queries = [q("T1-1"), q("T1-2"), q("T1-3"), q("T7-1"), q("T7-2"), q("T6-1", meta={"parent_qid": "T1-1"})]
    qrels = [qrel("T1-1", "CVE-2021-44228"), qrel("T1-2", "CVE-2014-0160"), qrel("T1-3", "CVE-2017-0144"),
             qrel("T6-1", "CVE-2021-44228"), qrel("T1-1", "CVE-2014-0346", 0)]
    root = make_dataset(tmp_path, queries, qrels)
    second = "CVE-2019-0708" if unjudged else "CVE-2014-0346"
    cand = [rec("T1-1", ["CVE-2021-44228", second], "cand", tiers=["EXACT", "WEAK"], probs=[None, 0.2], latency=900),
            rec("T1-2", ["CVE-2014-0160"], "cand", tiers=["EXACT"], probs=[None], latency=800),
            rec("T1-3", ["CVE-2017-0144"], "cand", tiers=["EXACT"], probs=[None], latency=850),
            rec("T7-1", [], "cand", abstained=True, latency=300),
            rec("T7-2", ["CVE-2000-0001"], "cand", tiers=["WEAK"], probs=[0.1], latency=400),
            rec("T6-1", ["CVE-2021-44228"], "cand", tiers=["STRONG"], probs=[0.97], latency=1200)]
    v1 = [rec("T1-1", ["CVE-2014-0346", "CVE-2021-44228"], "v1_match", tiers=["STRONG", "STRONG"], probs=[0.99, 0.98],
              latency=9000),
          rec("T1-2", [], "v1_match", error="http_504: deadline", latency=15000),
          rec("T1-3", ["CVE-2017-0144"], "v1_match", tiers=["EXACT"], probs=[1.0], latency=8000),
          rec("T7-1", ["CVE-2000-0002"], "v1_match", tiers=["PARTIAL"], probs=[0.7], latency=9000),
          rec("T7-2", ["CVE-2000-0003"], "v1_match", tiers=["WEAK"], probs=[0.3], latency=9000),
          rec("T6-1", ["CVE-2021-44228"], "v1_match", tiers=["STRONG"], probs=[0.9], latency=9000)]
    return root, write_jsonl(tmp_path / "cand.jsonl", cand), write_jsonl(tmp_path / "v1.jsonl", v1)


def score(tmp_path, root, run, *extra):
    out = tmp_path / f"{Path(run).stem}-rep.json"
    assert cli.main(["score", "--run", str(run), "--dataset", str(root), "--bootstrap", "500",
                     "--json-out", str(out), *extra]) == 0
    return out, json.loads(out.read_text(encoding="utf-8"))


def test_report_contents_and_markdown(tmp_path):
    root, cand, v1 = build(tmp_path)
    out, rep = score(tmp_path, root, cand, "--compare", str(v1))
    for key in ("harness", "dataset", "variant", "settings", "populations", "macro", "comparisons", "gates"):
        assert key in rep
    assert rep["dataset"]["manifest_verified"] is True and len(rep["dataset"]["manifest_sha256"]) == 64
    assert rep["harness"]["commit"] and rep["variant"]["run_sha256"]
    t1 = rep["populations"]["T1"]["metrics"]["success@1"]
    assert t1["value"] == 1.0 and t1["ci"] == [1.0, 1.0] and t1["n"] == 3
    ov = rep["populations"]["overall"]
    assert ov["metrics"]["ndcg@10"]["ci"] is not None
    assert rep["populations"]["T7"]["abstention"]["false_accept_rate"]["value"] == 0.0
    # Comparison cand - v1 on T1 S@1: cand 3/3, v1 1/3 (rank 2 hit, 504 miss, hit) -> +2/3
    cmp_t1 = rep["comparisons"][0]["populations"]["T1"]["success@1"]
    assert cmp_t1["diff"] == pytest.approx(2 / 3) and "noninferiority" in cmp_t1
    # Parent pair T6 - T1-1 on nDCG: both 1.0 -> diff 0
    assert rep["parent_pairs"]["T6_vs_clean"]["metrics"]["ndcg@10"]["diff"] == 0.0
    md = out.with_suffix(".md").read_text(encoding="utf-8")
    for section in ("## Ranking quality", "## Abstention and errors", "## Calibration", "## Latency",
                    "## Comparison: cand - v1_match", "## Release gates", "Manifest sha256"):
        assert section in md
    assert "1.000 [1.000, 1.000]" in md


def test_v1_report_counts_504_and_false_accept(tmp_path):
    root, cand, v1 = build(tmp_path)
    _, rep = score(tmp_path, root, v1)
    ov = rep["populations"]["overall"]
    assert ov["errors"]["http_504"] == 1
    assert rep["populations"]["T7"]["abstention"]["false_accept_rate"]["value"] == 0.5
    g = {r["id"]: r for r in rep["gates"]["results"]}
    assert g["no_http_504"]["status"] == "FAIL" and g["T7_false_accept"]["status"] == "FAIL"
    assert g["T1_success1"]["status"] == "FAIL"


def test_gates_pass_fail_missing_and_cli_exit(tmp_path):
    root, cand, v1 = build(tmp_path)
    out, rep = score(tmp_path, root, cand, "--compare", str(v1))
    g = {r["id"]: r for r in rep["gates"]["results"]}
    assert g["judgement_completeness"]["status"] == "PASS"
    assert g["T1_success1"]["status"] == "PASS"
    assert g["T7_false_accept"]["status"] == "PASS"
    assert g["no_http_504"]["status"] == "PASS"
    assert g["latency_free_text_p95"]["status"] == "PASS"
    assert g["T2_success5"]["status"] == "MISSING"            # no T2 queries: never a silent pass
    assert g["reranker_vs_ceiling_ndcg"]["status"] == "MISSING"
    # T0 vs v1 gate needs a T0 population; absent here.
    assert g["T0_ndcg_vs_v1"]["status"] == "MISSING"
    assert rep["gates"]["overall"] == "FAIL"
    assert cli.main(["gates", "--report", str(out)]) == 1
    # A gate file with only satisfied gates passes and the CLI exits 0.
    cfg = yaml.safe_load(DEFAULT_GATES.read_text(encoding="utf-8"))
    cfg["gates"] = [x for x in cfg["gates"] if x["id"] in ("T1_success1", "T7_false_accept", "no_http_504")]
    small = tmp_path / "gates.yaml"
    small.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert cli.main(["gates", "--report", str(out), "--gates", str(small)]) == 0


def test_unjudged_documents_fail_gates_unless_allowed(tmp_path):
    root, cand, v1 = build(tmp_path, unjudged=True)
    out, rep = score(tmp_path, root, cand)
    assert rep["populations"]["overall"]["unjudged"]["unjudged_positions"] == 1
    assert rep["flags"]["judgement_complete"] is False
    g = {r["id"]: r for r in rep["gates"]["results"]}
    assert g["judgement_completeness"]["status"] == "FAIL"
    small = tmp_path / "g.yaml"
    cfg = yaml.safe_load(DEFAULT_GATES.read_text(encoding="utf-8"))
    cfg["gates"] = [x for x in cfg["gates"] if x["id"] in ("judgement_completeness", "T1_success1")]
    small.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert cli.main(["gates", "--report", str(out), "--gates", str(small)]) == 1
    assert cli.main(["gates", "--report", str(out), "--gates", str(small), "--allow-unjudged"]) == 0
    res = evaluate_gates(rep, load_gates(small), allow_unjudged=True)
    assert res["provisional"] is True
    assert {r["id"]: r["status"] for r in res["results"]}["judgement_completeness"] == "WAIVED"
    out2, rep2 = score(tmp_path, root, cand, "--allow-unjudged")
    assert "PROVISIONAL" in out2.with_suffix(".md").read_text(encoding="utf-8")
    # T1-1 ranks [relevant, unjudged]. value: DCG 3 / IDCG 3 = 1. Scenario: the unjudged document is grade 2
    # and joins the ideal: (3 + 3*D2) / (3 + 3*D2) = 1 as well (the scenario is not an upper bound for nDCG).
    m = rep2["populations"]["T1"]["metrics"]
    assert m["ndcg@10"]["value"] == 1.0 and m["ndcg@10"]["if_unjudged_relevant"] == pytest.approx(1.0)
    assert m["success@5"]["if_unjudged_relevant"] == 1.0
    g2 = {r["id"]: r["status"] for r in rep2["gates"]["results"]}
    assert g2["judgement_completeness"] == "WAIVED"
    assert g2["ece_per_slice[T0]"] == "MISSING"          # absent population: never NOT_APPLICABLE
    assert g2["ece_per_slice[T1]"] == "NOT_APPLICABLE"   # present, but EXACT hits carry no probability


def test_pool_exports_unjudged_pairs(tmp_path):
    root, cand, v1 = build(tmp_path, unjudged=True)
    out = tmp_path / "pool.jsonl"
    assert cli.main(["pool", "--runs", str(cand), str(v1), "--dataset", str(root), "--out", str(out)]) == 0
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    # cand: T1-1 rank 2 CVE-2019-0708 unjudged.  v1: T1-1 ranks are judged (0346 judged 0); T7 never pooled.
    assert rows == [{"qid": "T1-1", "doc_id": "CVE-2019-0708", "ranks": {"cand": 2}, "best_rank": 2}]


def test_incomplete_run_is_refused_unless_allowed(tmp_path, capsys):
    root, cand, _ = build(tmp_path)
    lines = cand.read_text().splitlines()[:-1]
    part = tmp_path / "part.jsonl"
    part.write_text("\n".join(lines) + "\n")
    assert cli.main(["score", "--run", str(part), "--dataset", str(root), "--bootstrap", "100",
                     "--json-out", str(tmp_path / "x.json")]) == 2
    assert "run is incomplete" in capsys.readouterr().err
    assert cli.main(["score", "--run", str(part), "--dataset", str(root), "--bootstrap", "100", "--allow-incomplete",
                     "--json-out", str(tmp_path / "x.json")]) == 0
    assert json.loads((tmp_path / "x.json").read_text())["flags"]["incomplete"] is True


def test_gates_yaml_encodes_plan_thresholds():
    cfg = load_gates()
    g = {x["id"]: x for x in cfg["gates"]}
    assert g["T1_success1"]["min"] == 1.0
    assert g["T0_ndcg_vs_v1"]["min_diff"] == 0.15 and g["T0_ndcg_vs_v1"]["diff_lower_gt"] == 0.0
    assert g["T2_success5"]["min"] == 0.90 and g["T2_success5"]["lower_min"] == 0.85
    assert g["T3T4_recall10"]["min"] == 0.90 and g["T3T4_mrr10"]["min"] == 0.75
    assert g["T6_within5_ndcg"]["min_diff"] == -0.05
    assert g["T8_success1"]["min"] == 0.80
    assert g["T7_false_accept"]["max"] == 0.01
    assert g["reranker_vs_ceiling_ndcg"]["margin"] == 0.01
    assert g["strong_precision"]["min"] == 0.95 and g["strong_precision"]["lower_min"] == 0.90
    assert g["ece_overall"]["max"] == 0.05 and g["ece_per_slice"]["max"] == 0.05
    assert g["latency_free_text_p95"]["max"] == 3000 and g["latency_free_text_p95"]["target"] == 1000
    assert g["no_http_504"]["max"] == 0
    assert cfg["references"]["v1"] == "v1_match"
