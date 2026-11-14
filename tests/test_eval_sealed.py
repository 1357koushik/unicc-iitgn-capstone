"""B4 sealed test split: every command refuses the test split unless TRE_OPEN_SEALED=E1."""
from __future__ import annotations

import json

import pytest

from benchmarks_v2.eval import cli, sealed
from benchmarks_v2.eval.schema import load_dataset
from eval_helpers import make_dataset, q, qrel, rec, write_jsonl


@pytest.fixture()
def data(tmp_path, monkeypatch):
    monkeypatch.delenv(sealed.SEALED_ENV, raising=False)
    queries = [q("T1-1"), q("T1-2", split="test")]
    root = make_dataset(tmp_path, queries, [qrel("T1-1", "CVE-2021-44228"), qrel("T1-2", "CVE-2014-0160")])
    test_run = write_jsonl(tmp_path / "test_run.jsonl", [rec("T1-2", ["CVE-2014-0160"])])
    src = write_jsonl(tmp_path / "src.jsonl", [rec("T1-1", ["CVE-2021-44228"]), rec("T1-2", ["CVE-2014-0160"])])
    reg = tmp_path / "variants.yaml"
    reg.write_text(f"variants:\n  rf:\n    adapter: runfile\n    path: '{src.as_posix()}'\n", encoding="utf-8")
    return tmp_path, root, test_run, reg


def test_run_split_test_is_refused(data, capsys):
    tmp, root, _, reg = data
    rc = cli.main(["run", "--variant", "rf", "--registry", str(reg), "--dataset", str(root), "--split", "test",
                   "--out", str(tmp / "o.jsonl")])
    assert rc == 4
    assert "TRE_OPEN_SEALED=E1" in capsys.readouterr().err
    assert not (tmp / "o.jsonl").exists()


def test_run_query_file_with_test_rows_is_refused(data):
    tmp, _, _, reg = data
    qf = write_jsonl(tmp / "mixed.jsonl", [q("T1-1"), q("T1-2", split="test")])
    assert cli.main(["run", "--variant", "rf", "--registry", str(reg), "--queries", str(qf),
                     "--out", str(tmp / "o.jsonl")]) == 4


def test_loading_test_split_is_refused(data):
    _, root, _, _ = data
    with pytest.raises(sealed.SealedError):
        load_dataset(root, "test")


def test_score_pool_report_gates_refuse_test(data, tmp_path):
    tmp, root, test_run, _ = data
    assert cli.main(["score", "--run", str(test_run), "--dataset", str(root), "--split", "test"]) == 4
    # Without --split the run's qids are not in the open dataset -> treated as test -> refused.
    assert cli.main(["score", "--run", str(test_run), "--dataset", str(root)]) == 4
    assert cli.main(["pool", "--runs", str(test_run), "--dataset", str(root), "--out", str(tmp / "p.jsonl")]) == 4
    rep = tmp / "rep.json"
    rep.write_text(json.dumps({"split": "test", "variant": {"name": "x"}}), encoding="utf-8")
    assert cli.main(["report", "--json", str(rep)]) == 4
    assert cli.main(["gates", "--report", str(rep)]) == 4
    assert cli.main(["validate", "--dataset", str(root), "--split", "test"]) == 4


def test_open_with_e1(data, monkeypatch):
    tmp, root, test_run, reg = data
    monkeypatch.setenv(sealed.SEALED_ENV, "E1")
    assert cli.main(["run", "--variant", "rf", "--registry", str(reg), "--dataset", str(root), "--split", "test",
                     "--out", str(tmp / "o.jsonl")]) == 0
    assert cli.main(["score", "--run", str(tmp / "o.jsonl"), "--dataset", str(root), "--bootstrap", "100",
                     "--json-out", str(tmp / "r.json")]) == 0
    assert json.loads((tmp / "r.json").read_text())["split"] == "test"


def test_other_values_do_not_open(data, monkeypatch):
    _, root, _, _ = data
    for v in ("e1", "1", "E1 ", "yes"):
        monkeypatch.setenv(sealed.SEALED_ENV, v)
        with pytest.raises(sealed.SealedError):
            load_dataset(root, "test")
