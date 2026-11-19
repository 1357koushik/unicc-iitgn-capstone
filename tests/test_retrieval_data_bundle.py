"""
scripts/docker/retrieval_data.py: packing and checking the retrieval data bundle (the folder the
Docker container mounts at /data), on tiny made-up builds.

Run:  python -m pytest tests/test_retrieval_data_bundle.py -v
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "retrieval_data", Path(__file__).resolve().parents[1] / "scripts" / "docker" / "retrieval_data.py")
rd = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rd)

STORE, LEX, DENSE, ATTACK, TECH = "store-b1", "lex-b1", "dense-b1", "attack-b1", "tech-b1"
DENSE_MODEL = "bge-large-en-v1.5"
WEIGHTS = b"weights of the dense model"


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        data = json.dumps(data)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def sources(tmp_path, monkeypatch):
    monkeypatch.delenv("TRE_TECH_ENCODERS", raising=False)
    s = tmp_path / "src"
    write(s / "store" / STORE / "manifest.json", {"build_id": STORE})
    write(s / "store" / STORE / "store.sqlite", b"store")
    write(s / "store" / "LATEST", STORE)
    lex = s / "lexical" / LEX
    write(lex / "manifest.json", {"inputs": [{"kind": "cve", "store_build_id": STORE}]})
    for f in ("lexical.sqlite", "impact_data.npy", "impact_indices.npy", "impact_indptr.npy", "impact_rowids.npy"):
        write(lex / f, f.encode())
    dense = s / "dense" / DENSE
    files = {"vectors.npy": b"vectors", "doc_ids.txt": b"CVE-1\n"}
    for f, data in files.items():
        write(dense / f, data)
    write(dense / "manifest.json", {
        "files": {f: sha(d) for f, d in files.items()},
        "inputs": {"store": {"build_id": STORE}, "attack": {"build_id": ATTACK}},
        "model": {"name": DENSE_MODEL, "weights_file": "model.safetensors", "weights_sha256": sha(WEIGHTS)}})
    write(s / "dense" / "other-build" / "manifest.json", {})        # an older build, not the one to pack
    write(s / "attack" / ATTACK / "manifest.json", {})
    write(s / "attack" / ATTACK / "attack.sqlite", b"attack")
    write(s / "attack" / "LATEST", ATTACK)
    tech = s / "techniques" / TECH
    write(tech / "manifest.json", {"attack_build": ATTACK})
    for f in ("entries.jsonl", "emb_bge-large.npy", "emb_qwen3-emb.npy"):
        write(tech / f, f.encode())
    write(s / "techniques" / "LATEST", TECH)
    for m, weights in ((DENSE_MODEL, WEIGHTS), ("Qwen3-Embedding-0.6B", b"qwen")):
        write(s / "models" / m / "config.json", {})
        write(s / "models" / m / "model.safetensors", weights)
    write(s / "models" / "unused-model" / "config.json", {})
    return s


def pack(s: Path, out: Path, **override):
    srcs = {"store": s / "store", "lexical": s / "lexical" / LEX, "dense": s / "dense" / DENSE,
            "attack": s / "attack", "techniques": s / "techniques"}
    srcs.update(override)
    return rd.pack(out, srcs, s / "models")


def test_pack_takes_exactly_the_named_builds_and_needed_models(sources, tmp_path):
    out = tmp_path / "bundle"
    record = pack(sources, out)
    assert {n: c["build_id"] for n, c in record["components"].items()} == {
        "store": STORE, "lexical": LEX, "dense": DENSE, "attack": ATTACK, "techniques": TECH}
    assert sorted(record["models"]) == ["Qwen3-Embedding-0.6B", DENSE_MODEL]
    assert not (out / "dense" / "other-build").exists() and not (out / "models" / "unused-model").exists()
    assert (out / "dense" / "LATEST").read_text().strip() == DENSE
    result = rd.check(out, full=True)
    assert result["ok"], result["problems"]
    assert result["techniques"] is True and result["warnings"] == []


def test_check_finds_incomplete_and_damaged_copies(sources, tmp_path):
    out = tmp_path / "bundle"
    pack(sources, out)
    vectors = out / "dense" / DENSE / "vectors.npy"
    vectors.write_bytes(b"vectorZ")                      # same size, other content
    assert rd.check(out)["ok"]                           # the quick check only sees sizes
    full = rd.check(out, full=True)
    assert not full["ok"] and "damaged" in full["problems"][0]
    vectors.write_bytes(b"vec")                          # cut short
    assert "incomplete copy" in rd.check(out)["problems"][0]


def test_missing_parts_are_named(sources, tmp_path):
    out = tmp_path / "bundle"
    pack(sources, out)
    (out / "models" / DENSE_MODEL / "model.safetensors").unlink()
    assert any("no model weights" in p for p in rd.check(out)["problems"])
    assert rd.check(tmp_path / "nowhere")["problems"] == [f"the data folder {tmp_path / 'nowhere'} does not exist"]


def test_techniques_are_optional(sources, tmp_path):
    out = tmp_path / "bundle"
    record = pack(sources, out, techniques=None)
    assert "techniques" not in record["components"] and list(record["models"]) == [DENSE_MODEL]
    result = rd.check(out)
    assert result["ok"] and result["techniques"] is False
    assert "technique ranking is off" in result["warnings"][0]


def test_technique_ranking_can_be_turned_off(sources, tmp_path):
    out = tmp_path / "bundle"
    pack(sources, out)
    import shutil
    shutil.rmtree(out / "models" / "Qwen3-Embedding-0.6B")
    assert not rd.check(out)["ok"]                       # wanted, but its model is missing
    assert rd.check(out, techniques=False)["ok"]         # TRE_TECHNIQUES=0: not needed


def test_builds_that_do_not_belong_together_are_refused(sources, tmp_path):
    write(sources / "lexical" / LEX / "manifest.json", {"inputs": [{"kind": "cve", "store_build_id": "store-OLD"}]})
    with pytest.raises(rd.BundleError, match="made from store store-OLD"):
        pack(sources, tmp_path / "bundle")


def test_pack_refuses_a_model_that_differs_from_the_index(sources, tmp_path):
    write(sources / "models" / DENSE_MODEL / "model.safetensors", b"other weights")
    with pytest.raises(rd.BundleError, match="weights differ"):
        pack(sources, tmp_path / "bundle")


def test_bundle_without_record_still_checked_for_structure(sources, tmp_path):
    out = tmp_path / "bundle"
    pack(sources, out)
    (out / rd.BUNDLE_FILE).unlink()
    result = rd.check(out)
    assert result["ok"] and any("no BUNDLE.json" in w for w in result["warnings"])


def test_command_line_exit_codes(sources, tmp_path, capsys):
    out = tmp_path / "bundle"
    pack(sources, out)
    assert rd.main(["check", str(out), "--full"]) == 0
    assert "OK: retrieval data" in capsys.readouterr().out
    (out / "store" / "LATEST").write_text("missing-build")
    assert rd.main(["check", str(out)]) == 1
    assert "not usable" in capsys.readouterr().err
