"""C3 encode job and builds with a tiny local model: documented input format (prefixes, pooling, token cap),
deterministic batching, checkpointed and resumable multi-part encoding, assembly checks, the retriever
(model consistency, query cache) and the document-set file."""
from __future__ import annotations

import json
import shutil

import numpy as np
import pytest

pytest.importorskip("torch")
pytest.importorskip("transformers")

from threat_retrieval_engine.dense import build as B
from threat_retrieval_engine.dense import models as M
from threat_retrieval_engine.dense.encoder import Encoder, EncoderError, normalize_text
from threat_retrieval_engine.dense.index import DenseIndex
from threat_retrieval_engine.dense.retriever import DenseRetriever
from threat_retrieval_engine.dense.sources import DocumentSet

from dense_fixtures import document_set, make_tiny_model


@pytest.fixture(scope="module")
def tiny(tmp_path_factory):
    root = tmp_path_factory.mktemp("models")
    spec = make_tiny_model(root)
    cls = make_tiny_model(root, pooling="cls", name="tiny-cls", query_prefix="Represent: ", passage_prefix="")
    import os
    old = os.environ.get("TRE_MODEL_DIR")
    os.environ["TRE_MODEL_DIR"] = str(root)
    yield spec, cls, root
    if old is None:
        os.environ.pop("TRE_MODEL_DIR", None)
    else:
        os.environ["TRE_MODEL_DIR"] = old
    M.MODELS.pop("tiny-test", None)
    M.MODELS.pop("tiny-cls", None)


def test_documented_formats_are_pinned():
    m = M.MODELS
    assert m["bge-m3"].query_prefix == "" and m["bge-m3"].pooling == "cls"
    assert m["bge-large-en-v1.5"].query_prefix == M.BGE_EN_INSTRUCTION and m["bge-large-en-v1.5"].passage_prefix == ""
    assert m["bge-base-en-v1.5"].query_prefix == M.BGE_EN_INSTRUCTION and m["bge-base-en-v1.5"].dim == 768
    assert (m["e5-large-v2"].query_prefix, m["e5-large-v2"].passage_prefix, m["e5-large-v2"].pooling) == \
        ("query: ", "passage: ", "mean")
    assert (m["gte-large"].query_prefix, m["gte-large"].pooling) == ("", "mean")
    for name in M.COMPARED:
        s = m[name]
        assert len(s.revision) == 40 and len(s.weights_sha256) == 64
    assert M.DOCUMENT_MAX_TOKENS == 256 and M.QUERY_MAX_TOKENS == 256


def test_normalize_text():
    assert normalize_text("  a \t\n b  ", 256) == "a b"
    assert len(normalize_text("x" * 10**6, 256)) == 64 * 256
    with pytest.raises(TypeError):
        normalize_text(None, 256)


def test_encoder_format_and_determinism(tiny):
    spec, cls_spec, _ = tiny
    enc = Encoder.load("tiny-test", threads=2, batch_size=4, batch_tokens=64)
    assert enc.format(["a  b"], "query", 256) == ["query: a b"]
    assert enc.format(["a"], "passage", 256) == ["passage: a"]
    ids = enc.tokenize(["overflow " * 500], "passage", 16)
    assert len(ids[0]) == 16  # cap counts special tokens and the prefix
    texts = ["remote code execution", "overflow " * 300, "sql injection in plugin", "", "a"]
    v1 = enc.encode_documents(texts)
    v2 = enc.encode_documents(list(texts))
    assert v1.dtype == np.float32 and v1.shape == (5, 32)
    assert np.array_equal(v1, v2)
    assert np.allclose(np.linalg.norm(v1, axis=1), 1.0, atol=1e-5)
    # batch composition does not change a vector beyond float rounding
    one = np.stack([enc.encode_documents([t])[0] for t in texts])
    assert np.abs(one - v1).max() < 1e-5
    # mean pooling ignores padding; CLS model uses the first token
    enc_cls = Encoder.load("tiny-cls", threads=2)
    assert enc_cls.format(["x"], "query", 256) == ["Represent: x"]
    assert enc_cls.encode_queries(["x"]).shape == (1, 32)
    # batches: longest first, bounded by size and padded tokens
    b = enc.batches([3, 10, 10, 2, 7, 1])
    assert b[0][:2] == [1, 2] and sum(len(x) for x in b) == 6
    assert all(len(x) <= 4 and max([3, 10, 10, 2, 7, 1][i] for i in x) * len(x) <= 64 for x in b)


def test_weights_checksum_refused(tiny, tmp_path):
    spec, _, root = tiny
    bad = M.ModelSpec(**{**spec.as_dict(), "name": "tiny-bad", "weights_sha256": "0" * 64,
                         "files": tuple(spec.files)})
    shutil.copytree(root / "tiny-test", root / "tiny-bad")
    M.MODELS["tiny-bad"] = bad
    try:
        with pytest.raises(EncoderError, match="sha256"):
            Encoder.load("tiny-bad")
    finally:
        M.MODELS.pop("tiny-bad")


def test_document_set_roundtrip(tmp_path):
    ds = document_set()
    p = tmp_path / "docs.jsonl"
    sha = ds.write(p)
    back = DocumentSet.read(p)
    assert back.sha256() == sha and back.doc_ids == ds.doc_ids and back.kind_ranges() == {"cve": [0, 120],
                                                                                          "attack": [120, 135]}
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")  # truncated file
    with pytest.raises(ValueError):
        DocumentSet.read(p)
    sub = ds.subset(set(ds.doc_ids[::3]), {"rule": "every third"})
    assert sub.doc_ids == ds.doc_ids[::3]


def test_encode_job_resume_and_assemble(tiny, tmp_path):
    ds = document_set()
    docs = tmp_path / "docs.jsonl"
    ds.write(docs)
    work = tmp_path / "work"
    a = B.encode_job(docs, "tiny-test", work, max_tokens=64, chunk=20, part=(0, 2), threads=2, progress=lambda m: None)
    with pytest.raises(B.BuildError, match="missing"):
        B.assemble(docs, work, tmp_path / "out", progress=lambda m: None)
    b = B.encode_job(docs, "tiny-test", work, max_tokens=64, chunk=20, part=(1, 2), threads=2, progress=lambda m: None)
    assert a["chunks_encoded"] + b["chunks_encoded"] == 7
    again = B.encode_job(docs, "tiny-test", work, max_tokens=64, chunk=20, threads=2, progress=lambda m: None)
    assert again["chunks_encoded"] == 0 and again["chunks_skipped"] == 7
    with pytest.raises(B.BuildError, match="another job"):
        B.encode_job(docs, "tiny-test", work, max_tokens=32, chunk=20, threads=2, progress=lambda m: None)
    bdir = B.assemble(docs, work, tmp_path / "out", progress=lambda m: None)
    m = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    assert m["documents"] == len(ds) and m["counts"] == {"cve": 120, "attack": 15}
    assert m["model"]["name"] == "tiny-test" and m["model"]["document_max_tokens"] == 64
    assert m["encode"]["stats"]["at_cap"] >= 1 and m["inputs"]["documents_sha256"] == ds.sha256()
    ix = DenseIndex.open(bdir, check_norms=True)
    enc = Encoder.load("tiny-test", threads=2)
    direct = enc.encode_documents(ds.texts, max_tokens=64)
    assert np.abs(direct - ix.vectors).max() < 1e-5  # rows in document order, same vectors
    # a damaged chunk is detected on resume and on assembly
    v = np.load(work / "chunk_00003.npy")
    v[0, 0] += 1
    np.save(work / "chunk_00003.npy", v)
    with pytest.raises(B.BuildError):
        B.encode_job(docs, "tiny-test", work, max_tokens=64, chunk=20, threads=2, progress=lambda m: None)
    with pytest.raises(B.BuildError):
        B.assemble(docs, work, tmp_path / "out2", progress=lambda m: None)


def test_retriever(tiny, tmp_path):
    ds = document_set()
    docs = tmp_path / "docs.jsonl"
    ds.write(docs)
    B.encode_job(docs, "tiny-test", tmp_path / "w", chunk=50, threads=2, progress=lambda m: None)
    bdir = B.assemble(docs, tmp_path / "w", tmp_path / "out", progress=lambda m: None)
    r = DenseRetriever.open(bdir, torch_threads=2)
    assert r.model_input("  sql   injection ") == "query: sql injection"
    res = r.search("sql injection in a plugin", k=10, kinds=None)
    assert len(res.hits) == 10 and not res.cached
    again = r.search("sql   injection in a plugin", k=10, kinds=None)
    assert again.cached and again.hits == res.hits
    assert all(d.startswith("attack:") for d, _ in r.search("phishing", k=5, kinds=("attack",)).hits)
    for weird in ["", " ", "\x00‮", "x" * 100_000, "漏洞 😀"]:
        assert isinstance(r.search(weird, k=3).hits, list)
    with pytest.raises(TypeError):
        r.search(None)
    with pytest.raises(ValueError):
        DenseRetriever(DenseIndex.open(bdir), query_format="v1")  # only for the exported v1 vectors
    other = Encoder.load("tiny-cls", threads=2)
    with pytest.raises(ValueError):
        DenseRetriever(DenseIndex.open(bdir), encoder=other)
    # an index whose manifest names another revision is refused
    m = json.loads((bdir / "manifest.json").read_text(encoding="utf-8"))
    m["model"]["revision"] = "1" * 40
    (bdir / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(ValueError, match="revision"):
        DenseRetriever.open(bdir)
