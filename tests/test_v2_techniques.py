"""Technique route: knowledge base, keyword list, fusion, reranking and the service field."""
import json

import numpy as np
import pytest

from threat_retrieval_engine.v2 import techniques as T


class FakeEncoder:
    name = "fake"

    def __init__(self, vocab):
        self.vocab = vocab

    def _vec(self, text):
        v = np.array([text.lower().count(w) for w in self.vocab], dtype=np.float32) + 1e-3
        return v / np.linalg.norm(v)

    def docs(self, texts):
        return np.stack([self._vec(t) for t in texts])

    def query(self, text):
        return self._vec(text)


class FakeReranker(T.Reranker):
    name = "fake-rerank"

    def score(self, query, docs):
        return [1.0 if "powershell" in d.lower() else 0.0 for d in docs]


ENTRIES = [
    T.Entry("attack:T1003.001", "description", "LSASS Memory. Adversaries may access credential material in LSASS."),
    T.Entry("attack:T1003.001", "procedure", "APT1 used Mimikatz to dump credentials from LSASS memory."),
    T.Entry("attack:T1059.001", "description", "PowerShell. Adversaries may abuse PowerShell commands and scripts."),
    T.Entry("attack:T1059.001", "procedure", "The loader ran an encoded PowerShell command."),
    T.Entry("attack:T1190", "description", "Exploit Public-Facing Application. Adversaries may exploit a web server."),
]


@pytest.fixture()
def build(tmp_path):
    (tmp_path / "entries.jsonl").write_text(
        "\n".join(json.dumps({"doc_id": e.doc_id, "kind": e.kind, "text": e.text}) for e in ENTRIES) + "\n")
    (tmp_path / "manifest.json").write_text(json.dumps({"build_id": "test"}))
    enc = FakeEncoder(["lsass", "mimikatz", "powershell", "exploit", "web"])
    np.save(tmp_path / "emb_fake.npy", enc.docs([e.text for e in ENTRIES]))
    return tmp_path, enc


def ranker(build, monkeypatch, reranker=None):
    path, enc = build
    T.ENCODERS["fake"] = ("unused", "", None)
    monkeypatch.setattr(T, "Encoder", lambda name, threads=None: enc)
    monkeypatch.setattr(T, "load_reranker", lambda name, threads=None: reranker)
    return T.TechniqueRanker(path, None, ["fake"], reranker="x" if reranker else None)


def test_clean_removes_citations_and_links():
    assert T.clean("Uses [Mimikatz](https://x/y) (Citation: Foo 2020) to <code>dump</code>.") == \
        "Uses Mimikatz to dump."


def test_bm25_scores_shared_terms_only():
    bm = T.BM25([e.text for e in ENTRIES])
    s = bm.scores("mimikatz lsass")
    assert s[1] > 0 and s[4] == 0


def test_reducer_takes_best_entry_per_technique():
    red = T._Reducer([e.doc_id for e in ENTRIES])
    assert red.techs == ["attack:T1003.001", "attack:T1059.001", "attack:T1190"]
    assert list(red.best(np.array([0.1, 0.9, 0.2, 0.3, 0.5]))) == pytest.approx([0.9, 0.3, 0.5])


def test_reducer_rejects_ungrouped_entries():
    with pytest.raises(ValueError):
        T._Reducer(["a", "b", "a"])


def test_rank_fuses_keyword_and_dense(build, monkeypatch):
    r = ranker(build, monkeypatch)
    hits, info = r.rank("Mimikatz dumped LSASS credentials", k=3)
    assert hits[0].doc_id == "attack:T1003.001"
    assert hits[0].list_ranks["keyword"] == 1 and hits[0].list_ranks["fake"] == 1
    assert "Mimikatz" in hits[0].evidence
    assert [h.rank for h in hits] == [1, 2, 3] and not info["skipped"]


def test_reranker_reorders_head(build, monkeypatch):
    r = ranker(build, monkeypatch, FakeReranker())
    hits, info = r.rank("Mimikatz dumped LSASS credentials", k=3)
    assert hits[0].doc_id == "attack:T1059.001" and hits[0].rerank_score == 1.0
    assert "rerank" in info["timings_ms"]


def test_reranker_skipped_near_deadline(build, monkeypatch):
    import time
    r = ranker(build, monkeypatch, FakeReranker())
    hits, info = r.rank("Mimikatz dumped LSASS credentials", k=3, deadline=time.perf_counter() + 0.1)
    assert info["skipped"] == ["technique_rerank"] and hits[0].doc_id == "attack:T1003.001"


def test_entries_must_match_embeddings(build, monkeypatch):
    path, enc = build
    np.save(path / "emb_fake.npy", np.zeros((2, 5), dtype=np.float32))
    with pytest.raises(ValueError):
        ranker(build, monkeypatch)
