"""v2 wiring (C4 nickname route, C6 service and endpoints) with small stand-ins for the built indexes."""
from __future__ import annotations

import asyncio
import time

import pytest

from threat_retrieval_engine.v2.nicknames import NicknameRoute
from threat_retrieval_engine.v2.retriever import Hit, Retrieval
from threat_retrieval_engine.v2.service import Calibration, V2Service


def _route():
    return NicknameRoute({
        "eternalblue": {"cves": {"CVE-2017-0144"}, "sources": {"exploitdb"}, "caps_only": False},
        "ms17010": {"cves": {"CVE-2017-0143", "CVE-2017-0144"}, "sources": {"exploitdb"}, "caps_only": False},
        "crime": {"cves": {"CVE-2012-4929"}, "sources": {"wikidata"}, "caps_only": True},
        "dirtycow": {"cves": {"CVE-2016-5195"}, "sources": {"wikidata"}, "caps_only": False},
    })


def test_nickname_route_returns_every_cve_of_a_name():
    hits = {h.key: h.cves for h in _route().match("MS17-010 and Dirty COW patch status")}
    assert hits == {"ms17010": ("CVE-2017-0143", "CVE-2017-0144"), "dirtycow": ("CVE-2016-5195",)}


def test_caps_only_names_need_capitals():
    r = _route()
    assert [h.key for h in r.match("CRIME vulnerability details")] == ["crime"]
    assert r.match("an organised crime group used ransomware") == []


class _Store:
    build_dir = type("P", (), {"name": "store-test"})()


class _Texts:
    def rows(self, ids):
        return {d: {"title": f"title {d}", "description": f"description {d}", "sources": "nvd,cve_list",
                    "kev_listed": 1, "epss_score": 0.9, "published": "2017-03-17"} for d in ids}


class _Retriever:
    store = _Store()
    attack = None
    texts = _Texts()
    nick = _route()
    reranker = object()
    rerank_weight = 0.0
    lexical = type("L", (), {"build_id": "lex-test"})()
    dense = type("D", (), {"index": type("I", (), {"build_id": "dense-test"})()})()

    def __init__(self, delay=0.0):
        self.delay = delay

    def retrieve(self, query, k=100, deadline=None, rerank=True):
        time.sleep(self.delay)
        hits = [Hit("CVE-2017-0144", route="exact_id", matched=["CVE-2017-0144"]),
                Hit("CVE-2017-0143", route="nickname", rerank_logit=4.0, fused_rank=2, lexical_rank=2, dense_rank=1,
                    dense_cosine=0.8, matched=["EternalBlue"]),
                Hit("CVE-2026-33522", route="fused", rerank_logit=-6.0, fused_rank=3, lexical_rank=3)]
        for i, h in enumerate(hits, 1):
            h.rank = i
        return Retrieval(hits, ["CVE-2017-0144"], ["CVE-2099-0001"], [], [], [], {"routes": 0.1, "lexical": 3.0})


def test_match_response_tiers_and_notices():
    svc = V2Service(retriever=_Retriever(), calibration=None, hard_limit_s=3.0)
    svc.calib = None
    out = svc.match("CVE-2017-0144 CVE-2099-0001 EternalBlue 8.8.8.8", top_k=3)
    m = out["top_matches"]
    assert [x["chunk_id"] for x in m] == ["CVE-2017-0144", "CVE-2017-0143", "CVE-2026-33522"]
    assert m[0]["confidence_tier"] == "EXACT" and m[0]["tier_basis"] == "DETERMINISTIC_L1"
    # uncalibrated: never STRONG, marked calibrated false
    assert m[1]["confidence_tier"] == "PARTIAL" and m[1]["calibrated"] is False
    assert m[2]["confidence_tier"] == "UNSUPPORTED"
    assert m[0]["cisa_kev"] is True and m[0]["epss_score"] == 0.9
    codes = {n["code"] for n in out["notices"]}
    assert codes == {"not_in_corpus", "no_ioc_data_in_corpus"}
    assert out["pipeline_version"] == "v2"


def test_ioc_only_query_returns_no_matches():
    svc = V2Service(retriever=_Retriever(), calibration=None, hard_limit_s=3.0)
    svc.calib = None
    out = svc.match("d41d8cd98f00b204e9800998ecf8427e 10.0.0.1", top_k=3)
    assert out["top_matches"] == []
    assert "no_ioc_data_in_corpus" in {n["code"] for n in out["notices"]}


def test_calibrated_tiers():
    cal = Calibration({"features": ["rerank_logit"], "weights": [1.0], "bias": 0.0,
                       "tiers": [["STRONG", 0.95], ["PARTIAL", 0.7], ["WEAK", 0.3]], "version": "t"})
    svc = V2Service(retriever=_Retriever(), calibration=cal, hard_limit_s=3.0)
    m = svc.match("EternalBlue", top_k=3)["top_matches"]
    assert m[1]["confidence_tier"] == "STRONG" and m[1]["calibrated"] is True   # sigmoid(4) = 0.982
    assert m[2]["confidence_tier"] == "UNSUPPORTED"


def test_admission_returns_503_not_504(monkeypatch):
    from fastapi import HTTPException
    from threat_retrieval_engine.api.main import Admission
    adm = Admission(slots=1, queue=0)

    async def scenario():
        slow = asyncio.create_task(adm.run(lambda: time.sleep(0.3), timeout=5))
        await asyncio.sleep(0.05)
        with pytest.raises(HTTPException) as e:
            await adm.run(lambda: 1, timeout=5)
        assert e.value.status_code == 503 and e.value.headers["Retry-After"]
        await slow
        with pytest.raises(HTTPException) as e2:
            await adm.run(lambda: time.sleep(0.3), timeout=0.05)
        assert e2.value.status_code == 503

    asyncio.run(scenario())


def test_match_endpoint_uses_v2(monkeypatch):
    from fastapi.testclient import TestClient
    import threat_retrieval_engine.api.main as main
    import threat_retrieval_engine.v2.service as v2s
    svc = V2Service(retriever=_Retriever(), calibration=None, hard_limit_s=3.0)
    svc.calib = None
    monkeypatch.setenv("TRE_PIPELINE", "v2")
    monkeypatch.setattr(v2s, "_service", svc)
    client = TestClient(main.app)
    r = client.post("/api/v1/threats/match", json={"query": "EternalBlue CVE-2017-0144", "top_k": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pipeline_version"] == "v2" and body["top_matches"][0]["confidence_tier"] == "EXACT"
    assert body["top_matches"][1]["matched_names"] == ["EternalBlue"]
    assert client.get("/api/v1/health").json()["pipeline_version"] == "v2"


@pytest.mark.parametrize("text,ids", [
    ("cve  2024-45593", ["CVE-2024-45593"]), ("CVE_2017_0144 and CVE:2012-0083", ["CVE-2017-0144", "CVE-2012-0083"]),
    ("CVE2015-0703", ["CVE-2015-0703"]), ("CVE 2026 92627", ["CVE-2026-92627"]), ("CVE–2019–7127", ["CVE-2019-7127"]),
    ("xCVE-2020-12345", []), ("CVE-1990-0001", []),
])
def test_loose_cve_ids(text, ids):
    from threat_retrieval_engine.v2.retriever import CVE_LOOSE
    from threat_retrieval_engine.store.text import normalize_cve_id
    got = [x for x in (normalize_cve_id(f"CVE-{a}-{b}") for a, b in (m.groups() for m in CVE_LOOSE.finditer(text))) if x]
    assert got == ids


def test_blend_weights():
    from threat_retrieval_engine.v2.retriever import blend
    head = [Hit("a", rerank_logit=0.0), Hit("b", rerank_logit=1.0), Hit("c", rerank_logit=5.0)]
    assert [h.doc_id for h in blend(head, 0.0)] == ["a", "b", "c"]
    assert [h.doc_id for h in blend(head, float("inf"))] == ["c", "b", "a"]
    assert [h.doc_id for h in blend(head, 1.0)][0] in ("a", "c")


class _Techniques:
    def __init__(self):
        self.calls = 0

    def rank(self, text, k=10, deadline=None, rerank=True):
        from threat_retrieval_engine.v2.techniques import TechniqueHit
        self.calls += 1
        return ([TechniqueHit("attack:T1210", 1, 1, {"keyword": 1}, rerank_score=0.9,
                              evidence="WannaCry used an exploit of SMBv1 to spread.")], {"skipped": [], "timings_ms": {}})

    def info(self):
        return {"build": "tech-test"}


def test_match_returns_attack_techniques_and_can_skip_them():
    tech = _Techniques()
    svc = V2Service(retriever=_Retriever(), calibration=None, hard_limit_s=3.0, techniques=tech)
    out = svc.match("EternalBlue lateral movement over SMB", top_k=2)
    t = out["attack_techniques"]
    assert t[0]["technique_id"] == "T1210" and t[0]["rank"] == 1 and "SMBv1" in t[0]["evidence"]
    assert out["pipeline_profile"]["technique_ms"] >= 0
    out = svc.match("EternalBlue lateral movement over SMB", top_k=2, include_techniques=False)
    assert out["attack_techniques"] == [] and tech.calls == 1


def test_missing_technique_route_is_a_skipped_stage():
    svc = V2Service(retriever=_Retriever(), calibration=None, hard_limit_s=3.0, techniques=None)
    svc.techniques = None
    out = svc.match("EternalBlue lateral movement over SMB", top_k=2, include_techniques=True)
    assert out["attack_techniques"] == [] and "techniques" in out["skipped_stages"]
