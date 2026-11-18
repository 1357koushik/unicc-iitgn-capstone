"""C6: the v2 pipeline behind the unchanged REST contract (``/api/v1/threats/match`` and friends).

One ``V2Service`` per process: opens the store, lexical, dense, ATT&CK, nickname route and reranker once, then
answers requests within a hard deadline (``TRE_MATCH_HARD_LIMIT``, default 3.0 s): each stage checks the time
left, a skipped stage is named in ``skipped_stages``, and the response is built from what finished.

Confidence (plan 4.7):
* ``EXACT`` when the result's CVE or ATT&CK ID is literally in the question (``tier_basis`` DETERMINISTIC_L1).
* otherwise the calibrated model (C7) when ``calibration.json`` is present (``TRE_CALIBRATION``, default the
  file next to this module): ``composite_score`` is the probability of relevance and the tier follows the
  thresholds frozen on dev. Without that file the score is the reranker logit squashed by a sigmoid, marked
  ``calibrated: false`` and capped at tier ``PARTIAL`` (an uncalibrated score never claims STRONG).
* a question made only of hashes, IPs or domains: no CVE data covers indicators, so the response says
  ``no_ioc_data_in_corpus``.

Relevance and risk stay apart: KEV and EPSS are reported beside each match, never mixed into the score.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..indicators import IPV4_PATTERN, MD5_PATTERN, SHA256_PATTERN

logger = logging.getLogger(__name__)

CALIBRATION_FILE = Path(__file__).resolve().parent / "calibration.json"
PIPELINE_VERSION = "v2"
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top)\b", re.I)
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, x))))


class Calibration:
    """Logistic model over the C7 signals plus tier thresholds, both fitted and frozen on judged dev results."""

    def __init__(self, spec: dict):
        self.spec = spec
        self.features = spec["features"]
        self.w = spec["weights"]
        self.b = spec["bias"]
        self.tiers = spec["tiers"]          # [["STRONG", 0.9], ["PARTIAL", 0.6], ["WEAK", 0.2]]
        self.version = spec.get("version", "c7")

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Calibration | None":
        p = Path(path or os.environ.get("TRE_CALIBRATION") or CALIBRATION_FILE)
        if not p.is_file():
            return None
        return cls(json.loads(p.read_text(encoding="utf-8")))

    @staticmethod
    def vector(h, hits, query: str) -> dict[str, float]:
        """The C7 signals of one hit (same definitions at fit and serve time)."""
        nxt = [x.rerank_logit for x in hits if x is not h and x.rerank_logit is not None and x.rank > h.rank]
        lg = h.rerank_logit if h.rerank_logit is not None else -10.0
        return {
            "rerank_logit": lg,
            "margin_next": lg - (max(nxt) if nxt else lg - 5.0),
            "dense_cosine": h.dense_cosine or 0.0,
            "inv_lexical_rank": 1.0 / h.lexical_rank if h.lexical_rank else 0.0,
            "inv_dense_rank": 1.0 / h.dense_rank if h.dense_rank else 0.0,
            "both_lists": 1.0 if (h.lexical_rank and h.dense_rank) else 0.0,
            "inv_fused_rank": 1.0 / h.fused_rank if h.fused_rank else 0.0,
            "inv_rank": 1.0 / h.rank if h.rank else 0.0,
            "nickname_hit": 1.0 if h.route == "nickname" else 0.0,
            "entity_hit": 1.0 if h.route == "entity" else 0.0,
            "log_query_words": math.log1p(len(query.split())),
        }

    def prob(self, x: dict[str, float]) -> float:
        return _sigmoid(self.b + sum(self.w[i] * x.get(f, 0.0) for i, f in enumerate(self.features)))

    def tier(self, p: float) -> str:
        for name, thr in self.tiers:
            if p >= thr:
                return name
        return "UNSUPPORTED"


class V2Service:
    def __init__(self, retriever=None, poc_finder=None, calibration=None, hard_limit_s: float | None = None):
        from .system import open_system
        self.r = retriever or open_system()
        self.calib = calibration if calibration is not None else Calibration.load()
        self.hard_limit = float(hard_limit_s or os.environ.get("TRE_MATCH_HARD_LIMIT", 3.0))
        self.poc_finder = poc_finder
        self.store = self.r.store
        self.attack = self.r.attack
        self.ready = True

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def iocs(query: str) -> list[str]:
        out = []
        for pat in (SHA256_PATTERN, _SHA1, MD5_PATTERN, IPV4_PATTERN, _DOMAIN):
            out += [m.group(0) for m in pat.finditer(query)]
        return list(dict.fromkeys(out))

    def _score(self, h, hits, query) -> tuple[float, str, str, bool]:
        if h.route == "exact_id":
            return 1.0, "EXACT", "DETERMINISTIC_L1", False
        if self.calib is not None:
            p = self.calib.prob(Calibration.vector(h, hits, query))
            return round(p, 4), self.calib.tier(p), "CALIBRATED_LOGISTIC_REGRESSION", True
        if h.rerank_logit is None:
            return 0.0, "UNSUPPORTED", "UNCALIBRATED_NO_RERANK", False
        p = _sigmoid(h.rerank_logit)
        tier = "PARTIAL" if p >= 0.7 else "WEAK" if p >= 0.3 else "UNSUPPORTED"
        return round(p, 4), tier, "UNCALIBRATED_RERANKER_LOGIT", False

    def _match(self, h, row: dict, hits, query: str, cve_in_query: set[str]) -> dict[str, Any]:
        score, tier, basis, calibrated = self._score(h, hits, query)
        is_cve = h.doc_id.startswith("CVE-")
        rels: list[str] = []
        if is_cve and self.attack is not None:
            rels = list(dict.fromkeys(f"exploited-by:{d['doc_id']}" for d in self.attack.docs_for_cve(h.doc_id)))[:20]
        elif self.attack is not None:
            rels = list(dict.fromkeys(f"{e['rel_type']}:{e['dst_doc_id']}" for e in self.attack.edges(h.doc_id)))[:20]
        if is_cve:
            title = row.get("title") or h.doc_id
            snippet = (row.get("description") or "")[:400]
            src = row.get("sources") or ""
            published = row.get("published")
        else:
            title = row.get("title") or h.doc_id
            snippet = (row.get("description") or "")[:400]
            src = "mitre_attack"
            published = None
        sources = [s for s in src.split(",") if s]
        return {
            "rank": h.rank, "chunk_id": h.doc_id, "composite_score": score, "confidence_tier": tier,
            "evidence_breakdown": {
                "semantic_similarity": h.dense_cosine,
                "cve_similarity": 1.0 if h.doc_id in cve_in_query else 0.0,
                "features": {k: v for k, v in {
                    "rerank_logit": h.rerank_logit, "dense_cosine": h.dense_cosine,
                    "lexical_rank": h.lexical_rank, "dense_rank": h.dense_rank, "fused_rank": h.fused_rank,
                }.items() if v is not None},
            },
            "attribution": {"matching_cves": [h.doc_id] if h.doc_id in cve_in_query else [],
                            "matching_iocs": [], "shared_malware": [], "matching_mitre_techniques":
                                [h.doc_id.split(":", 1)[1]] if h.doc_id.startswith("attack:T") else []},
            "stix_relationships": rels,
            "citations": [{"doc_id": h.doc_id, "doc_title": title, "source_org": ",".join(sources) or "unknown",
                           "published_date": published, "text_snippet": snippet,
                           "provenance_status": "VERIFIED" if sources else "MISSING"}],
            "pocs": [],
            "match_type": {"exact_id": "EXACT_ID", "nickname": "NICKNAME", "entity": "ATTACK_ENTITY"}.get(
                h.route, "RETRIEVAL"),
            "tier_basis": basis, "calibrated": calibrated, "degraded": False,
            "model_version": self.calib.version if (calibrated and self.calib) else "v2-c5-int8",
            "evidence_record_class": "DESCRIPTION" if snippet else "METADATA_STUB",
            "sources_found": {s: "present" for s in sources},
            "corroboration_count": max(1, len(sources)),
            "cisa_kev": bool(row.get("kev_listed")) if is_cve else False,
            "epss_score": row.get("epss_score") if is_cve else None,
            "matched_names": h.matched,
        }

    # ------------------------------------------------------------------ endpoints
    def match(self, query: str, top_k: int = 5, include_pocs: bool = False) -> dict[str, Any]:
        t0 = time.perf_counter()
        deadline = t0 + self.hard_limit * 0.85
        notices: list[dict] = []
        iocs = self.iocs(query)
        res = self.r.retrieve(query, k=max(top_k, 10), deadline=deadline)
        for c in res.cve_ids_not_in_corpus:
            notices.append({"code": "not_in_corpus", "value": c})
        if iocs:
            notices.append({"code": "no_ioc_data_in_corpus", "values": iocs[:20],
                            "detail": "hashes, IPs and domains are not covered by the CVE and ATT&CK corpus"})
        stripped = query
        for v in iocs:
            stripped = stripped.replace(v, " ")
        only_iocs = bool(iocs) and not re.search(r"[A-Za-z]{3,}", re.sub(r"\b(?:ip|hash|domain|md5|sha\d*)\b", " ",
                                                                         stripped, flags=re.I))
        hits = [] if only_iocs else res.hits
        t1 = time.perf_counter()
        rows = self.r.texts.rows([h.doc_id for h in hits[:top_k]]) if hits else {}
        cin = set(res.cve_ids_in_query) | {e["doc_id"] for e in res.entities if e.get("matched_by") == "id"}
        matches = [self._match(h, rows.get(h.doc_id, {}), hits, query, cin) for h in hits[:top_k]]
        t2 = time.perf_counter()
        poc_ms = 0.0
        if include_pocs and self.poc_finder is not None:
            poc_ms = self._attach_pocs(matches, res.cve_ids_in_query)
        T = res.timings_ms
        return {
            "query_threat_id": str(uuid.uuid4()),
            "top_matches": matches,
            "pipeline_profile": {
                "exact_match_ms": round(T.get("routes", 0.0), 2),
                "vector_database_ms": round(T.get("lexical", 0) + T.get("dense_encode", 0) + T.get("dense_search", 0), 2),
                "knowledge_graph_ms": 0.0,
                "scoring_ms": round(T.get("rerank", 0.0), 2),
                "citation_ms": round((t2 - t1) * 1000, 2),
                "poc_discovery_ms": round(poc_ms, 2),
                "total_ms": round((time.perf_counter() - t0) * 1000, 2),
            },
            "degraded_components": [s for s in res.skipped],
            "deadline_exceeded": bool(res.skipped and time.perf_counter() > deadline),
            "pipeline_version": PIPELINE_VERSION,
            "skipped_stages": res.skipped,
            "notices": notices,
            "nicknames": res.nicknames,
        }

    def _attach_pocs(self, matches: list[dict], cves_in_query: list[str]) -> float:
        """PoC lookup with its own deadline (d_poc_seconds): CVEs named in the question plus EXACT/STRONG CVE
        results, at most 3; a PoC is attached only to the result whose CVE it was found for."""
        t = time.perf_counter()
        targets = list(dict.fromkeys(list(cves_in_query) + [m["chunk_id"] for m in matches if m["chunk_id"].startswith(
            "CVE-") and m["confidence_tier"] in ("EXACT", "STRONG")]))[:3]
        by = {m["chunk_id"]: m for m in matches}
        for c in targets:
            if c not in by:
                continue
            try:
                resp = self.poc_finder.find_pocs_sync(c, max_results=5)
                by[c]["pocs"] = [r.model_dump() if hasattr(r, "model_dump") else dict(r) for r in resp.results]
            except Exception as exc:  # timeout or source failure: reported on the match, never fails the request
                by[c]["poc_status"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        return (time.perf_counter() - t) * 1000

    def hybrid(self, query: str, top_k: int = 10) -> dict[str, Any]:
        res = self.r.retrieve(query, k=top_k, rerank=False)
        return {"query": query, "pipeline_version": PIPELINE_VERSION, "results": [
            {"chunk_id": h.doc_id, "rrf_score": None, "fused_rank": h.fused_rank, "dense_rank": h.dense_rank,
             "lexical_rank": h.lexical_rank, "dense_score": h.dense_cosine, "route": h.route} for h in res.hits],
            "timings_ms": res.timings_ms}

    def lookup(self, value: str) -> dict[str, Any]:
        present, absent = self.r._cve_ids(value)
        nick = self.r.nick.match(value) if self.r.nick is not None else []
        ents = self.r._entities(value)
        matches = [{"chunk_id": c, "matched_field": "cve_id", "matched_value": c, "doc_id": c} for c in present]
        for h in nick:
            matches += [{"chunk_id": c, "matched_field": "alias", "matched_value": h.surface, "doc_id": c} for c in h.cves]
        for e in ents[0] + ents[1]:
            matches.append({"chunk_id": e["doc_id"], "matched_field": f"attack_{e['matched_by']}",
                            "matched_value": e["surface"], "doc_id": e["doc_id"]})
        return {"target": value, "matches": matches, "not_in_corpus": absent}

    def health(self) -> dict[str, Any]:
        r = self.r
        return {"status": "healthy", "pipeline_version": PIPELINE_VERSION, "components": {
            "store": r.store.build_dir.name, "lexical": r.lexical.build_id, "dense": r.dense.index.build_id,
            "attack": r.attack.build_id if r.attack is not None else "unavailable",
            "reranker": (("available" if r.reranker is not None else "degraded") if r.rerank_weight > 0
                         else "off (TRE_RERANK_WEIGHT=0)"),
            "nicknames": len(r.nick) if r.nick is not None else 0,
            "confidence_model": "calibrated" if self.calib is not None else "uncalibrated"},
            "degraded_components": [] if (r.reranker is not None or r.rerank_weight == 0) else ["reranker"],
            "hard_limit_s": self.hard_limit}


_service: V2Service | None = None
_lock = threading.Lock()


def get_service() -> V2Service:
    global _service
    if _service is None:
        with _lock:
            if _service is None:
                from ..poc_intelligence import get_poc_finder
                _service = V2Service(poc_finder=get_poc_finder())
    return _service
