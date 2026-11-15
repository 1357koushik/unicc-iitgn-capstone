from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from threat_retrieval_engine.config import get_config
from threat_retrieval_engine.api.helpers import (
    build_citation,
    calculate_composite_score,
    classify_confidence_tier,
    extract_attribution,
    jaccard_similarity,
    parse_query_entities,
    ParsedEntities,
)
from threat_retrieval_engine.api.schemas import (
    AttributionSchema,
    CitationSchema,
    EvidenceBreakdownSchema,
    MatchResponse,
    PipelineProfileSchema,
    PoCResultSchema,
    TopMatchSchema,
)
from threat_retrieval_engine.api.confidence import (
    QueryProfile,
    parse_query_profile,
    resolve_confidence,
    get_confidence_model,
    classify_evidence_record_class,
)
from threat_retrieval_engine.search_engine.exact_lookup import exact_lookup
from threat_retrieval_engine.search_engine.vector_database import (
    fetch_chunk_metadata,
    fetch_text,
    setup_databases,
)

logger = logging.getLogger(__name__)


def _load_attack_graph():
    """The C9 ATT&CK graph (store, graph, gazetteer) shared with the query parsers; None when no build can be
    opened, in which case the component is reported unavailable (there is no fallback data)."""
    from threat_retrieval_engine.attack import runtime as attack_runtime

    return attack_runtime.get_attack_graph()


class ThreatRetrieverEngine:
    """
    Unified Orchestrator coordinating:
      Engine 1: Exact Match (exact_lookup.py)
      Engine 2: Vector Hybrid Search (hybrid_search.py via BGE-M3 + BM25)
      Engine 3: MITRE ATT&CK graph (C9 ATT&CK build, threat_retrieval_engine.attack)
    """

    def __init__(
        self,
        qdrant_client=None,
        sqlite_conn=None,
        hybrid_searcher=None,
        attack_graph=None,
        reranker=None,
        confidence_model=None,
    ) -> None:
        self.qdrant = qdrant_client
        self.sqlite = sqlite_conn
        self.sqlite_path = None
        self.hybrid_searcher = hybrid_searcher
        self.attack_graph = attack_graph
        self.reranker = reranker
        self.confidence_model = confidence_model
        self.attack_graph_status: dict[str, Any] = {"status": "uninitialized"}
        self.degraded_components: list[str] = []
        self._init_lock = threading.RLock()
        self._initialized = False

    def get_sqlite_conn(self) -> sqlite3.Connection:
        """Thread-safe SQLite connection accessor (R-4.1)."""
        if self.sqlite_path and Path(self.sqlite_path).is_file():
            try:
                from threat_retrieval_engine.search_engine.vector_database import get_thread_sqlite
                return get_thread_sqlite(str(self.sqlite_path), readonly=True)
            except Exception:
                pass
        return self.sqlite

    def initialize(self, qdrant_path: str | None = None, sqlite_path: str | None = None) -> None:
        """Initialize all three search engines and knowledge graph."""
        with self._init_lock:
            if self._initialized:
                return

            cfg = get_config()
            self.degraded_components = []
            self.sqlite_path = sqlite_path or str(cfg.sqlite_db_path)

            # 1. Databases (Qdrant + SQLite)
            if self.qdrant is None or self.sqlite is None:
                db_kwargs = {
                    "qdrant_path": qdrant_path or str(cfg.qdrant_storage_path),
                    "sqlite_path": sqlite_path or str(cfg.sqlite_db_path),
                }
                try:
                    self.qdrant, self.sqlite = setup_databases(**db_kwargs)
                except Exception as exc:
                    logger.error("Failed to setup databases: %s", exc)
                    self.degraded_components.append("databases")

            # 2. ATT&CK graph (C9 build). Relationships in responses come only from it.
            if self.attack_graph is None:
                self.attack_graph = _load_attack_graph()
            if self.attack_graph is None:
                from threat_retrieval_engine.attack import runtime as attack_runtime

                self.attack_graph_status = {"status": "unavailable", "reason": attack_runtime.status().get("reason")}
                self.degraded_components.append("attack_graph")
            else:
                self.attack_graph_status = {"status": "available", "build_id": self.attack_graph.build_id,
                                            "attack_version": self.attack_graph.store.attack_version}

            # 3. Hybrid Searcher (BM25 + BGE-M3)
            if self.hybrid_searcher is None:
                from threat_retrieval_engine.search_engine.bm25_index import build_from_sqlite, BM25Index
                from threat_retrieval_engine.search_engine.hybrid_search import HybridSearcher, default_query_encoder

                bm25_cache_file = cfg.bm25_cache_file
                try:
                    bm25 = build_from_sqlite(self.sqlite, cache_path=bm25_cache_file)
                except Exception as exc:
                    logger.warning("BM25 index build failed: %s; lexical search degraded.", exc)
                    self.degraded_components.append("bm25")
                    bm25 = BM25Index()

                # Vectorizer
                try:
                    from threat_retrieval_engine.search_engine.vectorizer import BGEVectorizer
                    logger.info("Pre-loading BGE-M3 embedding model during startup...")
                    vectorizer = BGEVectorizer(eager_load=True)
                    query_encoder = default_query_encoder(vectorizer)
                    query_encoder("startup warmup query")
                    logger.info("BGE-M3 embedding model preloaded successfully.")
                except Exception as exc:
                    logger.warning("BGEVectorizer load deferred or stubbed: %s", exc)
                    self.degraded_components.append("embedder")
                    query_encoder = lambda q: [0.0] * 1024

                self.hybrid_searcher = HybridSearcher(
                    qdrant=self.qdrant,
                    sqlite=self.sqlite,
                    bm25=bm25,
                    query_encoder=query_encoder,
                    rrf_k=cfg.rrf_k,
                )

            # 4. Cross-Encoder Reranker
            if self.reranker is None:
                try:
                    from threat_retrieval_engine.search_engine.reranker import CrossEncoderReranker
                    logger.info("Pre-loading Cross-Encoder Reranker during startup...")
                    reranker_instance = CrossEncoderReranker()
                    reranker_instance._load()
                    self.reranker = reranker_instance
                    logger.info("Reranker preloaded successfully.")
                except Exception as exc:
                    logger.warning("Reranker load failed: %s; running in degraded rerank mode.", exc)
                    self.degraded_components.append("reranker")
                    self.reranker = None

            # 5. Learned Confidence Model
            if self.confidence_model is None:
                try:
                    self.confidence_model = get_confidence_model()
                except Exception as exc:
                    logger.warning("Failed to load confidence model: %s. Using degraded mode.", exc)
                    self.degraded_components.append("confidence_model")
                    self.confidence_model = None

            self._initialized = True
            logger.info("ThreatRetrieverEngine initialized with degraded_components=%s", self.degraded_components)

    def run_query(
        self,
        query: str,
        top_k: int = 5,
        alpha: float = 0.5,
        allowed_sources: list[str] | None = None,
        include_pocs: bool = False,
    ) -> MatchResponse:
        """Execute exact match, vector hybrid search, and knowledge graph expansion."""
        t_total_start = time.perf_counter()
        self.initialize()
        cfg = get_config()

        query_threat_id = f"query_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        query_ent = parse_query_entities(query)
        sqlite_handle = self.get_sqlite_conn()

        # -------------------------------------------------------------------
        # Engine 1: Exact Match Lookup (Qdrant & SQLite) (R2, R7)
        # -------------------------------------------------------------------
        t_exact_start = time.perf_counter()
        exact_results = []
        try:
            exact_matches = exact_lookup(
                self.qdrant,
                sqlite_handle,
                query=query,
                limit=top_k,
                hydrate=True,
                allowed_sources=allowed_sources,
            )
            for m in exact_matches:
                meta = m.metadata or fetch_chunk_metadata(m.chunk_id, sqlite_handle) or {}
                txt = meta.get("text") or fetch_text(m.chunk_id, sqlite_handle) or ""
                doc_id = meta.get("doc_id", "")
                
                # Determine authentic match kind (R7)
                match_kind = "MENTION"
                if query_ent.cves and any(doc_id.upper().startswith(c) for c in query_ent.cves):
                    match_kind = "PRIMARY_ID"
                elif query_ent.hashes:
                    match_kind = "HASH"

                exact_results.append({
                    "chunk_id": m.chunk_id,
                    "doc_id": doc_id,
                    "source_org": meta.get("source_org", ""),
                    "text": txt,
                    "metadata": meta,
                    "entities": meta.get("entities", {}),
                    "exact_score": 1.0,
                    "dense_score": None,      # R7: never fabricate 1.0 semantic similarity
                    "rrf_score": None,        # R7: unmeasured in exact lookup
                    "identifier_match_kind": match_kind,
                })
        except Exception as exc:
            logger.warning("Exact match lookup encountered error: %s", exc)
        exact_match_ms = (time.perf_counter() - t_exact_start) * 1000

        # -------------------------------------------------------------------
        # Engine 2: Vector Hybrid Search (BGE-M3 + BM25 RRF) (R13)
        # -------------------------------------------------------------------
        t_vec_start = time.perf_counter()
        hybrid_results = []
        try:
            search_k = max(top_k * 4, 20)
            hits = self.hybrid_searcher.search(
                query=query,
                top_k=search_k,
                allowed_sources=allowed_sources,
                alpha=alpha,
            )
            for h in hits:
                hybrid_results.append({
                    "chunk_id": h.chunk_id,
                    "rrf_score": h.rrf_score,
                    "dense_score": h.dense_score,
                    "lexical_rank": h.lexical_rank,
                    "payload": h.payload or {},
                })
        except Exception as exc:
            logger.warning("Hybrid search encountered error: %s", exc)
        vector_database_ms = (time.perf_counter() - t_vec_start) * 1000

        # -------------------------------------------------------------------
        # Merge & Hydrate Candidates from SQLite (R2, R7, R15)
        # -------------------------------------------------------------------
        candidate_map: dict[str, dict[str, Any]] = {}
        for er in exact_results:
            cid = er["chunk_id"]
            meta = er.get("metadata") or fetch_chunk_metadata(cid, sqlite_handle) or {}
            txt = er.get("text") or fetch_text(cid, sqlite_handle) or ""
            candidate_map[cid] = {
                "chunk_id": cid,
                "text": txt,
                "metadata": meta,
                "is_exact": True,
                "dense_score": er["dense_score"],
                "rrf_score": er["rrf_score"],
                "identifier_match_kind": er["identifier_match_kind"],
                "source_org": meta.get("source_org", ""),
                "doc_id": meta.get("doc_id", ""),
            }

        for hr in hybrid_results:
            cid = hr["chunk_id"]
            if cid not in candidate_map:
                meta = fetch_chunk_metadata(cid, sqlite_handle) or {}
                txt = fetch_text(cid, sqlite_handle) or (hr["payload"].get("text", "") if hr.get("payload") else "")
                candidate_map[cid] = {
                    "chunk_id": cid,
                    "text": txt,
                    "metadata": meta,
                    "is_exact": False,
                    "dense_score": hr["dense_score"],
                    "rrf_score": hr["rrf_score"],
                    "identifier_match_kind": "HYBRID",
                    "source_org": meta.get("source_org", ""),
                    "doc_id": meta.get("doc_id", ""),
                }
            else:
                # Merge hybrid scores if exact lookup candidate didn't have them
                if candidate_map[cid].get("dense_score") is None:
                    candidate_map[cid]["dense_score"] = hr.get("dense_score")
                if candidate_map[cid].get("rrf_score") is None:
                    candidate_map[cid]["rrf_score"] = hr.get("rrf_score")

        # -------------------------------------------------------------------
        # Engine 2.5: Cross-Encoder Reranking (R12, R-2.5, N-4)
        # -------------------------------------------------------------------
        t_rerank_start = time.perf_counter()
        elapsed_before_rerank = time.perf_counter() - t_total_start
        if elapsed_before_rerank >= (cfg.d_match_seconds * 0.70):
            logger.warning("Over 70%% of match deadline elapsed (%.2fs); skipping cross-encoder reranking.", elapsed_before_rerank)
        elif getattr(self, "reranker", None) and candidate_map:
            try:
                # Rerank on enriched_text (R12)
                rerank_pairs = []
                for cid, c in candidate_map.items():
                    meta = c.get("metadata") or {}
                    enriched = meta.get("enriched_text") or c.get("text", "")
                    rerank_pairs.append((cid, enriched))

                rerank_limit = min(len(candidate_map), max(top_k * 4, 25))
                reranked = self.reranker.rerank(query, rerank_pairs, top_k=rerank_limit)

                # Update measured rerank scores; do NOT overwrite dense_score (N-4)
                for res in reranked:
                    if res.chunk_id in candidate_map:
                        candidate_map[res.chunk_id]["rerank_score"] = res.rerank_score
            except Exception as exc:
                logger.warning("Reranking encountered error: %s", exc)

        rerank_ms = (time.perf_counter() - t_rerank_start) * 1000
        vector_database_ms += rerank_ms

        # -------------------------------------------------------------------
        # Engine 3: Knowledge Graph Expansion (R8, R-2.5, C-1)
        # -------------------------------------------------------------------
        t_kg_start = time.perf_counter()
        chunk_graph_relations: dict[str, list[str]] = {}

        elapsed_before_kg = time.perf_counter() - t_total_start
        if elapsed_before_kg >= (cfg.d_match_seconds * 0.85):
            logger.warning("Over 85%% of match deadline elapsed (%.2fs); skipping knowledge graph expansion.", elapsed_before_kg)
        elif self.attack_graph and candidate_map:
            # Query context relationships: computed ONCE outside the candidate loop (C-1)
            query_rels: list[str] = []
            if query_ent.threat_actors or query_ent.mitre_techniques or query_ent.malware:
                try:
                    expanded_q = self.attack_graph.expand(
                        threat_actors=query_ent.threat_actors,
                        techniques=query_ent.mitre_techniques,
                        malware=query_ent.malware,
                    )
                    for r in expanded_q.get("relationships", []):
                        query_rels.append(f"[QUERY_CONTEXT] {r}")
                except Exception as q_exc:
                    logger.warning("Query graph expansion failed: %s", q_exc)

            doc_expansion_cache: dict[tuple, list[str]] = {}
            for cid, cand in candidate_map.items():
                meta = cand.get("metadata") or {}
                txt = cand.get("text") or ""
                raw_ent = meta.get("entities") or {}
                if isinstance(raw_ent, str):
                    try:
                        raw_ent = json.loads(raw_ent)
                    except Exception:
                        raw_ent = {}

                # Document entities cached by entity tuple (C-1)
                doc_actors = tuple(sorted(str(a) for a in raw_ent.get("threat_actors", [])))
                doc_ttps = tuple(sorted(str(t) for t in raw_ent.get("mitre_ttps", [])))
                doc_mal = tuple(sorted(str(m) for m in raw_ent.get("malware_families", [])))
                doc_key = (doc_actors, doc_ttps, doc_mal)

                if doc_key in doc_expansion_cache:
                    doc_rels = doc_expansion_cache[doc_key]
                else:
                    doc_rels = []
                    if any(doc_key):
                        try:
                            expanded_doc = self.attack_graph.expand(
                                threat_actors=list(doc_actors),
                                techniques=list(doc_ttps),
                                malware=list(doc_mal),
                            )
                            for r in expanded_doc.get("relationships", []):
                                doc_rels.append(f"[DOCUMENT] {r}")
                        except Exception as doc_exc:
                            logger.warning("Doc graph expansion failed: %s", doc_exc)
                    doc_expansion_cache[doc_key] = doc_rels

                combined_rels = list(dict.fromkeys(doc_rels + query_rels))
                chunk_graph_relations[cid] = combined_rels

        knowledge_graph_ms = (time.perf_counter() - t_kg_start) * 1000

        # -------------------------------------------------------------------
        # Scoring & Classification (R1, R6a, R17, R20)
        # -------------------------------------------------------------------
        t_score_start = time.perf_counter()
        scored_candidates = []
        query_profile = parse_query_profile(query)
        reranker_active = self.reranker is not None

        for cid, cand in candidate_map.items():
            meta = cand.get("metadata") or {}
            txt = cand.get("text") or ""
            attr_dict = extract_attribution(query_ent, meta, txt)
            cand["attribution"] = attr_dict

            semantic_sim = float(cand.get("dense_score") or cand.get("rerank_score") or 0.0)

            resolution = resolve_confidence(
                query_profile=query_profile,
                candidate_chunk=cand,
                candidate_score=semantic_sim,
                model=self.confidence_model,
                force_degraded=not reranker_active,
            )

            # Structured multi-source corroboration (R10)
            src_org = str(cand.get("source_org", "UNKNOWN")).upper()
            sources_found = {src_org: "FOUND"}
            # Check for EPSS / KEV mentions or records
            cisa_kev = False
            epss_score = None
            if "CISA" in src_org or "_KEV" in str(cand.get("doc_id", "")):
                cisa_kev = True
                sources_found["CISA_KEV"] = "FOUND"
            if "EPSS" in src_org or "_EPSS" in str(cand.get("doc_id", "")):
                sources_found["EPSS"] = "FOUND"
                # Extract EPSS numerical score if present
                m_epss = re.search(r"score of (0\.\d+)", txt)
                if m_epss:
                    try:
                        epss_score = float(m_epss.group(1))
                    except ValueError:
                        pass

            scored_candidates.append({
                "chunk_id": cid,
                "composite_score": resolution.probability,
                "confidence_tier": resolution.tier,
                "match_type": resolution.match_type,
                "tier_basis": resolution.tier_basis,
                "calibrated": resolution.calibrated,
                "degraded": resolution.degraded,
                "model_version": resolution.model_version,
                "features": resolution.features,
                "evidence_record_class": resolution.evidence_record_class,
                "sources_found": sources_found,
                "corroboration_count": len(sources_found),
                "cisa_kev": cisa_kev,
                "epss_score": epss_score,
                "evidence_breakdown": EvidenceBreakdownSchema(
                    ioc_similarity=round(resolution.features.get("ioc_coverage", 0.0), 2),
                    cve_similarity=round(resolution.features.get("cve_coverage", 0.0), 2),
                    ttp_similarity=round(resolution.features.get("ttp_coverage", 0.0), 2),
                    semantic_similarity=round(semantic_sim, 2) if semantic_sim > 0.0 else None,
                    features=resolution.features,
                ),
                "metadata": meta,
                "text": txt,
                "stix_relationships": chunk_graph_relations.get(cid, []),
                "attribution": attr_dict,
                "dense_score": semantic_sim,
            })

        # Sort candidates descending: composite_score, prioritize DESCRIPTION over METADATA_STUB (R6a)
        scored_candidates.sort(
            key=lambda x: (
                x["composite_score"],
                1 if x["evidence_record_class"] == "DESCRIPTION" else 0,
                x.get("dense_score", 0.0),
            ),
            reverse=True,
        )
        top_candidates = scored_candidates[:top_k]
        scoring_ms = (time.perf_counter() - t_score_start) * 1000

        # -------------------------------------------------------------------
        # Attribution, Citations & Optional Decoupled PoC Discovery (R34)
        # -------------------------------------------------------------------
        t_cite_start = time.perf_counter()
        top_matches: list[TopMatchSchema] = []

        # Decoupled PoC discovery: only run if include_pocs is True (R34, R-2.1, C-2, N-5)
        t_poc_start = time.perf_counter()
        discovered_pocs: dict[str, list[PoCResultSchema]] = {}
        poc_degraded = False
        if include_pocs and query_ent.cves:
            target_cves = list(dict.fromkeys(cve.upper() for cve in query_ent.cves))[:3]
            remaining_budget = max(0.0, cfg.d_match_seconds - (time.perf_counter() - t_total_start))
            poc_budget = min(cfg.d_poc_seconds, remaining_budget)

            if poc_budget < 0.5:
                logger.warning(
                    "Remaining match deadline budget (%.2fs) insufficient for PoC discovery; skipping.",
                    remaining_budget,
                )
                poc_degraded = True
            else:
                try:
                    from threat_retrieval_engine.poc_intelligence import get_poc_finder
                    import concurrent.futures
                    poc_finder = get_poc_finder()

                    def _fetch_one_cve(cve_id: str) -> tuple[str, list[PoCResultSchema]]:
                        resp = poc_finder.find_pocs_sync(cve_id, max_results=5, timeout=poc_budget)
                        return cve_id, resp.results

                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(target_cves), 3)) as pool:
                        futures = {pool.submit(_fetch_one_cve, cve): cve for cve in target_cves}
                        for future in concurrent.futures.as_completed(futures):
                            cve_target = futures[future]
                            try:
                                cve_res, results = future.result()
                                discovered_pocs[cve_res] = results
                            except Exception as cve_exc:
                                logger.warning("PoC lookup for %s failed or timed out: %s", cve_target, cve_exc)
                                poc_degraded = True
                except Exception as exc:
                    logger.warning("PoC discovery enrichment encountered error: %s", exc)
                    poc_degraded = True
        poc_discovery_ms = (time.perf_counter() - t_poc_start) * 1000

        for rank, cand in enumerate(top_candidates, start=1):
            attr_dict = extract_attribution(query_ent, cand["metadata"], cand["text"])
            citation_dict = build_citation(cand["chunk_id"], cand["metadata"], cand["text"])

            cand_pocs: list[PoCResultSchema] = []
            if include_pocs:
                for cve in attr_dict.get("matching_cves", []):
                    cand_pocs.extend(discovered_pocs.get(cve.upper(), []))
                if not cand_pocs and query_ent.cves:
                    for cve in query_ent.cves:
                        cand_pocs.extend(discovered_pocs.get(cve.upper(), []))

            # Deduplicate by URL
            seen_poc_urls = set()
            unique_cand_pocs = []
            for p in cand_pocs:
                if p.url not in seen_poc_urls:
                    seen_poc_urls.add(p.url)
                    unique_cand_pocs.append(p)

            top_matches.append(
                TopMatchSchema(
                    rank=rank,
                    chunk_id=cand["chunk_id"],
                    composite_score=cand["composite_score"],
                    confidence_tier=cand["confidence_tier"],
                    evidence_breakdown=cand["evidence_breakdown"],
                    attribution=AttributionSchema(**attr_dict),
                    stix_relationships=cand["stix_relationships"],
                    citations=[CitationSchema(**citation_dict)],
                    pocs=unique_cand_pocs,
                    match_type=cand.get("match_type"),
                    tier_basis=cand.get("tier_basis"),
                    calibrated=cand.get("calibrated", False),
                    degraded=cand.get("degraded", False),
                    model_version=cand.get("model_version"),
                    evidence_record_class=cand.get("evidence_record_class", "DESCRIPTION"),
                    sources_found=cand.get("sources_found", {}),
                    corroboration_count=cand.get("corroboration_count", 1),
                    cisa_kev=cand.get("cisa_kev", False),
                    epss_score=cand.get("epss_score"),
                )
            )

        citation_ms = (time.perf_counter() - t_cite_start) * 1000
        total_ms = (time.perf_counter() - t_total_start) * 1000

        # Deadline contract check (V2)
        deadline_exceeded = total_ms > (cfg.d_match_seconds * 1000.0)

        current_degraded = list(dict.fromkeys(self.degraded_components + (["poc_discovery"] if poc_degraded else [])))

        return MatchResponse(
            query_threat_id=query_threat_id,
            top_matches=top_matches,
            pipeline_profile=PipelineProfileSchema(
                exact_match_ms=round(exact_match_ms, 1),
                vector_database_ms=round(vector_database_ms, 1),
                knowledge_graph_ms=round(knowledge_graph_ms, 1),
                scoring_ms=round(scoring_ms, 1),
                citation_ms=round(citation_ms, 1),
                poc_discovery_ms=round(poc_discovery_ms, 1),
                total_ms=round(total_ms, 1),
            ),
            degraded_components=current_degraded,
            deadline_exceeded=deadline_exceeded,
        )


# Global singleton instance for FastAPI lifespan
_orchestrator = ThreatRetrieverEngine()


def get_orchestrator() -> ThreatRetrieverEngine:
    return _orchestrator
