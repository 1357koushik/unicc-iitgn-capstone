"""The v2 retrieval chain for one question (plan 4.1 steps 2-5), shared by the API (C6) and the benchmark adapter.

    1. identifiers: CVE IDs (primary key in the C1 store) and ATT&CK IDs (C9 gazetteer) -> EXACT, first
    2. named entities: ATT&CK group / software / technique names (C9 gazetteer) -> candidates
    3. nicknames (C4): every CVE of a matched name -> candidates
    4. free text: C2 lexical + C3 dense over CVE and ATT&CK documents, fused by weighted RRF (tuned on dev)
    5. rerank (C5): the int8 cross-encoder scores the first ``depth`` candidates (route candidates, then the
       fused list), and ``rerank_weight`` blends its order with the incoming order (``blend``); 0 turns the
       reranker off. Measured on dev and train with the benchmark answer keys, the reranker's order lowers
       macro nDCG@10 (dev 0.682 without it, 0.685 at weight 0.5, 0.642 alone; train 0.512 / 0.511 / 0.456),
       so the served default is 0 until judging round 1 settles it on judged labels
Every stage checks the deadline; a skipped stage is named in ``skipped``. Per-document signals (rerank logit,
fused / lexical / dense rank, dense cosine, route hits) are returned for the calibrated confidence (C7).
"""
from __future__ import annotations

import dataclasses
import math
import re
import time
from dataclasses import dataclass, field

from ..dense.fusion import RRFConfig, rrf
from ..store.text import normalize_cve_id

# CVE IDs as people type them: "CVE-2024-45593", "cve 2024-45593", "CVE_2024_45593", "CVE–2024–45593"
CVE_LOOSE = re.compile(r"(?<![A-Za-z0-9])CVE[\s_\-‐-―:]*(\d{4})[\s_\-‐-―:]+(\d{4,7})(?![0-9])",
                       re.IGNORECASE)
RERANK_DEPTH = 10
BLEND_K = 2.0
MAX_ROUTE_RERANK = 20      # a name naming many CVEs (FragAttacks: 12) is reranked whole, up to this many
CANDIDATES = 100
RERANK_BUDGET_S = 1.2      # rerank only when at least this much of the deadline is left


def blend(head: list, weight: float) -> list:
    """Order of the reranked head: each result scores 1/(K + its place in the list the reranker received) +
    weight/(K + its place by rerank logit), K = 2. weight inf is the reranker's order alone; 0 keeps the order."""
    if math.isinf(weight):
        return sorted(head, key=lambda h: -h.rerank_logit)
    rp = {id(h): i + 1 for i, h in enumerate(sorted(head, key=lambda h: -h.rerank_logit))}
    sc = {id(h): 1 / (BLEND_K + i + 1) + weight / (BLEND_K + rp[id(h)]) for i, h in enumerate(head)}
    pos = {id(h): i for i, h in enumerate(head)}
    return sorted(head, key=lambda h: (-sc[id(h)], pos[id(h)]))


@dataclass
class Hit:
    doc_id: str
    rank: int = 0
    route: str = "fused"            # exact_id | nickname | entity | fused
    rerank_logit: float | None = None
    fused_rank: int | None = None
    lexical_rank: int | None = None
    dense_rank: int | None = None
    dense_cosine: float | None = None
    matched: list[str] = field(default_factory=list)   # the names or IDs of the question that led here

    def features(self) -> dict:
        return {"rerank_logit": self.rerank_logit, "fused_rank": self.fused_rank, "lexical_rank": self.lexical_rank,
                "dense_rank": self.dense_rank, "dense_cosine": self.dense_cosine, "route": self.route}


@dataclass
class Retrieval:
    hits: list[Hit]
    cve_ids_in_query: list[str]
    cve_ids_not_in_corpus: list[str]
    nicknames: list[dict]
    entities: list[dict]
    skipped: list[str]
    timings_ms: dict[str, float]


class V2Retriever:
    def __init__(self, store, lexical, dense, rrf_cfg: RRFConfig, reranker=None, nicknames=None, attack_store=None,
                 texts=None, rerank_depth: int = RERANK_DEPTH, candidates: int = CANDIDATES,
                 rerank_weight: float = math.inf):
        self.store = store
        self.lexical = lexical
        self.dense = dense
        self.cfg = rrf_cfg
        self.reranker = reranker
        self.nick = nicknames
        self.attack = attack_store
        self.texts = texts
        self.rerank_depth = int(rerank_depth)
        self.rerank_weight = float(rerank_weight)
        self.candidates = int(candidates)
        self._gaz = attack_store.gazetteer() if attack_store is not None else None

    # ------------------------------------------------------------------ identifiers
    def _cve_ids(self, q: str) -> tuple[list[str], list[str]]:
        ids = list(dict.fromkeys(x for x in (normalize_cve_id(f"CVE-{m.group(1)}-{m.group(2)}")
                                             for m in CVE_LOOSE.finditer(q)) if x))
        if not ids:
            return [], []
        rows = dict(self.store._db.execute(
            f"SELECT cve_id, searchable FROM cve WHERE cve_id IN ({','.join('?' * len(ids))})", ids).fetchall())
        present = [i for i in ids if rows.get(i)]
        absent = [i for i in ids if not rows.get(i)]
        return present, absent

    def _entities(self, q: str):
        if self._gaz is None:
            return [], []
        exact, named = [], []
        for m in self._gaz.match(q, query=True):
            for c in m.candidates:
                b = self.attack.brief(c.doc_id)
                if not b or not b.get("searchable"):
                    continue
                rec = {"surface": m.text, "doc_id": c.doc_id, "doc_kind": c.doc_kind, "matched_by": m.matched_by}
                (exact if m.matched_by == "id" else named).append(rec)
        return exact, named

    # ------------------------------------------------------------------ main
    def retrieve(self, query: str, k: int = 100, deadline: float | None = None, rerank: bool = True) -> Retrieval:
        T = {}
        t0 = time.perf_counter()
        skipped: list[str] = []
        left = (lambda: deadline - time.perf_counter()) if deadline else (lambda: math.inf)

        present, absent = self._cve_ids(query)
        atk_exact, atk_named = self._entities(query)
        nick_hits = self.nick.match(query) if self.nick is not None else []
        T["routes"] = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        # The tuned depth, unless more results were asked for than it holds (results up to the depth are unchanged).
        depth = max(self.candidates, int(k))
        cfg = self.cfg if depth <= self.cfg.depth else dataclasses.replace(self.cfg, depth=depth)
        lex = self.lexical.search(query, k=depth, kinds=None)
        T["lexical"] = (time.perf_counter() - t1) * 1000
        den_hits: list[tuple[str, float]] = []
        if left() > 0.3:
            t2 = time.perf_counter()
            den = self.dense.search(query, k=depth, kinds=None)
            den_hits = den.hits
            T["dense_encode"] = den.timings_ms.get("encode", 0.0)
            T["dense_search"] = den.timings_ms.get("search", 0.0)
        else:
            skipped.append("dense")
        lex_ids = [d for d, _ in lex.hits]
        den_ids = [d for d, _ in den_hits]
        fused = rrf([lex_ids, den_ids], cfg, limit=depth) if den_ids else \
            [(d, 0.0) for d in lex_ids]
        lrank = {d: i + 1 for i, d in enumerate(lex_ids)}
        drank = {d: i + 1 for i, d in enumerate(den_ids)}
        dcos = dict(den_hits)
        frank = {d: i + 1 for i, (d, _) in enumerate(fused)}

        def mk(d, route, matched=()):
            return Hit(d, route=route, fused_rank=frank.get(d), lexical_rank=lrank.get(d), dense_rank=drank.get(d),
                       dense_cosine=dcos.get(d), matched=list(matched))

        exact: dict[str, Hit] = {}
        for c in present:
            exact[c] = mk(c, "exact_id", [c])
        for e in atk_exact:
            exact.setdefault(e["doc_id"], mk(e["doc_id"], "exact_id", [e["surface"]]))
        route: dict[str, Hit] = {}
        for h in nick_hits:
            for c in h.cves:
                if c not in exact:
                    route.setdefault(c, mk(c, "nickname")).matched.append(h.surface)
        for e in atk_named:
            if e["doc_id"] not in exact:
                route.setdefault(e["doc_id"], mk(e["doc_id"], "entity")).matched.append(e["surface"])
        rest = [mk(d, "fused") for d, _ in fused if d not in exact and d not in route]
        # route candidates in fused order (those the fused list does not hold last), then the fused list
        routed = sorted(route.values(), key=lambda h: h.fused_rank or 10**6)
        cands = routed + rest

        n = min(max(self.rerank_depth, min(len(route), MAX_ROUTE_RERANK)), len(cands))
        if not rerank:
            skipped.append("rerank")
        elif self.rerank_weight == 0:
            pass                                  # reranker off by configuration: not a skipped stage
        elif self.reranker is not None and self.texts is not None and n:
            if left() >= RERANK_BUDGET_S:
                t3 = time.perf_counter()
                head = cands[:n]
                rows = self.texts.rows([h.doc_id for h in head])
                logits, info = self.reranker.score(query, [self._rerank_text(h, rows) for h in head])
                for h, lg in zip(head, logits):
                    h.rerank_logit = lg
                cands = blend(head, self.rerank_weight) + cands[n:]
                T["rerank"] = (time.perf_counter() - t3) * 1000
            else:
                skipped.append("rerank")
        elif self.reranker is None:
            skipped.append("rerank")
        hits = list(exact.values()) + cands
        hits = hits[:k]
        for i, h in enumerate(hits, 1):
            h.rank = i
        T["total"] = (time.perf_counter() - t0) * 1000
        return Retrieval(hits, present, absent,
                         [{"surface": h.surface, "cves": list(h.cves), "sources": list(h.sources)} for h in nick_hits],
                         atk_exact + atk_named, skipped, T)

    @staticmethod
    def _rerank_text(h: Hit, rows: dict) -> str:
        """The document's text; a CVE reached by a name also shows that name as one of its aliases (the alias
        source, e.g. Wikidata, says the name belongs to this CVE; the store's own aliases are already in the
        text)."""
        text = rows.get(h.doc_id, {}).get("text", h.doc_id)
        if h.route == "nickname" and h.matched:
            names = [m for m in dict.fromkeys(h.matched) if m.lower() not in text.lower()]
            if names:
                cut = text.find(". ") if text.startswith("CVE-") else -1
                add = "Also known as: " + ", ".join(names)
                text = f"{text[:cut]}. {add}{text[cut:]}" if cut > 0 else f"{add}. {text}"
        return text

    def info(self) -> dict:
        return {"rrf": self.cfg.as_dict(), "rerank_depth": self.rerank_depth, "rerank_weight": self.rerank_weight, "candidates": self.candidates,
                "lexical": self.lexical.info(), "dense": self.dense.info(),
                "reranker": self.reranker.info() if self.reranker is not None else None,
                "nicknames": self.nick.info() if self.nick is not None else None}
