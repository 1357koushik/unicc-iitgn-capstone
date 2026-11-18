"""ATT&CK technique ranking: which techniques does a piece of text describe?

The mixed CVE + ATT&CK search cannot answer this: for a CVE description or a report sentence the 100 fused
candidates are almost all CVEs. This route searches technique evidence only.

Knowledge base (C9 build, no CVE links): for every searchable technique, one entry "name. description" and one entry
per procedure example (the description of each `uses` relationship that ends at the technique, e.g. "APT29 used
Mimikatz to dump credentials from LSASS memory."). Lists, each scored per entry and reduced to the best entry per
technique:
    keyword  BM25 over the entries (project tokenizer)
    dense    one list per configured sentence encoder (cosine, normalised embeddings precomputed at build time)
The lists are fused by reciprocal rank (k = 60, equal weights) and the first ``depth`` techniques are reordered by a
cross-encoder when one is configured and the deadline allows.

Build: ``python scripts/v2/build_techniques.py`` writes entries.jsonl, emb_<encoder>.npy and manifest.json.
"""
from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from ..text.tokenizer import tokenize

RRF_K = 60.0
DEFAULT_ENCODERS = ("bge-large", "qwen3-emb")   # with the keyword list; chosen on dev (docs/EXTERNAL_BENCHMARKS.md)
DEFAULT_RERANKER = "none"
RERANK_DEPTH = 20
RERANK_CHARS = 1200
ENTRY_CHARS = 2000
INSTRUCTION = "Given a cyber threat intelligence text, retrieve the MITRE ATT&CK technique it describes"

_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CODE = re.compile(r"</?code>")


def clean(text: str | None) -> str:
    t = _CITATION.sub("", text or "")
    t = _MDLINK.sub(r"\1", t)
    t = _CODE.sub("", t)
    return re.sub(r"\s+", " ", t).strip()


# ---------------------------------------------------------------------------------------------------------- KB
@dataclass
class Entry:
    doc_id: str          # attack:T1003.001
    kind: str            # description | procedure
    text: str


def kb_entries(attack_store) -> list[Entry]:
    """Entries sorted by technique, descriptions first. Deterministic for one C9 build."""
    db = attack_store._db
    techs = db.execute("SELECT doc_id, attack_id, title, description FROM objects "
                       "WHERE doc_kind = 'technique' AND searchable = 1 ORDER BY doc_id").fetchall()
    out: list[Entry] = []
    procs: dict[str, list[str]] = {}
    for dst, desc in db.execute(
            "SELECT e.dst_doc_id, e.description FROM edges e JOIN objects o ON o.doc_id = e.dst_doc_id "
            "WHERE e.rel_type = 'uses' AND o.doc_kind = 'technique' AND o.searchable = 1 "
            "ORDER BY e.dst_doc_id, e.rel_stix_id"):
        t = clean(desc)
        if len(t) > 20:
            procs.setdefault(dst, []).append(t[:ENTRY_CHARS])
    for doc_id, _aid, title, desc in techs:
        out.append(Entry(doc_id, "description", f"{title}. {clean(desc)}"[:ENTRY_CHARS]))
        for t in dict.fromkeys(procs.get(doc_id, [])):
            out.append(Entry(doc_id, "procedure", t))
    return out


# ---------------------------------------------------------------------------------------------------------- lists
class _Reducer:
    """Maps entry scores to the best entry per technique."""

    def __init__(self, doc_ids: list[str]):
        self.techs = list(dict.fromkeys(doc_ids))
        idx = {d: i for i, d in enumerate(self.techs)}
        tid = np.array([idx[d] for d in doc_ids])
        if np.any(np.diff(tid) < 0):
            raise ValueError("entries must be grouped by technique")
        self.starts = np.flatnonzero(np.r_[True, np.diff(tid) != 0])

    def best(self, scores: np.ndarray) -> np.ndarray:
        return np.maximum.reduceat(scores, self.starts)


class BM25:
    def __init__(self, texts: list[str], k1: float = 1.2, b: float = 0.75):
        self.k1, self.b = k1, b
        docs = [tokenize(t) for t in texts]
        self.n = len(docs)
        self.dl = np.array([len(d) for d in docs], dtype=np.float32)
        self.avgdl = float(self.dl.mean()) if self.n else 1.0
        post: dict[str, dict[int, int]] = {}
        for i, d in enumerate(docs):
            for tok in d:
                p = post.setdefault(tok, {})
                p[i] = p.get(i, 0) + 1
        self.post = {t: (np.fromiter(p.keys(), np.int32, len(p)), np.fromiter(p.values(), np.float32, len(p)))
                     for t, p in post.items()}
        self.norm = self.k1 * (1 - self.b + self.b * self.dl / self.avgdl)

    def scores(self, text: str) -> np.ndarray:
        s = np.zeros(self.n, dtype=np.float32)
        for tok in set(tokenize(text)):
            if tok not in self.post:
                continue
            ids, tf = self.post[tok]
            idf = math.log(1 + (self.n - len(ids) + 0.5) / (len(ids) + 0.5))
            s[ids] += idf * tf * (self.k1 + 1) / (tf + self.norm[ids])
        return s


# ---------------------------------------------------------------------------------------------------------- encoders
ENCODERS = {
    # name: (default model dir under TRE_TECH_MODELS_DIR, query prefix, query prompt)
    "bge-large": ("bge-large-en-v1.5", "Represent this sentence for searching relevant passages: ", None),
    "sentsecbert": ("SentSecBert_10k", "", None),
    "securebert2": ("SecureBERT2.0-biencoder", "", None),
    "qwen3-emb": ("Qwen3-Embedding-0.6B", "", f"Instruct: {INSTRUCTION}\nQuery: "),
}


def models_dir() -> Path:
    d = os.environ.get("TRE_TECH_MODELS_DIR") or os.environ.get("TRE_MODEL_DIR") or "~/team2/models"
    return Path(os.path.expanduser(d))


class Encoder:
    def __init__(self, name: str, path: str | Path | None = None, threads: int | None = None):
        from sentence_transformers import SentenceTransformer
        import torch
        if threads:
            torch.set_num_threads(threads)
        sub, self.prefix, self.prompt = ENCODERS[name]
        self.name = name
        self.path = str(path or models_dir() / sub)
        self.model = SentenceTransformer(self.path, device="cpu", model_kwargs={"dtype": torch.float32})
        self.model.max_seq_length = min(self.model.max_seq_length or 512, 512)

    def docs(self, texts: list[str], batch: int = 32) -> np.ndarray:
        return self.model.encode(texts, batch_size=batch, normalize_embeddings=True, convert_to_numpy=True,
                                 show_progress_bar=False).astype(np.float32)

    def query(self, text: str) -> np.ndarray:
        kw = {"prompt": self.prompt} if self.prompt else {}
        return self.model.encode([self.prefix + text], normalize_embeddings=True, convert_to_numpy=True,
                                 show_progress_bar=False, **kw)[0].astype(np.float32)


# ---------------------------------------------------------------------------------------------------------- rerankers
class Reranker:
    name = "none"

    def score(self, query: str, docs: list[str]) -> list[float]:
        raise NotImplementedError


class CrossEncoderReranker(Reranker):
    """sentence-transformers CrossEncoder (SecureBERT 2.0 cross-encoder)."""

    def __init__(self, path: str, name: str = "securebert2-ce"):
        from sentence_transformers import CrossEncoder
        self.name = name
        self.model = CrossEncoder(path, device="cpu", max_length=512)

    def score(self, query, docs):
        return [float(x) for x in self.model.predict([(query, d) for d in docs], batch_size=32,
                                                     show_progress_bar=False)]


class MonoT5Reranker(Reranker):
    """monoT5: P("true") for "Query: q Document: d Relevant:"."""

    def __init__(self, path: str, name: str = "monot5"):
        import torch
        from transformers import AutoTokenizer, T5ForConditionalGeneration
        self.torch, self.name = torch, name
        self.tok = AutoTokenizer.from_pretrained(path)
        self.model = T5ForConditionalGeneration.from_pretrained(path).eval()
        self.t_true = self.tok.encode("true", add_special_tokens=False)[0]
        self.t_false = self.tok.encode("false", add_special_tokens=False)[0]

    def score(self, query, docs):
        torch = self.torch
        enc = self.tok([f"Query: {query} Document: {d} Relevant:" for d in docs], padding=True, truncation=True,
                       max_length=512, return_tensors="pt")
        start = torch.full((len(docs), 1), self.model.config.decoder_start_token_id, dtype=torch.long)
        with torch.inference_mode():
            logits = self.model(**enc, decoder_input_ids=start).logits[:, 0, [self.t_false, self.t_true]]
        return torch.log_softmax(logits, dim=-1)[:, 1].tolist()


class Qwen3Reranker(Reranker):
    """Qwen3-Reranker: P("yes") after the model card's judge prompt."""

    PREFIX = ("<|im_start|>system\nJudge whether the Document meets the requirements based on the Query and the "
              "Instruct provided. Note that the answer can only be \"yes\" or \"no\".<|im_end|>\n<|im_start|>user\n")
    SUFFIX = "<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"

    def __init__(self, path: str, name: str = "qwen3-rerank"):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch, self.name = torch, name
        self.tok = AutoTokenizer.from_pretrained(path, padding_side="left")
        self.model = AutoModelForCausalLM.from_pretrained(path, torch_dtype=torch.float32).eval()
        self.t_yes = self.tok.convert_tokens_to_ids("yes")
        self.t_no = self.tok.convert_tokens_to_ids("no")

    def score(self, query, docs):
        torch = self.torch
        texts = [f"{self.PREFIX}<Instruct>: {INSTRUCTION}\n<Query>: {query}\n<Document>: {d}{self.SUFFIX}"
                 for d in docs]
        enc = self.tok(texts, padding=True, truncation=True, max_length=640, return_tensors="pt")
        with torch.inference_mode():
            logits = self.model(**enc).logits[:, -1, [self.t_no, self.t_yes]]
        return torch.log_softmax(logits, dim=-1)[:, 1].tolist()


class BgeInt8Reranker(Reranker):
    """The served int8 bge-reranker-v2-m3 (C5)."""

    def __init__(self, threads: int | None = None, name: str = "bge-rerank-int8"):
        from .rerank import Int8Reranker
        self.name = name
        self.model = Int8Reranker.load(threads=threads)

    def score(self, query, docs):
        return list(self.model.score(query, docs)[0])


RERANKERS = {
    "monot5": ("monot5_AllDataSplit", MonoT5Reranker),
    "securebert2-ce": ("SecureBERT2.0-cross_encoder", CrossEncoderReranker),
    "qwen3-rerank": ("Qwen3-Reranker-0.6B", Qwen3Reranker),
}


def load_reranker(name: str | None, threads: int | None = None) -> Reranker | None:
    if not name or name == "none":
        return None
    if name == "bge-rerank-int8":
        return BgeInt8Reranker(threads=threads)
    sub, cls = RERANKERS[name]
    return cls(str(models_dir() / sub), name=name)


# ---------------------------------------------------------------------------------------------------------- ranker
@dataclass
class TechniqueHit:
    doc_id: str
    rank: int
    fused_rank: int
    list_ranks: dict = field(default_factory=dict)
    rerank_score: float | None = None
    evidence: str = ""          # the best-matching entry (description or procedure example)


class TechniqueRanker:
    def __init__(self, build_dir: str | Path, attack_store, encoders: list[str], reranker: str | None = None,
                 threads: int | None = None, depth: int = RERANK_DEPTH):
        self.dir = Path(build_dir)
        self.manifest = json.loads((self.dir / "manifest.json").read_text(encoding="utf-8"))
        rows = [json.loads(l) for l in open(self.dir / "entries.jsonl", encoding="utf-8")]
        self.entries = [Entry(r["doc_id"], r["kind"], r["text"]) for r in rows]
        self.red = _Reducer([e.doc_id for e in self.entries])
        self.techs = self.red.techs
        self.bm25 = BM25([e.text for e in self.entries])
        self.enc, self.emb = {}, {}
        for name in encoders:
            self.enc[name] = Encoder(name, threads=threads)
            self.emb[name] = np.load(self.dir / f"emb_{name}.npy")
            if self.emb[name].shape[0] != len(self.entries):
                raise ValueError(f"emb_{name}.npy does not match entries.jsonl")
        self.reranker = load_reranker(reranker, threads=threads)
        self.depth = depth
        self.attack = attack_store
        self._doc_text: dict[str, str] = {}
        for e in self.entries:
            if e.kind == "description":
                self._doc_text[e.doc_id] = e.text[:RERANK_CHARS]

    def info(self) -> dict:
        return {"build": self.manifest.get("build_id"), "entries": len(self.entries), "techniques": len(self.techs),
                "encoders": list(self.enc), "reranker": self.reranker.name if self.reranker else None,
                "depth": self.depth}

    def _list(self, entry_scores: np.ndarray):
        best = self.red.best(entry_scores)
        order = np.argsort(-best, kind="stable")
        return order, best

    def _evidence(self, doc_i: int, entry_scores: np.ndarray) -> str:
        lo = self.red.starts[doc_i]
        hi = self.red.starts[doc_i + 1] if doc_i + 1 < len(self.red.starts) else len(self.entries)
        j = lo + int(np.argmax(entry_scores[lo:hi]))
        return self.entries[j].text

    def rank(self, text: str, k: int = 10, deadline: float | None = None, rerank: bool = True) -> tuple[list, dict]:
        T: dict[str, float] = {}
        t0 = time.perf_counter()
        lists: dict[str, np.ndarray] = {}
        bm = self.bm25.scores(text)
        lists["keyword"] = bm
        T["keyword"] = (time.perf_counter() - t0) * 1000
        for name, enc in self.enc.items():
            t1 = time.perf_counter()
            lists[name] = self.emb[name] @ enc.query(text)
            T[name] = (time.perf_counter() - t1) * 1000
        fused = np.zeros(len(self.techs))
        ranks: dict[str, np.ndarray] = {}
        for name, s in lists.items():
            order, best = self._list(s)
            r = np.empty(len(order), dtype=np.int64)
            r[order] = np.arange(1, len(order) + 1)
            if name == "keyword":
                r[best <= 0] = 10**6                      # no shared term: not in this list
            ranks[name] = r
            fused += np.where(r < 10**6, 1.0 / (RRF_K + r), 0.0)
        order = list(np.argsort(-fused, kind="stable"))
        evid_src = lists[next(iter(self.enc))] if self.enc else bm
        hits = [TechniqueHit(self.techs[i], 0, n + 1, {nm: int(ranks[nm][i]) for nm in ranks},
                             evidence=self._evidence(i, evid_src))
                for n, i in enumerate(order[:max(k, self.depth)])]
        skipped = []
        if self.reranker is not None and rerank:
            if deadline is None or deadline - time.perf_counter() > 0.8:
                t2 = time.perf_counter()
                head = hits[:self.depth]
                sc = self.reranker.score(text, [self._doc_text.get(h.doc_id, h.doc_id) for h in head])
                for h, s in zip(head, sc):
                    h.rerank_score = float(s)
                hits = sorted(head, key=lambda h: -h.rerank_score) + hits[self.depth:]
                T["rerank"] = (time.perf_counter() - t2) * 1000
            else:
                skipped.append("technique_rerank")
        hits = hits[:k]
        for i, h in enumerate(hits, 1):
            h.rank = i
        T["total"] = (time.perf_counter() - t0) * 1000
        return hits, {"timings_ms": T, "skipped": skipped}
