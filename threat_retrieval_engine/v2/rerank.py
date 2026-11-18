"""C5: the large cross-encoder (BAAI/bge-reranker-v2-m3), quantized to int8, applied to the top of the fused list.

    from threat_retrieval_engine.v2.rerank import Int8Reranker
    rr = Int8Reranker.load()                          # Hugging Face cache, offline
    logits = rr.score("eternalblue patch status", ["CVE-2017-0144. Microsoft SMBv1 ...", ...])

Serving choice (plan 4.6, decided by the owner): no fine-tuning and no distilled model; the large reranker is
quantized with PyTorch dynamic int8 quantization (every ``nn.Linear`` weight stored as int8, activations
quantized per batch) and scores only the first ``depth`` candidates of the fused list (cascade). Ranking uses
raw logits (plan 4.6 item 5), never a squashed score. Inputs: whitespace collapsed, the query cut to
``QUERY_MAX_TOKENS`` first, the pair cut to ``PAIR_MAX_TOKENS`` (document side truncated), pairs sorted by
length and scored in one padded batch.
"""
from __future__ import annotations

import os
import re
import threading
import time

MODEL_REPO = "BAAI/bge-reranker-v2-m3"
PAIR_MAX_TOKENS = 256
QUERY_MAX_TOKENS = 96
DEFAULT_DEPTH = 10
_WS = re.compile(r"\s+")


def clean(text: str) -> str:
    return _WS.sub(" ", text or "").strip()


class Int8Reranker:
    def __init__(self, model, tokenizer, threads: int | None = None, quantized: bool = True, source: str = ""):
        self.model = model
        self.tok = tokenizer
        self.threads = threads
        self.quantized = quantized
        self.source = source
        self._lock = threading.Lock()  # torch intra-op threads are shared; one batch at a time

    @classmethod
    def load(cls, repo: str | None = None, threads: int | None = None, quantize: bool = True) -> "Int8Reranker":
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        repo = repo or os.environ.get("TRE_RERANKER_MODEL", MODEL_REPO)
        if threads is None and os.environ.get("TRE_RERANK_THREADS"):
            threads = int(os.environ["TRE_RERANK_THREADS"])
        if threads:
            torch.set_num_threads(int(threads))
        tok = AutoTokenizer.from_pretrained(repo)
        model = AutoModelForSequenceClassification.from_pretrained(repo, torch_dtype=torch.float32).eval()
        if quantize:
            model = torch.ao.quantization.quantize_dynamic(model, {torch.nn.Linear}, dtype=torch.qint8)
        return cls(model, tok, threads=threads, quantized=quantize, source=repo)

    def _cut_query(self, q: str) -> str:
        ids = self.tok(q, add_special_tokens=False, truncation=True, max_length=QUERY_MAX_TOKENS)["input_ids"]
        return self.tok.decode(ids)

    def score(self, query: str, texts: list[str]) -> tuple[list[float], dict]:
        """Raw relevance logits, one per text, in the order given; plus timings."""
        import torch
        if not texts:
            return [], {"pairs": 0, "ms": 0.0}
        t0 = time.perf_counter()
        q = self._cut_query(clean(query))
        docs = [clean(t) for t in texts]
        order = sorted(range(len(docs)), key=lambda i: len(docs[i]))
        enc = self.tok([q] * len(docs), [docs[i] for i in order], padding=True, truncation="only_second",
                       max_length=PAIR_MAX_TOKENS, return_tensors="pt")
        with self._lock, torch.inference_mode():
            out = self.model(**enc).logits.view(-1).float().tolist()
        logits = [0.0] * len(docs)
        for pos, i in enumerate(order):
            logits[i] = float(out[pos])
        return logits, {"pairs": len(docs), "tokens_max": int(enc["input_ids"].shape[1]),
                        "ms": (time.perf_counter() - t0) * 1000}

    def info(self) -> dict:
        return {"model": self.source, "quantization": "torch dynamic int8 (nn.Linear)" if self.quantized else "none",
                "pair_max_tokens": PAIR_MAX_TOKENS, "query_max_tokens": QUERY_MAX_TOKENS, "threads": self.threads}
