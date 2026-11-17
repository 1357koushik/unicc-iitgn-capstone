"""Text encoders: one interface for every compared model, each in its documented format (``models.py``).

    from threat_retrieval_engine.dense.encoder import Encoder
    enc = Encoder.load("bge-m3", threads=16)
    q = enc.encode_queries(["log4j jndi lookup remote code execution"])      # (1, 1024) float32, unit norm
    d = enc.encode_documents(texts)                                          # (n, 1024)

Input handling, identical for queries and documents:

1. Whitespace runs are collapsed to one space and the ends stripped (every compared tokenizer splits on
   whitespace, so the tokens are unchanged; this only bounds the work below).
2. At most ``CHARS_PER_TOKEN * max_tokens`` characters are tokenized (bounded work for hostile input; a text
   that long always exceeds ``max_tokens`` tokens for real prose, and the build verifies that the cut never
   changes the tokens of a corpus document).
3. The model's prefix is prepended (``query: ``, the bge-en instruction, ...), and the text is tokenized with
   truncation at ``max_tokens`` tokens including special tokens and prefix (plan 4.5: 256).

Batches are formed from inputs sorted by token length (longest first, ties by input position), each batch at
most ``batch_size`` inputs and ``batch_tokens`` padded tokens; the order of the returned vectors is the input
order. Pooling and L2 normalisation follow the model card. Weights load in float32 (the checkpoints of some
models are stored in float16; computing in float32 avoids double rounding) and are checked against the
pinned sha256 before use.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np

from . import models as M

CHARS_PER_TOKEN = 64
_WS = re.compile(r"\s+")
_SHA_CACHE: dict[tuple[str, int, int], str] = {}


class EncoderError(RuntimeError):
    pass


def normalize_text(text: str, max_tokens: int) -> str:
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    t = _WS.sub(" ", text).strip()
    return t[: CHARS_PER_TOKEN * max_tokens]


def sha256_file(path: Path) -> str:
    st = path.stat()
    key = (str(path), st.st_size, st.st_mtime_ns)
    if key not in _SHA_CACHE:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 22), b""):
                h.update(chunk)
        _SHA_CACHE[key] = h.hexdigest()
    return _SHA_CACHE[key]


def set_torch_threads(threads: int | None) -> int:
    import torch
    if threads:
        torch.set_num_threads(int(threads))
    return torch.get_num_threads()


class Encoder:
    def __init__(self, spec: M.ModelSpec, model_path: Path, device: str = "cpu", threads: int | None = None,
                 verify_weights: bool = True, batch_size: int = 32, batch_tokens: int = 8192):
        import torch
        from transformers import AutoModel, AutoTokenizer
        self.spec = spec
        self.path = Path(model_path)
        self.device = device
        self.batch_size = int(batch_size)
        self.batch_tokens = int(batch_tokens)
        t0 = time.perf_counter()
        wfile = self.path / spec.weights_file
        self.weights_sha256 = sha256_file(wfile) if verify_weights else None
        if verify_weights and spec.weights_sha256 and self.weights_sha256 != spec.weights_sha256:
            raise EncoderError(f"{wfile}: sha256 {self.weights_sha256} differs from the pinned {spec.weights_sha256}")
        self.threads = set_torch_threads(threads) if device == "cpu" else None
        self.tokenizer = AutoTokenizer.from_pretrained(str(self.path), local_files_only=True)
        if not getattr(self.tokenizer, "is_fast", False):
            raise EncoderError(f"{spec.name}: a fast tokenizer is required")
        kw = {"local_files_only": True}
        try:
            self.model = AutoModel.from_pretrained(str(self.path), dtype=torch.float32, **kw)
        except TypeError:  # transformers < 4.56 names it torch_dtype
            self.model = AutoModel.from_pretrained(str(self.path), torch_dtype=torch.float32, **kw)
        self.model.eval()
        self.model.to(device)
        for p in self.model.parameters():
            if p.dtype != torch.float32:
                raise EncoderError(f"{spec.name}: parameter in {p.dtype}, expected float32")
        self.load_seconds = time.perf_counter() - t0
        self._lock = threading.Lock()
        self.stats = {"at_cap": 0, "encoded": 0}

    @classmethod
    def load(cls, name: str, model_root: str | None = None, **kw) -> "Encoder":
        spec = M.get(name)
        return cls(spec, M.model_dir(spec, model_root), **kw)

    # ------------------------------------------------------------------ formatting
    def format(self, texts: Iterable[str], kind: str, max_tokens: int) -> list[str]:
        if kind not in ("query", "passage"):
            raise ValueError("kind must be 'query' or 'passage'")
        prefix = self.spec.query_prefix if kind == "query" else self.spec.passage_prefix
        return [prefix + normalize_text(t, max_tokens) for t in texts]

    def tokenize(self, texts: Sequence[str], kind: str, max_tokens: int) -> list[list[int]]:
        if not 4 <= max_tokens <= self.spec.max_position_tokens:
            raise ValueError(f"max_tokens must be in [4, {self.spec.max_position_tokens}]")
        enc = self.tokenizer(self.format(texts, kind, max_tokens), truncation=True, max_length=max_tokens,
                             padding=False, return_attention_mask=False, return_token_type_ids=False)
        return enc["input_ids"]

    def untruncated_lengths(self, texts: Sequence[str], kind: str, max_tokens: int) -> list[int]:
        """Token counts without the cap (for reporting how many inputs the cap shortens)."""
        enc = self.tokenizer(self.format(texts, kind, max_tokens), truncation=False, padding=False,
                             return_attention_mask=False, return_token_type_ids=False, verbose=False)
        return [len(x) for x in enc["input_ids"]]

    # ------------------------------------------------------------------ encoding
    def batches(self, lengths: Sequence[int]) -> list[list[int]]:
        """Deterministic batches of input positions: longest first (ties by position), bounded by batch_size
        and batch_tokens (padded)."""
        order = sorted(range(len(lengths)), key=lambda i: (-lengths[i], i))
        out, cur, cur_max = [], [], 0
        for i in order:
            m = max(cur_max, lengths[i])
            if cur and (len(cur) + 1 > self.batch_size or m * (len(cur) + 1) > self.batch_tokens):
                out.append(cur)
                cur, m = [], lengths[i]
            cur.append(i)
            cur_max = m
        if cur:
            out.append(cur)
        return out

    def encode_ids(self, ids: list[list[int]]) -> np.ndarray:
        import torch
        n = len(ids)
        out = np.zeros((n, self.spec.dim), dtype=np.float32)
        if n == 0:
            return out
        pad = self.tokenizer.pad_token_id
        with self._lock, torch.inference_mode():
            for b in self.batches([len(x) for x in ids]):
                L = max(len(ids[i]) for i in b)
                inp = torch.full((len(b), L), pad, dtype=torch.long)
                att = torch.zeros((len(b), L), dtype=torch.long)
                for r, i in enumerate(b):
                    inp[r, : len(ids[i])] = torch.tensor(ids[i], dtype=torch.long)
                    att[r, : len(ids[i])] = 1
                inp, att = inp.to(self.device), att.to(self.device)
                hidden = self.model(input_ids=inp, attention_mask=att).last_hidden_state
                if self.spec.pooling == "cls":
                    v = hidden[:, 0]
                elif self.spec.pooling == "mean":
                    m = att.unsqueeze(-1).to(hidden.dtype)
                    v = (hidden * m).sum(dim=1) / m.sum(dim=1).clamp(min=1.0)
                else:
                    raise EncoderError(f"unknown pooling {self.spec.pooling}")
                v = torch.nn.functional.normalize(v.float(), p=2, dim=-1)
                out[b] = v.cpu().numpy()
        self.stats["encoded"] += n
        return out

    def encode(self, texts: Sequence[str], kind: str, max_tokens: int) -> np.ndarray:
        texts = list(texts)
        ids = self.tokenize(texts, kind, max_tokens)
        self.stats["at_cap"] += sum(1 for x in ids if len(x) >= max_tokens)
        return self.encode_ids(ids)

    def encode_queries(self, texts: Sequence[str], max_tokens: int = M.QUERY_MAX_TOKENS) -> np.ndarray:
        return self.encode(texts, "query", max_tokens)

    def encode_documents(self, texts: Sequence[str], max_tokens: int = M.DOCUMENT_MAX_TOKENS) -> np.ndarray:
        return self.encode(texts, "passage", max_tokens)

    def info(self) -> dict:
        import torch
        import transformers
        return {"model": self.spec.as_dict(), "path": str(self.path), "weights_sha256": self.weights_sha256,
                "device": self.device, "torch_threads": self.threads, "batch_size": self.batch_size,
                "batch_tokens": self.batch_tokens, "torch": torch.__version__,
                "transformers": transformers.__version__, "load_seconds": round(self.load_seconds, 2),
                "tokenizer": type(self.tokenizer).__name__}


def config_key(spec: M.ModelSpec, max_tokens: int) -> str:
    """Identity of an encoding configuration (cache keys, manifests)."""
    return hashlib.sha256(json.dumps({"repo": spec.repo, "revision": spec.revision, "pooling": spec.pooling,
                                      "q": spec.query_prefix, "p": spec.passage_prefix, "max_tokens": max_tokens,
                                      "chars_per_token": CHARS_PER_TOKEN}, sort_keys=True).encode()).hexdigest()[:16]


def env_threads() -> int | None:
    v = os.environ.get("TRE_TORCH_THREADS")
    return int(v) if v else None
