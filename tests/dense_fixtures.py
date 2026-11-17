"""Fixtures for the C3 dense tests: a tiny randomly initialised BERT with a WordPiece vocabulary, saved like a
Hugging Face model directory and registered as embedding model ``tiny-test`` (no download, runs in CI), and
helpers for document sets and builds."""
from __future__ import annotations

import hashlib
import random
from pathlib import Path

import numpy as np

from threat_retrieval_engine.dense import models as M

WORDS = ("remote code execution buffer overflow cross site scripting sql injection denial service privilege "
         "escalation authentication bypass memory corruption path traversal deserialization arbitrary file upload "
         "crafted request attacker allows vulnerability plugin server kernel driver firmware router apache nginx "
         "openssl windows linux android chrome firefox wordpress group malware technique phishing").split()


def make_tiny_model(root: Path, pooling: str = "mean", name: str = "tiny-test", query_prefix: str = "query: ",
                    passage_prefix: str = "passage: ") -> M.ModelSpec:
    import torch
    from transformers import BertConfig, BertModel, BertTokenizerFast
    d = Path(root) / name
    d.mkdir(parents=True, exist_ok=True)
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]", ":", ".", ",", "-", "query", "passage"] + sorted(set(WORDS))
    vocab += [f"##{c}" for c in "abcdefghijklmnopqrstuvwxyz0123456789"] + list("abcdefghijklmnopqrstuvwxyz0123456789")
    (d / "vocab.txt").write_text("\n".join(dict.fromkeys(vocab)) + "\n", encoding="utf-8")
    tok = BertTokenizerFast(vocab_file=str(d / "vocab.txt"), do_lower_case=True)
    tok.save_pretrained(str(d))
    torch.manual_seed(0)
    cfg = BertConfig(vocab_size=len(dict.fromkeys(vocab)), hidden_size=32, num_hidden_layers=2, num_attention_heads=2,
                     intermediate_size=64, max_position_embeddings=512)
    BertModel(cfg).save_pretrained(str(d), safe_serialization=True)
    sha = hashlib.sha256((d / "model.safetensors").read_bytes()).hexdigest()
    spec = M.ModelSpec(name=name, repo=f"test/{name}", revision="0" * 40, dim=32, pooling=pooling,
                       query_prefix=query_prefix, passage_prefix=passage_prefix, weights_sha256=sha,
                       max_position_tokens=512, licence="test")
    M.MODELS[name] = spec
    return spec


def random_text(rnd: random.Random, lo: int = 4, hi: int = 60) -> str:
    return " ".join(rnd.choice(WORDS) for _ in range(rnd.randint(lo, hi)))


def document_set(n_cve: int = 120, n_attack: int = 15, seed: int = 1):
    from threat_retrieval_engine.dense.sources import DocumentSet
    rnd = random.Random(seed)
    ids = [f"CVE-2020-{1000 + i}" for i in range(n_cve)] + [f"attack:T{1000 + i}" for i in range(n_attack)]
    kinds = ["cve"] * n_cve + ["attack"] * n_attack
    texts = [random_text(rnd) for _ in ids]
    texts[3] = "  remote   code\texecution \n in apache  "          # whitespace runs
    texts[4] = "overflow " * 400                                     # far beyond the token cap
    hashes = [hashlib.sha256(t.encode()).hexdigest() for t in texts]
    return DocumentSet(ids, kinds, texts, hashes, {"fixture": True}, {"rule": "fixture"})


def random_unit(n: int, dim: int, seed: int = 0) -> np.ndarray:
    v = np.random.default_rng(seed).standard_normal((n, dim)).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True)
    return v
