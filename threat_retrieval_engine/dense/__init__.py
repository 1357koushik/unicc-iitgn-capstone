"""C3 dense retrieval: exact search over a float32 matrix held in RAM, and the embedding-model comparison.

Documents:  python -m threat_retrieval_engine.dense.build documents --out all.jsonl      (PC, from C1 + C9)
Encode:     scripts/dense/encode_server.sh all.jsonl <work> bge-m3                     (server, resumable)
Assemble:   python -m threat_retrieval_engine.dense.build assemble --documents all.jsonl --work <work>/bge-m3
v1 export:  python -m threat_retrieval_engine.dense.export_v1 rows|build ...
Check:      python -m threat_retrieval_engine.dense.check_c3
Read:       from threat_retrieval_engine.dense import DenseIndex, DenseRetriever, rrf

Plan reference: docs/RETRIEVAL_V2_PLAN.md 4.5 (dense, embedding model, fusion), 4.9 (latency), 8.1 (compute),
12 (C3 entry with the measurements and decisions).

Importing this package does not import torch; the encoder loads it when a model is opened.
"""
from .fusion import FusedRetriever, RRFConfig, rrf
from .index import DenseIndex, DenseIndexError, resolve_build, top_k
from .models import COMPARED, MODELS, ModelSpec
from .retriever import DenseResult, DenseRetriever
from .schema import DENSE_FORMAT, KINDS

__all__ = ["COMPARED", "DENSE_FORMAT", "KINDS", "MODELS", "DenseIndex", "DenseIndexError", "DenseResult",
           "DenseRetriever", "FusedRetriever", "ModelSpec", "RRFConfig", "resolve_build", "rrf", "top_k"]
