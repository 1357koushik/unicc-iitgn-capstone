"""
threat_retrieval_engine.search_engine
=====================================
The core RAG indexing, search, and matching engine.
"""

from .validator import ThreatChunk, build_context
from .tokenizer import tokenize, extract_identifiers
from .duplicate_checker import DuplicateChecker
from .vectorizer import BGEVectorizer, VectorResult
from .vector_database import (
    COLLECTION_NAME,
    setup_databases,
    store_chunks,
    fetch_text,
    fetch_chunk_metadata,
)
from .bm25_index import BM25Index, build_from_sqlite
from .exact_lookup import exact_lookup, ExactMatch
from .hybrid_search import HybridSearcher, HybridResult
from .reranker import CrossEncoderReranker, RerankedResult
from .mitre_graph import MitreAttackGraph, AttackNode, AttackEdge
