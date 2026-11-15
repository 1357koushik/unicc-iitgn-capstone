"""C2 lexical index: SQLite FTS5 over the C1 store with per-column BM25 weights, pre-tokenized by the
shared domain tokenizer (threat_retrieval_engine.text).

Build:  python -m threat_retrieval_engine.lexical.build [--store <C1 build>] [--out data/lexical]
Check:  python -m threat_retrieval_engine.lexical.check_c2
Read:   from threat_retrieval_engine.lexical import LexicalIndex

Plan reference: docs/RETRIEVAL_V2_PLAN.md 4.5 (lexical), 4.9 (latency), 12 (C2 entry with the measurements).
"""
from .config import RANKING, TOKENIZER, RankingConfig
from .index import LexicalIndex, Query, SearchResult, resolve_build
from .schema import COLUMNS, LEXICAL_FORMAT

__all__ = ["COLUMNS", "LEXICAL_FORMAT", "RANKING", "TOKENIZER", "LexicalIndex", "Query", "RankingConfig",
           "SearchResult", "resolve_build"]
