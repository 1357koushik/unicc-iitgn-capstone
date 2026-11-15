"""Tuned settings of the lexical retriever.

The values below were fitted on the benchmark's train split and selected on dev (never on the sealed test);
the measurements are in the C2 entry of docs/RETRIEVAL_V2_PLAN.md section 12 and in
``results/lexical/``. A build records them in its manifest; ``LexicalIndex`` uses the manifest's values
unless a caller passes an explicit ``RankingConfig`` (tuning and ablations only).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace

from ..text.tokenizer import TokenizerConfig
from .schema import COLUMNS

# Index-time tokenizer settings (changing them needs a rebuild).
TOKENIZER = TokenizerConfig(split_compounds=True, trailing_digits=True, stemmer="porter2")

STOP_MODES = ("none", "english")


@dataclass(frozen=True)
class RankingConfig:
    # FTS5 bm25() column weights in schema.COLUMNS order (FTS5 bm25 has k1 = 1.2 and b = 0.75).
    # ids title aliases vendor_product description weakness kev_text exploit_titles
    weights: tuple[float, ...] = (50.0, 0.5, 1.0, 2.0, 1.0, 2.0, 8.0, 2.0)
    stop_words: str = "english"      # query-side stop words: none | english
    max_df_ratio: float = 0.25       # drop query terms present in more than this share of documents
    max_terms: int = 24              # keep at most this many query terms (the rarest ones)
    max_query_chars: int = 20_000    # longer input is cut before tokenizing (bounded work)
    candidate_budget: int = 3_000    # summed document frequency of the matching (rarest) terms

    def __post_init__(self):
        if len(self.weights) != len(COLUMNS):
            raise ValueError(f"weights needs {len(COLUMNS)} values ({', '.join(COLUMNS)})")
        if any((not isinstance(w, (int, float))) or w < 0 or w != w or w == float("inf") for w in self.weights):
            raise ValueError("weights must be finite and non-negative")
        if not any(w > 0 for w in self.weights):
            raise ValueError("at least one weight must be positive")
        if self.stop_words not in STOP_MODES:
            raise ValueError(f"stop_words must be one of {STOP_MODES}")
        if not 0 < self.max_df_ratio <= 1:
            raise ValueError("max_df_ratio must be in (0, 1]")
        if not 1 <= self.max_terms <= 512:
            raise ValueError("max_terms must be in [1, 512]")
        if not 1 <= self.max_query_chars <= 1_000_000:
            raise ValueError("max_query_chars must be in [1, 1000000]")
        if not 1 <= self.candidate_budget <= 10_000_000:
            raise ValueError("candidate_budget must be in [1, 10000000]")

    def weight_map(self) -> dict[str, float]:
        return dict(zip(COLUMNS, self.weights))

    def as_dict(self) -> dict:
        d = asdict(self)
        d["weights"] = self.weight_map()
        d["bm25"] = {"k1": 1.2, "b": 0.75, "implementation": "sqlite fts5 bm25()"}
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RankingConfig":
        w = d["weights"]
        weights = tuple(float(w[c]) for c in COLUMNS) if isinstance(w, dict) else tuple(float(x) for x in w)
        return cls(weights=weights, stop_words=d.get("stop_words", "english"),
                   max_df_ratio=float(d.get("max_df_ratio", 0.25)), max_terms=int(d.get("max_terms", 24)),
                   max_query_chars=int(d.get("max_query_chars", 20_000)),
                   candidate_budget=int(d.get("candidate_budget", 3_000)))

    def with_(self, **kw) -> "RankingConfig":
        if "weights" in kw and isinstance(kw["weights"], dict):
            base = self.weight_map()
            base.update(kw["weights"])
            kw["weights"] = tuple(float(base[c]) for c in COLUMNS)
        return replace(self, **kw)


RANKING = RankingConfig()
