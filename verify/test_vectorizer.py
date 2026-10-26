from __future__ import annotations

import math
import numpy as np
import pytest
from unittest.mock import MagicMock

from threat_retrieval_engine.search_engine.vectorizer import (
    VectorResult,
    BGEVectorizer,
)


def test_vector_result_dataclass():
    dense = [0.1] * 1024
    sparse = {101: 1.5, 202: 0.8}
    res = VectorResult(
        chunk_id="chk1",
        dense_vector=dense,
        sparse_vector=sparse,
        enriched_text="Sample enriched text",
    )
    assert res.chunk_id == "chk1"
    assert len(res.dense_vector) == 1024
    assert res.sparse_vector[101] == 1.5


def test_bge_vectorizer_l2_normalization_and_encode():
    vectorizer = BGEVectorizer.__new__(BGEVectorizer)
    vectorizer._batch_size = 16
    vectorizer._use_gpu = False

    # Mock the internal model to return unnormalized dense array and sparse dict
    mock_model = MagicMock()
    # 2 sample outputs
    raw_vec1 = np.ones(1024, dtype=np.float32) * 2.0
    raw_vec2 = np.ones(1024, dtype=np.float32) * 5.0
    mock_model.encode.return_value = {
        "dense_vecs": np.array([raw_vec1, raw_vec2]),
        "lexical_weights": [{1: 0.5}, {2: 1.0}],
    }
    vectorizer._model = mock_model

    pairs = [("c1", "text 1"), ("c2", "text 2")]
    results = vectorizer.encode(pairs)

    assert len(results) == 2
    assert results[0].chunk_id == "c1"
    assert results[1].chunk_id == "c2"

    # Dense vectors must be L2 normalized (norm == 1.0)
    norm0 = math.sqrt(sum(x * x for x in results[0].dense_vector))
    norm1 = math.sqrt(sum(x * x for x in results[1].dense_vector))
    assert math.isclose(norm0, 1.0, rel_tol=1e-5)
    assert math.isclose(norm1, 1.0, rel_tol=1e-5)
