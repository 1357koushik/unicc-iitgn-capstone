"""
test_vectorizer.py
==================
Tests for src/vectorizer.py (BGE-M3 pipeline)

The actual BGE-M3 model is MOCKED here — no GPU or download needed.
These tests verify the logic around batching, normalization, and output shape.

Run with: pytest verify/test_vectorizer.py -v
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vectorizer import BGEVectorizer, VectorResult


# ---------------------------------------------------------------------------
# Helpers to build a fake BGE-M3 model output
# ---------------------------------------------------------------------------


def _fake_model_output(batch_size: int):
    """Simulate what BGEM3FlagModel.encode() returns."""
    # Random dense vectors (NOT normalized — the code should normalize them)
    dense = np.random.rand(batch_size, 1024).astype(np.float32) * 5.0
    # Fake sparse weights: 10 tokens per item
    sparse = [{str(i * 10 + j): float(j) / 10 for j in range(1, 11)} for i in range(batch_size)]
    return {"dense_vecs": dense, "lexical_weights": sparse}


# ---------------------------------------------------------------------------
# Fixture: a BGEVectorizer with the model patched out
# ---------------------------------------------------------------------------


@pytest.fixture
def mocked_vectorizer():
    vectorizer = BGEVectorizer.__new__(BGEVectorizer)
    vectorizer._use_gpu = False
    vectorizer._batch_size = 16

    fake_model = MagicMock()

    def side_effect(texts, **kwargs):
        return _fake_model_output(len(texts))

    fake_model.encode.side_effect = side_effect
    vectorizer._model = fake_model
    return vectorizer


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_encode_returns_correct_count(mocked_vectorizer):
    """One VectorResult should come back for each input."""
    items = [(f"chunk_{i}", f"Some text about vulnerability {i} found in software.") for i in range(5)]
    results = mocked_vectorizer.encode(items)
    assert len(results) == 5


def test_dense_vector_is_1024_dims(mocked_vectorizer):
    """Dense vector must be exactly 1024-dimensional."""
    items = [("chunk_0", "Apache Log4j allows remote code execution via JNDI lookup.")]
    results = mocked_vectorizer.encode(items)
    assert len(results[0].dense_vector) == 1024


def test_dense_vector_is_l2_normalized(mocked_vectorizer):
    """After normalization, the L2 norm of the dense vector should be ~1.0."""
    items = [("chunk_0", "A remote code execution vulnerability was discovered in Apache Log4j.")]
    results = mocked_vectorizer.encode(items)
    dense = np.array(results[0].dense_vector)
    norm = float(np.linalg.norm(dense))
    assert abs(norm - 1.0) < 1e-4, f"Expected L2 norm ≈ 1.0, got {norm}"


def test_sparse_vector_has_int_keys(mocked_vectorizer):
    """SPLADE sparse weights must use integer token IDs as dict keys."""
    items = [("chunk_0", "Vulnerability in OpenSSL allows TLS session hijacking.")]
    results = mocked_vectorizer.encode(items)
    sparse = results[0].sparse_vector
    assert all(isinstance(k, int) for k in sparse.keys()), "Sparse keys must be ints"


def test_sparse_vector_has_float_values(mocked_vectorizer):
    """SPLADE weight values must be floats."""
    items = [("chunk_0", "Buffer overflow in Microsoft Windows kernel allows privilege escalation.")]
    results = mocked_vectorizer.encode(items)
    sparse = results[0].sparse_vector
    assert all(isinstance(v, float) for v in sparse.values()), "Sparse values must be floats"


def test_enriched_text_is_preserved(mocked_vectorizer):
    """The enriched_text field in VectorResult must match what was passed in."""
    context = "Document: Test | Content: Vulnerability found in SSH."
    items = [("chunk_abc", context)]
    results = mocked_vectorizer.encode(items)
    assert results[0].enriched_text == context


def test_chunk_ids_are_preserved(mocked_vectorizer):
    """chunk_id in VectorResult must match the input chunk_id."""
    items = [
        ("id_one", "First vulnerability description that is long enough to pass."),
        ("id_two", "Second vulnerability description that is long enough to pass."),
    ]
    results = mocked_vectorizer.encode(items)
    returned_ids = {r.chunk_id for r in results}
    assert returned_ids == {"id_one", "id_two"}


def test_batching_calls_model_correctly(mocked_vectorizer):
    """With batch_size=16 and 20 items, the model should be called twice."""
    mocked_vectorizer._batch_size = 16
    items = [(f"c{i}", f"Text {i} about a cybersecurity vulnerability in network software.") for i in range(20)]
    results = mocked_vectorizer.encode(items)
    # 20 items / batch 16 = 2 batches
    assert mocked_vectorizer._model.encode.call_count == 2
    assert len(results) == 20


def test_zero_vector_does_not_crash_normalization(mocked_vectorizer):
    """A zero dense vector should be handled safely (not divide by zero)."""
    fake_model = MagicMock()
    # Return a zero vector
    zero_dense = np.zeros((1, 1024), dtype=np.float32)
    fake_model.encode.return_value = {
        "dense_vecs": zero_dense,
        "lexical_weights": [{"1": 0.5}],
    }
    mocked_vectorizer._model = fake_model
    items = [("zero_chunk", "Normal text that should not produce a division error.")]
    results = mocked_vectorizer.encode(items)
    # Should not crash; norm of zero vector is handled
    assert len(results) == 1
