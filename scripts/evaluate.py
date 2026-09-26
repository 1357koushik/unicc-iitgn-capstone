#!/usr/bin/env python3
"""
scripts/evaluate.py
===================
Benchmark evaluation for the Threat Retrieval & Matching Subsystem.

Evaluates the teammates' existing retrieval implementation and the existing
Team 2 matching pipeline without creating a benchmark-specific retrieval pathway.

Intended Architecture:
  Temporary benchmark query / dataset
        ↓
  TEAMMATES' EXISTING RETRIEVAL (unicc-iitgn-capstone-main/)
    - Hybrid retrieval: unicc-iitgn-capstone-main/hybrid_search.py (HybridSearcher)
    - Keyword retrieval: unicc-iitgn-capstone-main/bm25_index.py (BM25Index)
        ↓
  Actual retrieved historical threats (corpus_store.db via UpstreamRetrievalBackend)
        ↓
  Existing Team 2 threat matching (src/services/pipeline.py)
        ↓
  Existing scoring (src/services/scoring.py)
        ↓
  Existing classification (src/services/classifier.py)
        ↓
  Existing evidence / citations (src/services/citation.py)
        ↓
  Benchmark metrics (Hit@3, MRR@10, NDCG@10, Macro F1, P95 latency)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEAMMATE_ROOT = PROJECT_ROOT.parent / "unicc-iitgn-capstone-main"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(TEAMMATE_ROOT) not in sys.path:
    sys.path.insert(0, str(TEAMMATE_ROOT))

from src.core.bootstrap import (
    DEFAULT_SQLITE_PATH,
    build_live_backend,
    build_live_bm25_backend,
)
from src.core.interfaces import (
    MissingUpstreamDependency,
    get_backend,
    set_backend,
)
from src.core.metrics import (
    confusion_matrix,
    hit_at_k,
    macro_f1,
    mrr_at_k,
    ndcg_at_k,
)
from src.services.pipeline import run_threat_match_pipeline

DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "benchmark_dataset.json"

TARGET_NDCG = 0.85
TARGET_MRR = 0.80
TARGET_LATENCY_MS = 200.0


# ---------------------------------------------------------------------------
# Teammate Backend Initializer
# ---------------------------------------------------------------------------


def initialize_teammate_backend(
    retrieval_mode: str = "auto",
    sqlite_path: Path | None = None,
) -> tuple[Any, str]:
    """
    Initialize the teammate retrieval backend from unicc-iitgn-capstone-main/.

    Returns:
        (backend, active_mode_name)
    """
    db_path = sqlite_path or Path(DEFAULT_SQLITE_PATH)

    if retrieval_mode == "hybrid":
        print("Initializing teammates' full HybridSearcher (unicc-iitgn-capstone-main/hybrid_search.py)...")
        backend = build_live_backend()
        return backend, "Teammates' HybridSearcher (BM25 + Dense BGE-M3 + RRF)"

    if retrieval_mode == "bm25":
        print(f"Initializing teammates' Okapi BM25Index (unicc-iitgn-capstone-main/bm25_index.py) from {db_path.name}...")
        backend = build_live_bm25_backend(sqlite_path=db_path)
        return backend, "Teammates' Okapi BM25Index (unicc-iitgn-capstone-main/bm25_index.py)"

    # auto mode: try hybrid first, report blocker and fall back to BM25 if dependencies missing
    try:
        backend = build_live_backend()
        return backend, "Teammates' HybridSearcher (BM25 + Dense BGE-M3 + RRF)"
    except MissingUpstreamDependency as exc:
        print("\n[NOTE] Teammates' full HybridSearcher could not be loaded:")
        print(f"       {exc}")
        print(f"       Evaluating with teammates' live Okapi BM25 index ({db_path.name}).\n")
        backend = build_live_bm25_backend(sqlite_path=db_path)
        return backend, "Teammates' Okapi BM25Index (unicc-iitgn-capstone-main/bm25_index.py)"


# ---------------------------------------------------------------------------
# Benchmark Runner
# ---------------------------------------------------------------------------


async def evaluate_pipeline(
    dataset: list[dict[str, Any]],
    backend: Any,
    backend_name: str,
) -> bool:
    """
    Run evaluation by passing benchmark queries through the existing Team 2 pipeline
    using the active teammate retrieval backend.
    """
    original_backend = get_backend()
    set_backend(backend)

    print("=" * 65)
    print("THREAT RETRIEVAL & MATCHING EVALUATION")
    print("=" * 65)
    print(f"Retrieval Engine : {backend_name}")
    print(
        "Data Flow        : Benchmark Query\n"
        "                   → Teammates' Existing Retrieval (unicc-iitgn-capstone-main)\n"
        "                   → Existing Threat Matching (src/services/pipeline.py)\n"
        "                   → Existing Scoring / Classification / Citations\n"
        "                   → Benchmark Evaluation Metrics"
    )
    print(f"Queries Count    : {len(dataset)}")
    print("=" * 65)

    try:
        actual_tiers: list[str] = []
        predicted_tiers: list[str] = []
        retrieval_ranked_ids: list[list[str]] = []
        retrieval_targets: list[list[str]] = []
        latencies: list[float] = []

        for case in dataset:
            query = case["query"]
            expected_tier = case.get("expected_tier", "UNSUPPORTED")
            expected_chunk = case.get("expected_top_chunk", "")
            relevant_docs = case.get("relevant_documents") or []

            # Execute the query through the EXISTING Team 2 pipeline
            # NO custom retrieval function: delegates to active teammate backend
            result = await run_threat_match_pipeline(
                query=query,
                top_k=10,
                alpha=0.5,
            )

            latencies.append(result.pipeline_profile.total_ms)

            # Predicted confidence tier from existing 5-tier classifier
            predicted_tier = (
                result.top_matches[0].confidence_tier
                if result.top_matches
                else "UNSUPPORTED"
            )
            actual_tiers.append(expected_tier)
            predicted_tiers.append(predicted_tier)

            # Target matching for retrieval metrics
            if relevant_docs:
                retrieval_targets.append(relevant_docs)
                ranked_doc_ids = [
                    m.citations[0].doc_id if m.citations else ""
                    for m in result.top_matches
                ]
                retrieval_ranked_ids.append(ranked_doc_ids)
            elif expected_chunk:
                retrieval_targets.append([expected_chunk])
                ranked_chunk_ids = [m.chunk_id for m in result.top_matches]
                retrieval_ranked_ids.append(ranked_chunk_ids)

        # --- Retrieval Metrics ---
        print("\n" + "=" * 55)
        print("RETRIEVAL EVALUATION (Teammates' Retrieval Engine)")
        print("=" * 55)

        if retrieval_targets:
            avg_hit = sum(
                hit_at_k(t, p, 3)
                for t, p in zip(retrieval_targets, retrieval_ranked_ids)
            ) / len(retrieval_targets)
            avg_mrr = sum(
                mrr_at_k(t, p, 10)
                for t, p in zip(retrieval_targets, retrieval_ranked_ids)
            ) / len(retrieval_targets)
            avg_ndcg = sum(
                ndcg_at_k(t, p, 10)
                for t, p in zip(retrieval_targets, retrieval_ranked_ids)
            ) / len(retrieval_targets)
        else:
            avg_hit, avg_mrr, avg_ndcg = 0.0, 0.0, 0.0

        print(f"  Hit@3:    {avg_hit:.4f}")
        print(f"  MRR@10:   {avg_mrr:.4f}")
        print(f"  NDCG@10:  {avg_ndcg:.4f}")

        retrieval_gate_pass = avg_ndcg >= TARGET_NDCG and avg_mrr >= TARGET_MRR
        if not retrieval_gate_pass:
            if avg_ndcg < TARGET_NDCG:
                print(f"  [WARN] NDCG@10 {avg_ndcg:.4f} below target {TARGET_NDCG}")
            if avg_mrr < TARGET_MRR:
                print(f"  [WARN] MRR@10 {avg_mrr:.4f} below target {TARGET_MRR}")

        # --- Classification Metrics ---
        print("\n" + "=" * 55)
        print("CLASSIFICATION EVALUATION (Existing Team 2 Pipeline)")
        print("=" * 55)

        classes = ["EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"]
        f1 = macro_f1(actual_tiers, predicted_tiers, classes)
        cm = confusion_matrix(actual_tiers, predicted_tiers, classes)

        print(f"\nMacro F1: {f1:.4f}")
        print("\nConfusion Matrix (Actual \\ Predicted):")
        print(" " * 14 + "".join([f"{c[:3]:>5}" for c in classes]))
        for cls in classes:
            print(f"{cls:<13} " + "".join([f"{cm[cls][p]:>5}" for p in classes]))

        # Per-class breakdown
        print("\n" + "=" * 55)
        print("CLASSIFICATION QUALITY BREAKDOWN")
        print("=" * 55)
        for cls in classes:
            tp = cm[cls].get(cls, 0)
            fp = sum(cm[c].get(cls, 0) for c in classes if c != cls)
            fn = sum(cm[cls].get(c, 0) for c in classes if c != cls)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1_c = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            support = sum(cm[cls].values())
            print(
                f"  {cls:<12}: P={prec:.2f} R={rec:.2f} F1={f1_c:.2f} (Support: {support})"
            )

        # --- Latency SLA ---
        p95_idx = int(len(latencies) * 0.95) if latencies else 0
        p95_latency = sorted(latencies)[p95_idx] if latencies else 0.0
        print(
            f"\nP95 Latency: {p95_latency:.2f} ms (SLA Target: <={TARGET_LATENCY_MS} ms)"
        )

        # --- Quality Gates Summary ---
        print("\n" + "=" * 55)
        print("QUALITY GATES SUMMARY")
        print("=" * 55)
        latency_status = "PASS" if p95_latency <= TARGET_LATENCY_MS else "FAIL"
        retrieval_status = "PASS" if retrieval_gate_pass else "FAIL"
        print(f"Retrieval Quality Gate : {retrieval_status}")
        print(f"Latency SLA Gate       : {latency_status}")
        print(f"Classification Gate    : INFORMATIONAL (Macro F1: {f1:.4f})")

        return retrieval_gate_pass and (p95_latency <= TARGET_LATENCY_MS)

    finally:
        set_backend(original_backend)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Threat Matching Subsystem using teammates' existing retrieval"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help="Path to benchmark evaluation dataset JSON (default: data/benchmark_dataset.json)",
    )
    parser.add_argument(
        "--retrieval",
        choices=["auto", "hybrid", "bm25"],
        default="auto",
        help="Teammate retrieval engine to evaluate: hybrid (HybridSearcher), bm25 (BM25Index), or auto (default)",
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=None,
        help="Path to teammate SQLite corpus store (default: unicc-iitgn-capstone-main/data/sqlite/corpus_store.db)",
    )

    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"Error: Dataset file not found: {args.dataset}")
        sys.exit(1)

    with open(args.dataset, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    try:
        backend, backend_name = initialize_teammate_backend(
            retrieval_mode=args.retrieval,
            sqlite_path=args.sqlite_path,
        )
    except MissingUpstreamDependency as exc:
        print("\n" + "=" * 65)
        print("INTEGRATION BLOCKER REPORTED")
        print("=" * 65)
        print(f"Teammates' retrieval initialization failed:\n{exc}")
        print("\nAs required by Section 10, no artificial or fallback retrieval was created.")
        print("Install the required dependencies from unicc-iitgn-capstone-main/pyproject.toml")
        print("or run with '--retrieval=bm25' to evaluate using teammates' Okapi BM25 engine.")
        print("=" * 65)
        sys.exit(1)

    success = asyncio.run(
        evaluate_pipeline(
            dataset=dataset,
            backend=backend,
            backend_name=backend_name,
        )
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
