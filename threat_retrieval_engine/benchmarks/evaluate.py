#!/usr/bin/env python3
"""
threat_retrieval_engine/benchmarks/evaluate.py
=============================================
Official Benchmark Evaluation Suite for the Threat Retrieval & Matching Subsystem.

Evaluates retrieval quality (Hit@3, MRR@10, NDCG@10), classification fidelity
(Macro F1 across 5 tiers), and latency SLA (P95 <= 200ms) against calibrated
CTI benchmark scenarios.

Usage:
  python threat_retrieval_engine/benchmarks/evaluate.py
  python threat_retrieval_engine/benchmarks/evaluate.py --retrieval=bm25
  python threat_retrieval_engine/benchmarks/evaluate.py --dataset=threat_retrieval_engine/benchmarks/golden_dataset.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Configure paths so imports resolve reliably from any working directory
_BENCHMARK_DIR = Path(__file__).resolve().parent
_ENGINE_DIR = _BENCHMARK_DIR.parent
_REPO_ROOT = _ENGINE_DIR.parent

# Ensure repository root is on sys.path (C-4)
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from threat_retrieval_engine.benchmarks.metrics import (
    confusion_matrix,
    hit_at_k,
    macro_f1,
    mrr_at_k,
    ndcg_at_k,
)
from threat_retrieval_engine.benchmarks.report import compare_reports, render_comparison_markdown

logger = logging.getLogger(__name__)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

DEFAULT_DATASET = _BENCHMARK_DIR / "benchmark_dataset.json"
DEFAULT_OUTPUT = _BENCHMARK_DIR / "benchmark_results.json"
DEFAULT_SQLITE_PATH = _REPO_ROOT / "data" / "sqlite" / "corpus_store.db"
DEFAULT_QDRANT_PATH = _REPO_ROOT / "data" / "qdrant_storage"

TARGET_NDCG = 0.85
TARGET_MRR = 0.80
TARGET_LATENCY_MS = 200.0


def initialize_engine(
    retrieval_mode: str = "auto",
    sqlite_path: Path | None = None,
    qdrant_path: Path | None = None,
) -> tuple[Any, str]:
    """
    Initialize the ThreatRetrieverEngine with configured storage paths.

    ``retrieval_mode="bm25"`` runs lexical-only: no BGE-M3 download and no
    cross-encoder, so the suite is usable on CPU / Kaggle without a GPU. The
    previous revision accepted the flag but always loaded the neural stack.
    """
    from threat_retrieval_engine.api.pipeline import ThreatRetrieverEngine

    db_path = str(sqlite_path or DEFAULT_SQLITE_PATH)
    qd_path = str(qdrant_path or DEFAULT_QDRANT_PATH)
    lexical_only = retrieval_mode == "bm25"

    engine = ThreatRetrieverEngine()
    engine.qdrant = None  # force initialisation to honour the storage path
    engine.initialize(qdrant_path=qd_path, sqlite_path=db_path, lexical_only=lexical_only)

    mode_label = f"ThreatRetrieverEngine ({retrieval_mode.upper()} mode)"
    return engine, mode_label


async def evaluate_engine(
    engine: Any,
    engine_name: str,
    dataset: list[dict[str, Any]],
    output_path: Path | None = DEFAULT_OUTPUT,
    baseline_path: Path | None = None,
) -> tuple[bool, dict[str, Any]]:
    """
    Execute benchmark evaluation over provided queries.
    """
    print("=" * 68)
    print("THREAT RETRIEVAL & MATCHING SUBSYSTEM BENCHMARK")
    print("=" * 68)
    print(f"Retrieval Engine : {engine_name}")
    print(f"Benchmark Set    : {len(dataset)} scenarios")
    print(
        "Data Flow        : Query -> Exact Match / Hybrid Search\n"
        "                   -> STIX Graph Expansion -> 4-Factor Scoring\n"
        "                   -> 5-Tier Classification -> Citations"
    )
    print("=" * 68)

    actual_tiers: list[str] = []
    predicted_tiers: list[str] = []
    retrieval_ranked_ids: list[list[str]] = []
    retrieval_targets: list[list[str]] = []
    latencies: list[float] = []
    per_query_results: list[dict[str, Any]] = []

    for case in dataset:
        query = case["query"]
        expected_tier = case.get("expected_tier", "UNSUPPORTED")
        expected_chunk = case.get("expected_top_chunk", "")
        relevant_docs = case.get("relevant_documents") or []

        # Execute through unified pipeline
        t0 = time.perf_counter()
        result = engine.run_query(query=query, top_k=10, alpha=0.5)
        latency_ms = (time.perf_counter() - t0) * 1000
        latencies.append(latency_ms)

        predicted_tier = (
            result.top_matches[0].confidence_tier
            if result.top_matches
            else "UNSUPPORTED"
        )
        actual_tiers.append(expected_tier)
        predicted_tiers.append(predicted_tier)

        top_match_info = None
        if result.top_matches:
            tm = result.top_matches[0]
            doc_id = tm.citations[0].doc_id if tm.citations else ""
            top_match_info = {
                "chunk_id": tm.chunk_id,
                "document_id": doc_id,
                "confidence_tier": tm.confidence_tier,
                "composite_score": round(tm.composite_score, 4),
            }

        per_query_results.append({
            "query_id": case.get("query_id", f"query_{len(per_query_results)+1}"),
            "query": query,
            "expected_tier": expected_tier,
            "predicted_tier": predicted_tier,
            "relevant_documents": relevant_docs,
            "expected_top_chunk": expected_chunk,
            "top_match": top_match_info,
            "latency_ms": round(latency_ms, 2),
        })

        if relevant_docs:
            retrieval_targets.append(relevant_docs)
            ranked_doc_ids = []
            for m in result.top_matches:
                doc_id = m.citations[0].doc_id if m.citations else ""
                cve_match = _CVE_RE.search(doc_id)
                ranked_doc_ids.append(cve_match.group(0).upper() if cve_match else doc_id)
            retrieval_ranked_ids.append(ranked_doc_ids)
        elif expected_chunk:
            retrieval_targets.append([expected_chunk])
            ranked_chunk_ids = [m.chunk_id for m in result.top_matches]
            retrieval_ranked_ids.append(ranked_chunk_ids)

    # 1. Retrieval Metrics
    print("\n" + "=" * 55)
    print("RETRIEVAL EVALUATION")
    print("=" * 55)
    if retrieval_targets:
        avg_hit = sum(
            hit_at_k(t, p, 3) for t, p in zip(retrieval_targets, retrieval_ranked_ids)
        ) / len(retrieval_targets)
        avg_mrr = sum(
            mrr_at_k(t, p, 10) for t, p in zip(retrieval_targets, retrieval_ranked_ids)
        ) / len(retrieval_targets)
        avg_ndcg = sum(
            ndcg_at_k(t, p, 10) for t, p in zip(retrieval_targets, retrieval_ranked_ids)
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

    # 2. Classification Metrics
    print("\n" + "=" * 55)
    print("CLASSIFICATION EVALUATION (5-Tier Framework)")
    print("=" * 55)
    classes = ["EXACT", "STRONG", "PARTIAL", "WEAK", "UNSUPPORTED"]
    f1 = macro_f1(actual_tiers, predicted_tiers, classes)
    cm = confusion_matrix(actual_tiers, predicted_tiers, classes)

    print(f"\nMacro F1: {f1:.4f}")
    print("\nConfusion Matrix (Actual \\ Predicted):")
    print(" " * 14 + "".join([f"{c[:3]:>5}" for c in classes]))
    for cls in classes:
        print(f"{cls:<13} " + "".join([f"{cm[cls][p]:>5}" for p in classes]))

    print("\n" + "=" * 55)
    print("CLASSIFICATION BREAKDOWN")
    print("=" * 55)
    per_class_report = {}
    for cls in classes:
        tp = cm[cls].get(cls, 0)
        fp = sum(cm[c].get(cls, 0) for c in classes if c != cls)
        fn = sum(cm[cls].get(c, 0) for c in classes if c != cls)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_c = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        support = sum(cm[cls].values())
        per_class_report[cls] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1_c, 4),
            "support": support,
        }
        print(f"  {cls:<12}: P={prec:.2f} R={rec:.2f} F1={f1_c:.2f} (Support: {support})")

    # 3. Latency Metrics
    p95_idx = int(len(latencies) * 0.95) if latencies else 0
    p95_latency = sorted(latencies)[p95_idx] if latencies else 0.0
    print(f"\nP95 Latency: {p95_latency:.2f} ms (SLA Target: <={TARGET_LATENCY_MS} ms)")

    # 4. Quality Gates
    print("\n" + "=" * 55)
    print("QUALITY GATES SUMMARY")
    print("=" * 55)
    latency_status = "PASS" if p95_latency <= TARGET_LATENCY_MS else "FAIL"
    retrieval_status = "PASS" if retrieval_gate_pass else "FAIL"
    print(f"Retrieval Quality Gate : {retrieval_status}")
    print(f"Latency SLA Gate       : {latency_status}")
    print(f"Classification Gate    : INFORMATIONAL (Macro F1: {f1:.4f})")

    # Save results to output JSON
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "timestamp": datetime.now(UTC).isoformat(),
            "retrieval_engine": engine_name,
            "queries_count": len(dataset),
            "summary_metrics": {
                "hit_at_3": round(avg_hit, 4),
                "mrr_at_10": round(avg_mrr, 4),
                "ndcg_at_10": round(avg_ndcg, 4),
                "macro_f1": round(f1, 4),
                "p95_latency_ms": round(p95_latency, 2),
            },
            "quality_gates": {
                "retrieval": retrieval_status,
                "latency_sla": latency_status,
                "classification": "INFORMATIONAL",
            },
            "confusion_matrix": cm,
            "per_class_metrics": per_class_report,
            "per_query_results": per_query_results,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[INFO] Benchmark results saved to: {output_path}")

    return retrieval_gate_pass and (p95_latency <= TARGET_LATENCY_MS)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Threat Retrieval & Matching Subsystem against benchmarks"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to benchmark evaluation dataset JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to save benchmark JSON results",
    )
    parser.add_argument(
        "--retrieval",
        choices=["auto", "hybrid", "bm25"],
        default="auto",
        help="Retrieval engine mode (auto, hybrid, or bm25)",
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=DEFAULT_SQLITE_PATH,
        help="Path to SQLite corpus store",
    )
    parser.add_argument(
        "--qdrant-path",
        type=Path,
        default=DEFAULT_QDRANT_PATH,
        help="Path to embedded Qdrant storage directory",
    )

    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"Error: Dataset file not found: {args.dataset}")
        sys.exit(1)

    with open(args.dataset, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    engine, engine_name = initialize_engine(
        retrieval_mode=args.retrieval,
        sqlite_path=args.sqlite_path,
        qdrant_path=args.qdrant_path,
    )

    success = asyncio.run(
        evaluate_engine(
            engine=engine,
            engine_name=engine_name,
            dataset=dataset,
            output_path=args.output,
        )
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
