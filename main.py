"""
main.py
=======
The main pipeline orchestrator.

Pipeline flow (in order):
  1. validator.py   — Parse raw data → ThreatChunks (clean + validated)
  2. duplicate_checker.py — Drop near-duplicate chunks (90% threshold)
  3. vectorizer.py  — Embed unique chunks with BGE-M3 (dense + sparse)
  4. vector_database.py — Store vectors in Qdrant, full text in SQLite

Usage:
    python main.py --nvd-dir ./data/nvd_cve_data
                   --cvelist-dir ./cve_data_fetching/cvelistV5-live/cves
                   --kev-csv ./cve_data_fetching/cisa_kev-2026-09-12.csv
                   --epss-csv ./cve_data_fetching/epss_scores-2026-09-12.csv

    Or run with --help to see all options.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from validator import (
    ThreatChunk,
    build_context,
    parse_cisa_kev_csv,
    parse_cvelist_directory,
    parse_epss_csv,
    parse_normalized_directory,
    parse_normalized_jsonl,
    parse_nvd_directory,
)
from duplicate_checker import DuplicateChecker
from vectorizer import BGEVectorizer
from vector_database import setup_databases, store_chunks

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline settings
# ---------------------------------------------------------------------------
STORE_BATCH_SIZE = 500   # How many chunks to vectorize + store per batch


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_pipeline(
    normalized_dir: Path | None = None,
    normalized_jsonl: Path | None = None,
    nvd_dir: Path | None = None,
    cvelist_dir: Path | None = None,
    kev_csv: Path | None = None,
    epss_csv: Path | None = None,
    qdrant_path: str = "./data/qdrant_storage",
    sqlite_path: str = "./data/sqlite/corpus_store.db",
) -> None:
    """
    End-to-end ingestion pipeline:
    Parse → Deduplicate → Vectorize → Store
    """
    logger.info("=== Pipeline Start ===")

    # Step 1: Setup databases (creates collections/tables if needed)
    logger.info("Step 1/4 — Setting up databases …")
    qdrant, sqlite = setup_databases(qdrant_path, sqlite_path)

    # Step 2: Parse all sources into a unified stream of ThreatChunks
    logger.info("Step 2/4 — Ingesting data sources …")

    def all_chunks():
        # Primary intake: Team 1's unified normalized CVE JSON files or JSONL
        if normalized_dir and normalized_dir.is_dir():
            logger.info("  → Parsing Team 1 unified normalized JSON from: %s", normalized_dir)
            yield from parse_normalized_directory(normalized_dir)

        if normalized_jsonl and normalized_jsonl.is_file():
            logger.info("  → Streaming Team 1 unified normalized JSONL: %s", normalized_jsonl)
            yield from parse_normalized_jsonl(normalized_jsonl)

        # Fallback intake: Raw source files directly
        if nvd_dir and nvd_dir.is_dir():
            logger.info("  → Parsing raw NVD JSON files from: %s", nvd_dir)
            yield from parse_nvd_directory(nvd_dir)

        if cvelist_dir and cvelist_dir.is_dir():
            logger.info("  → Parsing raw CVE List V5 JSON from: %s", cvelist_dir)
            yield from parse_cvelist_directory(cvelist_dir)

        if kev_csv and kev_csv.is_file():
            logger.info("  → Parsing raw CISA KEV CSV: %s", kev_csv)
            yield from parse_cisa_kev_csv(kev_csv)

        if epss_csv and epss_csv.is_file():
            logger.info("  → Parsing raw EPSS CSV: %s", epss_csv)
            yield from parse_epss_csv(epss_csv)

    # Step 3: Deduplicate
    logger.info("Step 3/4 — Deduplicating chunks …")
    checker = DuplicateChecker()

    # Step 4: Vectorize + Store in batches
    logger.info("Step 4/4 — Vectorizing and storing chunks …")
    vectorizer = BGEVectorizer()

    batch_chunks: list[ThreatChunk] = []
    total_stored = 0

    for chunk in checker.filter(list(all_chunks())):
        batch_chunks.append(chunk)

        if len(batch_chunks) >= STORE_BATCH_SIZE:
            total_stored += _process_batch(batch_chunks, vectorizer, qdrant, sqlite)
            batch_chunks = []

    # Process any remaining chunks
    if batch_chunks:
        total_stored += _process_batch(batch_chunks, vectorizer, qdrant, sqlite)

    logger.info("=== Pipeline Complete — %d chunks stored. ===", total_stored)


def _process_batch(
    chunks: list[ThreatChunk],
    vectorizer: BGEVectorizer,
    qdrant,
    sqlite,
) -> int:
    """Vectorize and store one batch. Returns number of chunks stored."""
    # Build enriched context strings (Strategy C)
    items = [(chunk.chunk_id, build_context(chunk)) for chunk in chunks]

    # Embed
    vector_results = vectorizer.encode(items)

    # Store into Qdrant + SQLite
    store_chunks(vector_results, chunks, qdrant, sqlite)

    return len(chunks)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the full CTI ingestion pipeline: Parse → Deduplicate → Vectorize → Store"
    )
    parser.add_argument(
        "--normalized-dir",
        type=Path,
        default=None,
        help="Path to directory containing Team 1 unified normalized JSON files (CVE-*_normalized.json).",
    )
    parser.add_argument(
        "--normalized-jsonl",
        type=Path,
        default=None,
        help="Path to Team 1 unified normalized JSONL file.",
    )
    parser.add_argument(
        "--nvd-dir",
        type=Path,
        default=None,
        help="(Fallback) Path to nvd_cve_data/ directory containing yearly JSON files.",
    )
    parser.add_argument(
        "--cvelist-dir",
        type=Path,
        default=None,
        help="(Fallback) Path to cvelistV5-live/cves/ directory (git clone).",
    )
    parser.add_argument(
        "--kev-csv",
        type=Path,
        default=None,
        help="(Fallback) Path to CISA KEV CSV file (e.g. cisa_kev-2026-09-12.csv).",
    )
    parser.add_argument(
        "--epss-csv",
        type=Path,
        default=None,
        help="(Fallback) Path to EPSS scores CSV file (e.g. epss_scores-2026-09-12.csv).",
    )
    parser.add_argument(
        "--qdrant-path",
        type=str,
        default="./data/qdrant_storage",
        help="Directory for embedded Qdrant storage.",
    )
    parser.add_argument(
        "--sqlite-path",
        type=str,
        default="./data/sqlite/corpus_store.db",
        help="Path for SQLite corpus database.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_pipeline(
        normalized_dir=args.normalized_dir,
        normalized_jsonl=args.normalized_jsonl,
        nvd_dir=args.nvd_dir,
        cvelist_dir=args.cvelist_dir,
        kev_csv=args.kev_csv,
        epss_csv=args.epss_csv,
        qdrant_path=args.qdrant_path,
        sqlite_path=args.sqlite_path,
    )
