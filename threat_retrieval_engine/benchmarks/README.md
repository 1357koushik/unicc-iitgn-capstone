# Threat Retrieval & Matching Benchmarks

This directory is reserved for offline and online evaluation suites:

## Planned Benchmarks
1. **Retrieval Accuracy**:
   - NDCG@10 and MRR over CTIBench and labeled CTI query sets.
   - Exact-match recall on Technical IOCs (CVE IDs, Hashes, IPs, Domains).
2. **Re-ranking Precision**:
   - Top-5 reranking fidelity with BAAI/bge-reranker-v2-m3.
3. **Latency & SLA Benchmarking**:
   - Layer 1 (IOC Exact Lookup): < 1ms
   - Layer 2 (Dense + BM25 Fusion): ~145ms
   - Layer 3 (MITRE STIX Graph): ~50ms
   - End-to-End pipeline throughput under concurrency.
4. **RAGAS / DeepEval Evaluation**:
   - Faithfulness, Answer Relevance, and Context Precision.
