# V2 Decision Record: Latency and Deadline Contract

## 1. Context and Objective
Previously, latency targets and client timeouts in the codebase contradicted each other:
- README cited a 200 ms SLA for core matching.
- Historical benchmarks observed 31–75 s per query due to synchronous outbound OSINT and sequential processing.
- Team 3 client (`investigator.py`) enforced a fixed 30 s `urllib` timeout, failing whenever latency reached 31+ s.
- In-pipeline PoC discovery blocked the event loop and coupled four external network services into `/match`.

This decision record establishes a unified deadline contract across server, client, and enrichment workflows.

## 2. Invariants and Definitions

1. **`D_match` (Server-side hard deadline for `/match`): 15.0 seconds**
   - Covers exact lookup, dense/sparse vector retrieval, cross-encoder reranking, and confidence scoring.
   - **Excludes PoC discovery** (PoC discovery is decoupled into an opt-in or asynchronous job under `D_poc`).
   - If processing reaches `D_match`, the engine returns a 200 response with `deadline_exceeded: true` and `degraded_components: ["reranker" | ...]` using the best available candidates from fast retrieval tiers.

2. **`T_client_match` (Team 3 client timeout): 20.0 seconds**
   - Formula: `T_client_match = D_match + client_margin` (where `client_margin` = 5.0 s for network round-trip and serialization).
   - Invariant: `T_client_match > D_match` is strictly enforced. The client will never prematurely time out before the server has returned its result or declared a degraded state.

3. **`D_poc` (Enrichment deadline): 10.0 seconds**
   - Dedicated deadline for public PoC discovery across GitHub, X, Mastodon, and BlueSky.
   - Outbound queries run concurrently via `asyncio.gather`.
   - Max CVEs processed per batch is capped to avoid multiplicative delays.

4. **Scope of the 200 ms Target:**
   - The 200 ms latency target applies strictly to cached queries and the fast-path exact IOC/CVE lookup (`Engine 1`), not to cold model inference or full cross-encoder reranking over large candidate sets.

## 3. Configuration Single Source of Truth
These parameters are defined in `config/retrieval_config.yaml` under `deadlines:` and loaded into `threat_retrieval_engine.config.RetrievalConfig`.
