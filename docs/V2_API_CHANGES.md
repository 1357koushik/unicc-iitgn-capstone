# Retrieval service v2: what changes for callers (Team 3)

The endpoints, request bodies and response fields of v1 stay. v2 is the default (`TRE_PIPELINE=v2`);
`TRE_PIPELINE=v1` starts the previous pipeline (rollback copy: `~/team2/releases/v1-rollback-20261118.zip` on the
server).

## Behaviour

| Item | v1 | v2 |
|---|---|---|
| `alpha` in the request | dense/keyword weight | accepted and ignored; fusion weights are tuned on the benchmark dev split |
| `composite_score` | logistic formula over a squashed reranker score | probability that the result is relevant (calibrated model, C7), or 1.0 for `EXACT` |
| `confidence_tier` | fixed cut-offs | `EXACT` (ID in the question), else tier from calibrated precision: `STRONG` >= 95%, `PARTIAL` >= 70%, `WEAK` >= 30%, else `UNSUPPORTED`. Until the calibration file is present, scores are marked `calibrated: false` and never reach `STRONG` |
| Deadline | 15 s, then HTTP 504 | hard limit 3.0 s: stages are skipped to meet it and named in `skipped_stages`; HTTP 503 with `Retry-After` when busy; never 504 |
| PoC enrichment (`include_pocs`) | inside the match deadline | after matching, on its own 20 s deadline; CVEs in the question plus `EXACT`/`STRONG` CVE results, at most 3 |
| X (Twitter) PoC source | disabled switch | removed; a request naming `x` gets status `source_not_supported` |
| Hashes, IPs, domains | searched as text | notice `no_ioc_data_in_corpus`; a question made only of indicators returns no matches |
| A well-formed CVE ID not in the corpus | ignored | notice `not_in_corpus` |

## New optional response fields

`MatchResponse`: `pipeline_version`, `skipped_stages`, `notices` (list of `{code, ...}`), `nicknames` (names found in
the question with their CVEs). `TopMatchSchema`: `matched_names` (IDs, nicknames or ATT&CK names that led to the
result), `poc_status` (why PoC lookup did not finish for that result). `match_type` values: `EXACT_ID`, `NICKNAME`,
`ATTACK_ENTITY`, `RETRIEVAL`. `evidence_breakdown.features` carries `rerank_logit`, `dense_cosine`,
`lexical_rank`, `dense_rank`, `fused_rank`.

Results may be ATT&CK objects (`chunk_id` `attack:G0032`, `attack:T1190`, ...) as well as CVEs.

## ATT&CK techniques (added 2026-11-18)

`MatchRequest.include_techniques` (optional; `null` = server default, on). `MatchResponse.attack_techniques`: the
ATT&CK techniques the text describes, best first, up to 10: `{technique_id, doc_id, name, rank, rerank_score,
evidence}`; `evidence` is the description or procedure example that matched best. `pipeline_profile.technique_ms`
gives its time (about 0.3 s). It is separate from `top_matches`, which is unchanged. Results on public benchmarks:
`docs/EXTERNAL_BENCHMARKS.md`.

Deployment: build the technique knowledge base once per ATT&CK build with
`python scripts/v2/build_techniques.py --out <dir> --encoders bge-large qwen3-emb`, set `TRE_TECH_DIR=<dir>` (the
directory holding LATEST) and `TRE_MODEL_DIR` (bge-large-en-v1.5 and Qwen3-Embedding-0.6B). Without `TRE_TECH_DIR`
the route is off and `techniques` is listed in `skipped_stages` when a request asks for it.
