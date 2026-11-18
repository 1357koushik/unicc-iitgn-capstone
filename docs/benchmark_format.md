# Benchmark data format (contract between B2, B3, B4 and later packages)

All files are JSON Lines (one JSON object per line, UTF-8). Benchmark data lives outside git under
`data/benchmark/<version>/` in the repository root; only build code, the dataset card and file hashes are committed.

## Document identifiers

| Kind | `doc_id` form | Example |
|---|---|---|
| CVE | upper-case CVE ID | `CVE-2021-44228` |
| ATT&CK object | `attack:` + ATT&CK ID | `attack:G0016`, `attack:T1059.001`, `attack:S0154`, `attack:M1050` |

Results are evaluated at document level: several corpus rows for one CVE count as one document.

## `queries.jsonl`

| Field | Type | Meaning |
|---|---|---|
| `qid` | string | unique, stable, `<slice>-<n>` |
| `slice` | string | `T0` … `T9` (plan section 6.2) |
| `split` | string | `train`, `dev` or `test` |
| `text` | string | the query as sent to the service |
| `answerable` | bool | `false` only for T7. T1 holds only existing IDs; well-formed non-existent IDs belong to T7 |
| `temporal_holdout` | bool | target published in the last 90 days before the build date |
| `source` | object | `{name, id, licence}` of the source the query was derived from; `{name: "generated"}` if synthetic |
| `meta` | object | free-form, except the fixed keys below |

## `qrels.jsonl`

| Field | Type | Meaning |
|---|---|---|
| `qid` | string | |
| `doc_id` | string | |
| `grade` | int | 2 relevant, 1 related, 0 not relevant |
| `origin` | string | `known_item`, `equivalence`, `judged`, `authoring` |
| `judge` | object | for `judged`: `{round, first, second, adjudicated}`; otherwise omitted |

A document absent from `qrels.jsonl` for an answerable query is **unjudged**, never assumed not relevant. Unanswerable queries (`answerable=false`) have no qrels; every document is grade 0 for them.

Binary metrics (Success@k, MRR, recall) count a document as relevant when its grade is at least 2.

### Fixed `meta` keys

| Slice | Key | Values |
|---|---|---|
| T6 | `parent_qid` (required) | qid of the clean query it was derived from |
| T6 | `noise_type` (required) | `typo`, `spacing`, `abbreviation`, `log_fragment` |
| T9 | `query_form` (required) | `id`, `exact_name`, `natural`; the 100% Success@1 gate applies to `id` and `exact_name` |

## `equivalence.jsonl`

`{set_id, members: [doc_id, ...], reason}` — documents describing the same flaw (for example a CVE rejected as a duplicate of another). A hit on any member counts as a hit on the set. Overlapping sets are merged transitively by consumers; builders should avoid creating them.

## Run files (system output), `run.jsonl`

| Field | Type | Meaning |
|---|---|---|
| `qid` | string | |
| `variant` | string | registry name of the system variant |
| `ranked` | list | `[{doc_id, score, tier, probability}]`, best first, documents de-duplicated. `score` is a number. `tier` is one of `EXACT`, `STRONG`, `PARTIAL`, `WEAK`, `UNSUPPORTED`, or null; `probability` is a number in [0, 1] or null |
| `abstained` | bool | the system declared the query unanswerable |
| `latency_ms` | number | end-to-end |
| `error` | string or null | |
| `extra` | object, optional | adapter details such as HTTP status |

Run-level metadata (variant config, service health, host) goes in a sidecar `<run>.meta.json`.

## Judgement pool (`pool.jsonl`, written for B3)

`{qid, doc_id, ranks, best_rank}`: one line per (query, document) pair that needs a judgement; `ranks` maps variant name to rank.

## Sealed test split

Test-split queries and qrels are stored in `data/benchmark/<version>/sealed/`. Tools refuse to evaluate, pool or print the test split unless the environment variable `TRE_OPEN_SEALED=E1` is set, which only work package E1 does. Judgement round 3 (sealed-test outputs) is therefore executed as the first step of E1: E1 opens the split, pools the outputs, has them judged, and only then computes metrics. Judges see query–document pairs only, never metrics.

## Manifest

`data/benchmark/<version>/manifest.json`: version, build date, builder commit, input source manifests (name, date, sha256), counts per slice and split, and `files`: an object mapping each relative path to `{"sha256": ..., "count": ...}`. The committed dataset card copies the counts and hashes.
