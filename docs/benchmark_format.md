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
| `answerable` | bool | `false` only for T7 |
| `temporal_holdout` | bool | target published in the last 90 days before the build date |
| `source` | object | `{name, id, licence}` of the source the query was derived from; `{name: "generated"}` if synthetic |
| `meta` | object | free-form (e.g. noise type for T6, parent qid) |

## `qrels.jsonl`

| Field | Type | Meaning |
|---|---|---|
| `qid` | string | |
| `doc_id` | string | |
| `grade` | int | 2 relevant, 1 related, 0 not relevant |
| `origin` | string | `known_item`, `equivalence`, `judged`, `authoring` |
| `judge` | object | for `judged`: `{round, first, second, adjudicated}`; otherwise omitted |

A document absent from `qrels.jsonl` for a query is **unjudged**, never assumed not relevant.

## `equivalence.jsonl`

`{set_id, members: [doc_id, ...], reason}` — documents describing the same flaw (for example a CVE rejected as a duplicate of another). A hit on any member counts as a hit on the set.

## Run files (system output), `run.jsonl`

| Field | Type | Meaning |
|---|---|---|
| `qid` | string | |
| `variant` | string | registry name of the system variant |
| `ranked` | list | `[{doc_id, score, tier, probability}]`, best first, documents de-duplicated; `tier` and `probability` may be null |
| `abstained` | bool | the system declared the query unanswerable |
| `latency_ms` | number | end-to-end |
| `error` | string or null | |

## Sealed test split

Test-split queries and qrels are stored in `data/benchmark/<version>/sealed/`. Tools refuse to evaluate or print the test split unless the environment variable `TRE_OPEN_SEALED=E1` is set, which only work package E1 does.

## Manifest

`data/benchmark/<version>/manifest.json`: version, build date, builder commit, input source manifests (name, date, sha256), per-file sha256 and counts per slice and split. The committed dataset card copies the counts and hashes.
