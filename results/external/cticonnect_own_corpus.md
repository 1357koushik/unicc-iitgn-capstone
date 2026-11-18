# v2 on public cybersecurity retrieval benchmarks

Questions 729, answered 729. Values: mean [95% bootstrap interval]. Questions whose answer is not in our corpus count as misses.

## cticonnect_ata (n=160, answer not in corpus: 1, text found in our ATT&CK descriptions: 0)

| order | hit1 | hit3 | hit5 | hit10 | mrr10 | recall3 | recall10 |
|---|---|---|---|---|---|---|---|
| served | 0.144 [0.094, 0.200] | 0.312 [0.237, 0.388] | 0.388 [0.312, 0.463] | 0.500 [0.425, 0.575] | 0.251 [0.197, 0.306] | 0.312 [0.237, 0.388] | 0.500 [0.425, 0.575] |
| fused | 0.150 [0.100, 0.206] | 0.312 [0.237, 0.388] | 0.388 [0.312, 0.463] | 0.500 [0.425, 0.575] | 0.254 [0.200, 0.310] | 0.312 [0.237, 0.388] | 0.500 [0.425, 0.575] |

## cticonnect_atd (n=261, answer not in corpus: 1, text found in our ATT&CK descriptions: 0)

| order | hit1 | hit3 | hit5 | hit10 | mrr10 | recall3 | recall10 |
|---|---|---|---|---|---|---|---|
| served | 0.192 [0.146, 0.241] | 0.345 [0.287, 0.402] | 0.452 [0.391, 0.513] | 0.536 [0.475, 0.594] | 0.292 [0.246, 0.339] | 0.345 [0.287, 0.402] | 0.536 [0.475, 0.594] |
| fused | 0.195 [0.146, 0.245] | 0.345 [0.287, 0.402] | 0.452 [0.391, 0.513] | 0.536 [0.475, 0.594] | 0.294 [0.247, 0.341] | 0.345 [0.287, 0.402] | 0.536 [0.475, 0.594] |

## cticonnect_wim (n=308, answer not in corpus: 0, text found in our ATT&CK descriptions: 0)

| order | hit1 | hit3 | hit5 | hit10 | mrr10 | recall3 | recall10 |
|---|---|---|---|---|---|---|---|
| served | 0.448 [0.393, 0.503] | 0.597 [0.542, 0.653] | 0.666 [0.614, 0.718] | 0.721 [0.669, 0.769] | 0.534 [0.485, 0.583] | 0.289 [0.245, 0.333] | 0.446 [0.398, 0.494] |
| fused | 0.448 [0.393, 0.503] | 0.597 [0.542, 0.653] | 0.666 [0.614, 0.718] | 0.721 [0.669, 0.769] | 0.534 [0.485, 0.583] | 0.289 [0.245, 0.333] | 0.446 [0.398, 0.494] |

Retrieval time per question (12 parallel workers x 4 threads): p50 639 ms, p95 826 ms; skipped stages: Counter()
