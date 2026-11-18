# Technique route: list fusions and rerankers

Questions with rankings: 56 of 56. Choice made on dev only.

## Fusions (no reranker)

| lists | dev R@10 | dev MRR | dev Hit@1 | Text2TTP R@10 | KEV Hits@10 | KEV MRR | CTIC ATD Hit@5 | CTIC ATA Hit@5 |
|---|---|---|---|---|---|---|---|---|
| keyword | 0.622 | 0.633 | 0.518 | nan | nan | nan | nan | nan |
| bge-large | 0.525 | 0.585 | 0.482 | nan | nan | nan | nan | nan |
| sentsecbert | 0.512 | 0.572 | 0.482 | nan | nan | nan | nan | nan |
| securebert2 | 0.221 | 0.312 | 0.250 | nan | nan | nan | nan | nan |
| qwen3-emb | 0.543 | 0.635 | 0.518 | nan | nan | nan | nan | nan |
| keyword+bge-large | 0.608 | 0.668 | 0.571 | nan | nan | nan | nan | nan |
| keyword+sentsecbert | 0.623 | 0.667 | 0.607 | nan | nan | nan | nan | nan |
| keyword+securebert2 | 0.524 | 0.506 | 0.375 | nan | nan | nan | nan | nan |
| keyword+qwen3-emb | 0.587 | 0.679 | 0.589 | nan | nan | nan | nan | nan |
| bge-large+sentsecbert | 0.557 | 0.634 | 0.554 | nan | nan | nan | nan | nan |
| bge-large+securebert2 | 0.442 | 0.445 | 0.339 | nan | nan | nan | nan | nan |
| bge-large+qwen3-emb | 0.559 | 0.655 | 0.571 | nan | nan | nan | nan | nan |
| sentsecbert+securebert2 | 0.475 | 0.428 | 0.304 | nan | nan | nan | nan | nan |
| sentsecbert+qwen3-emb | 0.555 | 0.657 | 0.589 | nan | nan | nan | nan | nan |
| securebert2+qwen3-emb | 0.449 | 0.444 | 0.321 | nan | nan | nan | nan | nan |
| keyword+bge-large+sentsecbert | 0.602 | 0.685 | 0.625 | nan | nan | nan | nan | nan |
| keyword+bge-large+securebert2 | 0.563 | 0.570 | 0.446 | nan | nan | nan | nan | nan |
| keyword+bge-large+qwen3-emb | 0.571 | 0.677 | 0.589 | nan | nan | nan | nan | nan |
| keyword+sentsecbert+securebert2 | 0.555 | 0.577 | 0.446 | nan | nan | nan | nan | nan |
| keyword+sentsecbert+qwen3-emb | 0.580 | 0.692 | 0.625 | nan | nan | nan | nan | nan |
| keyword+securebert2+qwen3-emb | 0.564 | 0.600 | 0.482 | nan | nan | nan | nan | nan |
| bge-large+sentsecbert+securebert2 | 0.532 | 0.545 | 0.411 | nan | nan | nan | nan | nan |
| bge-large+sentsecbert+qwen3-emb | 0.560 | 0.654 | 0.589 | nan | nan | nan | nan | nan |
| bge-large+securebert2+qwen3-emb | 0.544 | 0.537 | 0.411 | nan | nan | nan | nan | nan |
| sentsecbert+securebert2+qwen3-emb | 0.566 | 0.580 | 0.464 | nan | nan | nan | nan | nan |
| keyword+bge-large+sentsecbert+securebert2 | 0.580 | 0.631 | 0.536 | nan | nan | nan | nan | nan |
| keyword+bge-large+sentsecbert+qwen3-emb | 0.612 | 0.701 | 0.643 | nan | nan | nan | nan | nan |
| keyword+bge-large+securebert2+qwen3-emb | 0.588 | 0.642 | 0.536 | nan | nan | nan | nan | nan |
| keyword+sentsecbert+securebert2+qwen3-emb | 0.584 | 0.639 | 0.536 | nan | nan | nan | nan | nan |
| bge-large+sentsecbert+securebert2+qwen3-emb | 0.578 | 0.600 | 0.482 | nan | nan | nan | nan | nan |
| keyword+bge-large+sentsecbert+securebert2+qwen3-emb | 0.588 | 0.649 | 0.554 | nan | nan | nan | nan | nan |

Best fusion on dev (Recall@10, then MRR, then fewer lists): **keyword+sentsecbert**

## Rerankers on the first 20 of a fusion

| reranker | fusion | dev R@10 | dev MRR | dev Hit@1 | Text2TTP R@10 | KEV Hits@10 | KEV MRR | CTIC ATD Hit@5 | CTIC ATA Hit@5 | ms/question p50 |
|---|---|---|---|---|---|---|---|---|---|---|
| bge-rerank-int8 |  | 0.491 | 0.500 | 0.357 | nan | nan | nan | nan | nan | 5358 |
| monot5 |  | 0.491 | 0.549 | 0.429 | nan | nan | nan | nan | nan | 11153 |
| qwen3-rerank (12 of 56 questions; stopped: about 60 s per question) |  | 0.500 | 0.269 | 0.083 | nan | nan | nan | nan | nan | 59776 |
| securebert2-ce |  | 0.495 | 0.609 | 0.500 | nan | nan | nan | nan | nan | 12913 |

Text2TTP questions whose text contains a whole knowledge-base entry: 0
