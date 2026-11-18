# Technique route: list fusions and rerankers

Questions with rankings: 4435 of 4435. Choice made on dev only.

## Fusions (no reranker)

| lists | dev R@10 | dev MRR | dev Hit@1 | Text2TTP R@10 | KEV Hits@10 | KEV MRR | CTIC ATD Hit@5 | CTIC ATA Hit@5 |
|---|---|---|---|---|---|---|---|---|
| keyword | 0.622 | 0.633 | 0.518 | 0.827 | 0.513 | 0.286 | 0.395 | 0.581 |
| bge-large | 0.525 | 0.585 | 0.482 | 0.841 | 0.625 | 0.392 | 0.410 | 0.531 |
| sentsecbert | 0.512 | 0.572 | 0.482 | 0.820 | 0.525 | 0.283 | 0.303 | 0.438 |
| securebert2 | 0.221 | 0.312 | 0.250 | 0.658 | 0.418 | 0.166 | 0.337 | 0.306 |
| qwen3-emb | 0.543 | 0.635 | 0.518 | 0.832 | 0.616 | 0.263 | 0.487 | 0.600 |
| keyword+bge-large | 0.608 | 0.668 | 0.571 | 0.890 | 0.671 | 0.388 | 0.464 | 0.662 |
| keyword+sentsecbert | 0.623 | 0.667 | 0.607 | 0.882 | 0.618 | 0.351 | 0.437 | 0.619 |
| keyword+securebert2 | 0.524 | 0.506 | 0.375 | 0.841 | 0.642 | 0.315 | 0.464 | 0.537 |
| keyword+qwen3-emb | 0.587 | 0.679 | 0.589 | 0.888 | 0.675 | 0.348 | 0.510 | 0.662 |
| bge-large+sentsecbert | 0.557 | 0.634 | 0.554 | 0.877 | 0.649 | 0.407 | 0.448 | 0.631 |
| bge-large+securebert2 | 0.442 | 0.445 | 0.339 | 0.820 | 0.654 | 0.359 | 0.441 | 0.494 |
| bge-large+qwen3-emb | 0.559 | 0.655 | 0.571 | 0.876 | 0.733 | 0.374 | 0.510 | 0.662 |
| sentsecbert+securebert2 | 0.475 | 0.428 | 0.304 | 0.817 | 0.640 | 0.328 | 0.433 | 0.500 |
| sentsecbert+qwen3-emb | 0.555 | 0.657 | 0.589 | 0.875 | 0.695 | 0.358 | 0.494 | 0.644 |
| securebert2+qwen3-emb | 0.449 | 0.444 | 0.321 | 0.827 | 0.666 | 0.308 | 0.429 | 0.494 |
| keyword+bge-large+sentsecbert | 0.602 | 0.685 | 0.625 | 0.896 | 0.678 | 0.417 | 0.464 | 0.700 |
| keyword+bge-large+securebert2 | 0.563 | 0.570 | 0.446 | 0.873 | 0.697 | 0.391 | 0.517 | 0.606 |
| keyword+bge-large+qwen3-emb | 0.571 | 0.677 | 0.589 | 0.906 | 0.730 | 0.403 | 0.529 | 0.681 |
| keyword+sentsecbert+securebert2 | 0.555 | 0.577 | 0.446 | 0.872 | 0.671 | 0.393 | 0.490 | 0.606 |
| keyword+sentsecbert+qwen3-emb | 0.580 | 0.692 | 0.625 | 0.903 | 0.706 | 0.394 | 0.510 | 0.688 |
| keyword+securebert2+qwen3-emb | 0.564 | 0.600 | 0.482 | 0.873 | 0.716 | 0.368 | 0.506 | 0.625 |
| bge-large+sentsecbert+securebert2 | 0.532 | 0.545 | 0.411 | 0.859 | 0.699 | 0.416 | 0.460 | 0.588 |
| bge-large+sentsecbert+qwen3-emb | 0.560 | 0.654 | 0.589 | 0.885 | 0.723 | 0.416 | 0.502 | 0.681 |
| bge-large+securebert2+qwen3-emb | 0.544 | 0.537 | 0.411 | 0.862 | 0.733 | 0.394 | 0.479 | 0.594 |
| sentsecbert+securebert2+qwen3-emb | 0.566 | 0.580 | 0.464 | 0.863 | 0.711 | 0.389 | 0.490 | 0.600 |
| keyword+bge-large+sentsecbert+securebert2 | 0.580 | 0.631 | 0.536 | 0.890 | 0.711 | 0.425 | 0.506 | 0.656 |
| keyword+bge-large+sentsecbert+qwen3-emb | 0.612 | 0.701 | 0.643 | 0.908 | 0.730 | 0.434 | 0.513 | 0.700 |
| keyword+bge-large+securebert2+qwen3-emb | 0.588 | 0.642 | 0.536 | 0.890 | 0.733 | 0.410 | 0.529 | 0.669 |
| keyword+sentsecbert+securebert2+qwen3-emb | 0.584 | 0.639 | 0.536 | 0.891 | 0.728 | 0.419 | 0.521 | 0.650 |
| bge-large+sentsecbert+securebert2+qwen3-emb | 0.578 | 0.600 | 0.482 | 0.883 | 0.737 | 0.420 | 0.506 | 0.644 |
| keyword+bge-large+sentsecbert+securebert2+qwen3-emb | 0.588 | 0.649 | 0.554 | 0.902 | 0.737 | 0.444 | 0.510 | 0.681 |

Best fusion on dev (Recall@10, then MRR, then fewer lists): **keyword+sentsecbert**


Text2TTP questions whose text contains a whole knowledge-base entry: 9
