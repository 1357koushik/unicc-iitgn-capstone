"""Embedding models compared in C3, each with its documented input format, pinned to a revision.

Every entry follows the model card of the pinned revision:

* ``bge-m3`` (BAAI/bge-m3): dense vector = the [CLS] token's last hidden state, L2-normalised; no instruction
  for queries or passages ("no instruction needed" for retrieval with BGE-M3).
* ``bge-large-en-v1.5`` / ``bge-base-en-v1.5`` (BAAI): [CLS] pooling, L2-normalised; short queries for passage
  retrieval get the instruction ``"Represent this sentence for searching relevant passages: "``, passages none.
* ``e5-large-v2`` (intfloat): mean pooling over the attention mask, L2-normalised; ``"query: "`` and
  ``"passage: "`` prefixes ("otherwise you will see a performance degradation").
* ``gte-large`` (thenlper): mean pooling over the attention mask, L2-normalised; no instruction or prefix.

``v1`` is not a model but the vectors v1 computed with BGE-M3 (FlagEmbedding, Strategy-C context strings with
metadata labels and the CVE ID, no truncation); v1 encoded queries with the bge-en instruction above, which
belongs to another model family. ``v1_query_prefix`` records that so the v1 baseline can be evaluated both as
v1 served it and in BGE-M3's documented format.

Model files are loaded from a local directory (``$TRE_MODEL_DIR/<name>`` or the Hugging Face cache for
BGE-M3) and checked against the sha256 of the weight file before use (plan 5.1, supply chain).
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

BGE_EN_INSTRUCTION = "Represent this sentence for searching relevant passages: "

# Input cap from plan 4.5 ("model input is capped at 256 tokens"), counted in the model's own tokens including
# the special tokens and any prefix.
DOCUMENT_MAX_TOKENS = 256
QUERY_MAX_TOKENS = 256


@dataclass(frozen=True)
class ModelSpec:
    name: str
    repo: str
    revision: str
    dim: int
    pooling: str                     # cls | mean
    query_prefix: str = ""
    passage_prefix: str = ""
    weights_file: str = "model.safetensors"
    weights_sha256: str = ""
    max_position_tokens: int = 512
    licence: str = "mit"
    card_note: str = ""
    files: tuple[str, ...] = field(default=("config.json", "tokenizer.json", "tokenizer_config.json",
                                            "special_tokens_map.json"))

    def as_dict(self) -> dict:
        d = asdict(self)
        d["files"] = list(self.files)
        return d


MODELS: dict[str, ModelSpec] = {
    "bge-m3": ModelSpec(
        name="bge-m3", repo="BAAI/bge-m3", revision="5617a9f61b028005a4858fdac845db406aefb181", dim=1024,
        pooling="cls", weights_file="pytorch_model.bin",
        weights_sha256="b5e0ce3470abf5ef3831aa1bd5553b486803e83251590ab7ff35a117cf6aad38",
        max_position_tokens=8192,
        card_note="dense: CLS of last hidden state, normalised; no instruction for queries"),
    "bge-large-en-v1.5": ModelSpec(
        name="bge-large-en-v1.5", repo="BAAI/bge-large-en-v1.5", revision="d4aa6901d3a41ba39fb536a557fa166f842b0e09",
        dim=1024, pooling="cls", query_prefix=BGE_EN_INSTRUCTION,
        weights_sha256="45e1954914e29bd74080e6c1510165274ff5279421c89f76c418878732f64ae7",
        card_note="CLS pooling, normalised; query instruction for short-query passage retrieval"),
    "bge-base-en-v1.5": ModelSpec(
        name="bge-base-en-v1.5", repo="BAAI/bge-base-en-v1.5", revision="a5beb1e3e68b9ab74eb54cfd186867f64f240e1a",
        dim=768, pooling="cls", query_prefix=BGE_EN_INSTRUCTION,
        weights_sha256="c7c1988aae201f80cf91a5dbbd5866409503b89dcaba877ca6dba7dd0a5167d7",
        card_note="CLS pooling, normalised; query instruction for short-query passage retrieval"),
    "e5-large-v2": ModelSpec(
        name="e5-large-v2", repo="intfloat/e5-large-v2", revision="f169b11e22de13617baa190a028a32f3493550b6",
        dim=1024, pooling="mean", query_prefix="query: ", passage_prefix="passage: ",
        weights_sha256="d741c1a688a6169af0ecb5a047c44645cd992c31e1bf431269f98bba9ae2911a",
        card_note="mean pooling, normalised; 'query: ' / 'passage: ' prefixes"),
    "gte-large": ModelSpec(
        name="gte-large", repo="thenlper/gte-large", revision="4bef63f39fcc5e2d6b0aae83089f307af4970164",
        dim=1024, pooling="mean",
        weights_sha256="4b13b8593311201737b0acaa24f33c39e2d07953e5ba13fc6ff0c6242d13e1b5",
        card_note="mean pooling, normalised; no instruction"),
}

# The v1 vectors: BGE-M3 at the revision above, applied by v1 to its Strategy-C context strings.
V1_VECTORS = {"model": "bge-m3", "v1_query_prefix": BGE_EN_INSTRUCTION,
              "document_text": "v1 Strategy-C context string (Document | Section | Content | CVEs | Malware | TTPs), "
                               "FlagEmbedding max_length 8192 (no truncation)"}

COMPARED = ("bge-m3", "bge-large-en-v1.5", "bge-base-en-v1.5", "e5-large-v2", "gte-large")


def get(name: str) -> ModelSpec:
    if name not in MODELS:
        raise KeyError(f"unknown embedding model {name!r}; known: {', '.join(MODELS)}")
    return MODELS[name]


def model_dir(spec: ModelSpec, root: str | os.PathLike | None = None) -> Path:
    """Directory holding the model's files at the pinned revision.

    Order: ``root`` / ``$TRE_MODEL_DIR`` (``<root>/<name>``), then the Hugging Face cache snapshot
    (``$HF_HOME/hub`` or ``~/.cache/huggingface/hub``) for exactly the pinned revision."""
    cands = []
    base = root or os.environ.get("TRE_MODEL_DIR")
    if base:
        cands.append(Path(base) / spec.name)
    cands.append(Path(__file__).resolve().parents[2] / "data" / "models" / spec.name)
    hf = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")) / "hub"
    cands.append(hf / f"models--{spec.repo.replace('/', '--')}" / "snapshots" / spec.revision)
    for c in cands:
        if (c / spec.weights_file).is_file() and (c / "config.json").is_file():
            return c
    raise FileNotFoundError(f"model {spec.name} (revision {spec.revision}) not found in: "
                            + ", ".join(str(c) for c in cands))
