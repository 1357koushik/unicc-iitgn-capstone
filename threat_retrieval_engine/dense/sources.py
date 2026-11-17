"""Documents to embed: ``(doc_id, kind, text, content_hash)`` in index order.

Index order is: CVE documents (C1 store, searchable rows, ``dense_text``) in CVE ID text order, then ATT&CK
documents (C9, active and searchable, ``dense_text``) in doc_id order. A document's position in that order is
its row in the vector matrix and the tie-break of the search (plan 6.5: ties broken by document ID).

A ``DocumentSet`` is materialised as ``documents.jsonl`` (one JSON object per line) so an encode job can run
on a machine without the store; the file's sha256 is recorded in the build manifest, and the set records the
store and ATT&CK build IDs it came from.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .schema import KINDS


@dataclass
class DocumentSet:
    doc_ids: list[str]
    kinds: list[str]
    texts: list[str]
    content_hashes: list[str]
    inputs: dict = field(default_factory=dict)
    selection: dict = field(default_factory=dict)

    def __post_init__(self):
        n = len(self.doc_ids)
        if not (len(self.kinds) == len(self.texts) == len(self.content_hashes) == n):
            raise ValueError("DocumentSet columns differ in length")
        check_order(self.doc_ids, self.kinds)

    def __len__(self) -> int:
        return len(self.doc_ids)

    def kind_ranges(self) -> dict[str, list[int]]:
        out: dict[str, list[int]] = {}
        for i, k in enumerate(self.kinds):
            if k not in out:
                out[k] = [i, i + 1]
            else:
                out[k][1] = i + 1
        return out

    def sha256(self) -> str:
        h = hashlib.sha256()
        for d, k, t, c in zip(self.doc_ids, self.kinds, self.texts, self.content_hashes):
            h.update(f"{k}\x1e{d}\x1e{c}\x1e".encode("utf-8"))
            h.update(hashlib.sha256(t.encode("utf-8")).digest())
        return h.hexdigest()

    def write(self, path: Path) -> str:
        path = Path(path)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"header": True, "inputs": self.inputs, "selection": self.selection,
                                "documents": len(self), "documents_sha256": self.sha256()}, sort_keys=True) + "\n")
            for d, k, t, c in zip(self.doc_ids, self.kinds, self.texts, self.content_hashes):
                f.write(json.dumps({"doc_id": d, "kind": k, "text": t, "content_hash": c}, ensure_ascii=False) + "\n")
        return self.sha256()

    @classmethod
    def read(cls, path: Path) -> "DocumentSet":
        ids, kinds, texts, hashes = [], [], [], []
        header = None
        with open(path, encoding="utf-8") as f:
            for line in f:
                o = json.loads(line)
                if o.get("header"):
                    header = o
                    continue
                ids.append(o["doc_id"])
                kinds.append(o["kind"])
                texts.append(o["text"])
                hashes.append(o["content_hash"])
        if header is None:
            raise ValueError(f"{path}: no header line")
        ds = cls(ids, kinds, texts, hashes, header.get("inputs", {}), header.get("selection", {}))
        if ds.sha256() != header["documents_sha256"] or len(ds) != header["documents"]:
            raise ValueError(f"{path}: content does not match its header (truncated or edited)")
        return ds

    def subset(self, keep: Iterable[str], selection: dict) -> "DocumentSet":
        keep = set(keep)
        idx = [i for i, d in enumerate(self.doc_ids) if d in keep]
        return DocumentSet([self.doc_ids[i] for i in idx], [self.kinds[i] for i in idx], [self.texts[i] for i in idx],
                           [self.content_hashes[i] for i in idx], dict(self.inputs), selection)


def check_order(doc_ids: list[str], kinds: list[str]) -> None:
    """Kinds contiguous in KINDS order, doc_ids strictly increasing inside a kind."""
    last_kind, last_id = -1, None
    for d, k in zip(doc_ids, kinds):
        if k not in KINDS:
            raise ValueError(f"unknown kind {k!r}")
        ki = KINDS.index(k)
        if ki < last_kind:
            raise ValueError(f"{d}: kind {k} after a later kind")
        if ki > last_kind:
            last_kind, last_id = ki, None
        if last_id is not None and d <= last_id:
            raise ValueError(f"{d}: doc_ids not strictly increasing inside kind {k}")
        last_id = d


def iter_store(store) -> Iterator[tuple[str, str, str, str]]:
    for row in store.iter_searchable(columns=("cve_id", "dense_text", "content_hash")):
        text = row["dense_text"]
        if not text:
            raise ValueError(f"{row['cve_id']}: searchable row without dense_text")
        yield row["cve_id"], "cve", text, row["content_hash"]


def iter_attack(attack) -> Iterator[tuple[str, str, str, str]]:
    for row in attack.iter_searchable(columns=("doc_id", "dense_text", "content_hash", "state")):
        if row.get("state", "active") != "active":
            continue
        if not row["dense_text"]:
            raise ValueError(f"{row['doc_id']}: searchable ATT&CK document without dense_text")
        yield row["doc_id"], "attack", row["dense_text"], row["content_hash"]


def from_builds(store_path=None, attack_path=None, with_attack: bool = True) -> DocumentSet:
    """Every searchable CVE of a C1 build and (by default) every active searchable ATT&CK document."""
    from ..store import Store
    ids, kinds, texts, hashes = [], [], [], []
    inputs: dict = {}
    with Store.open(store_path) as s:
        for d, k, t, c in iter_store(s):
            ids.append(d); kinds.append(k); texts.append(t); hashes.append(c)  # noqa: E702
        inputs["store"] = {"build_id": s.build_id, "path": str(s.build_dir), "searchable": s.count(searchable=True),
                           "store_version": s.manifest.get("store_version"),
                           "inputs_sha256": s.manifest.get("inputs_sha256")}
    if with_attack:
        from ..attack import AttackStore
        a = AttackStore.open(attack_path)
        try:
            for d, k, t, c in iter_attack(a):
                ids.append(d); kinds.append(k); texts.append(t); hashes.append(c)  # noqa: E702
            inputs["attack"] = {"build_id": a.build_id, "path": str(a.build_dir),
                                "attack_version": a.attack_version, "c1_store_build_id": a.c1_store_build_id}
        finally:
            a.close()
    return DocumentSet(ids, kinds, texts, hashes, inputs, {"rule": "all searchable documents"})
