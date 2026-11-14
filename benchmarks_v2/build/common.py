"""Shared helpers: paths, deterministic JSON, seeded randomness, hashing."""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILDER_VERSION = "2.0.0"
DEFAULT_SEED = 20261114

SLICES = ("T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9")
SPLITS = ("train", "dev", "test")
# Plan section 6.3: split proportions per slice group.
SPLIT_RATIOS: dict[str, dict[str, float]] = {
    **{s: {"train": 0.4, "dev": 0.2, "test": 0.4} for s in ("T3", "T4")},
    **{s: {"train": 0.0, "dev": 0.4, "test": 0.6} for s in ("T0", "T2", "T5", "T6", "T7", "T8", "T9")},
    "T1": {"train": 0.0, "dev": 0.5, "test": 0.5},
}
# Plan section 6.2 target sizes.
TARGET_SIZES = {"T0": 600, "T1": 300, "T2": 250, "T3": 1500, "T4": 800, "T5": 300, "T6": 400, "T7": 400,
                "T8": 300, "T9": 300}
OVERLAP_THRESHOLD = 0.60
TEMPORAL_DAYS = 90

QUERY_ROLES = ("query",)
INCIDENT_ROLES = ("incident",)
EXPANSION_SOURCES = ("exploitdb", "metasploit_modules", "nuclei_templates", "poc_in_github")

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ATTACK_DOC_RE = re.compile(r"^attack:(G\d{4}|S\d{4}|M\d{4}|T\d{4}(\.\d{3})?)$")


def _main_checkout_root(start: Path) -> Path | None:
    """For a git worktree, return the main checkout root (where untracked data lives)."""
    git = start / ".git"
    if git.is_file():
        m = re.match(r"gitdir:\s*(.+)", git.read_text(encoding="utf-8").strip())
        if m:
            gd = Path(m.group(1).strip())
            # <main>/.git/worktrees/<name>
            if gd.parent.name == "worktrees":
                return gd.parent.parent.parent
    return None


def data_root_candidates() -> list[Path]:
    roots = [REPO_ROOT]
    main = _main_checkout_root(REPO_ROOT)
    if main is not None:
        roots.append(main)
    return roots


def default_sources_dir() -> Path:
    env = os.environ.get("TRE_SOURCES_DIR")
    if env:
        return Path(env)
    for r in data_root_candidates():
        if (r / "data" / "sources").is_dir():
            return r / "data" / "sources"
    return REPO_ROOT / "data" / "sources"


def default_feeds_dir() -> Path:
    env = os.environ.get("TRE_FEEDS_DIR")
    if env:
        return Path(env)
    for r in data_root_candidates():
        if (r / "knowledge_foundation" / "feeds" / "nvd_cve_data").is_dir():
            return r / "knowledge_foundation" / "feeds"
    return REPO_ROOT / "knowledge_foundation" / "feeds"


def default_benchmark_dir() -> Path:
    for r in data_root_candidates():
        if (r / "data").is_dir() and (r / "data" / "sources").is_dir():
            return r / "data" / "benchmark"
    return REPO_ROOT / "data" / "benchmark"


def dumps(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact, UTF-8 characters kept."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "wb") as f:
        for r in rows:
            f.write(dumps(r).encode("utf-8") + b"\n")
            n += 1
    return n


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def rng(seed: int, *keys: Any) -> random.Random:
    """Independent, reproducible random stream for (seed, keys)."""
    h = hashlib.sha256(("|".join([str(seed)] + [str(k) for k in keys])).encode("utf-8")).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def stable_key(seed: int, *keys: Any) -> str:
    """Seeded sort key; deterministic and independent of Python hash randomisation."""
    return hashlib.sha256(("|".join([str(seed)] + [str(k) for k in keys])).encode("utf-8")).hexdigest()


def seeded_sample(items: list, k: int, seed: int, *keys: Any) -> list:
    """Deterministic sample of k items in a seeded order (input order must itself be deterministic)."""
    order = sorted(range(len(items)), key=lambda i: stable_key(seed, *keys, i))
    return [items[i] for i in order[:k]]


def git_head(repo: Path) -> str | None:
    """Read HEAD commit by plain file access (no git process)."""
    gitp = repo / ".git"
    try:
        if gitp.is_file():
            m = re.match(r"gitdir:\s*(.+)", gitp.read_text(encoding="utf-8").strip())
            gitdir = Path(m.group(1).strip()) if m else None
            common = gitdir.parent.parent if gitdir is not None and gitdir.parent.name == "worktrees" else gitdir
        else:
            gitdir = common = gitp
        if gitdir is None:
            return None
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head
        ref = head.split(None, 1)[1]
        for base in (gitdir, common):
            p = base / ref
            if p.is_file():
                return p.read_text(encoding="utf-8").strip()
        packed = common / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0]
    except OSError:
        return None
    return None
