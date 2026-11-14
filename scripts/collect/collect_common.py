"""Shared helpers for the B1 source collectors.

Standard library plus httpx only. Every collector module exposes

    SPEC    -- a SourceSpec describing role, URLs and licence
    collect(ctx) -> iterable of JSON-serialisable dict records

and `run_source` wraps it: it builds the day directory in a temporary
location, writes raw/, records.jsonl and manifest.json, then swaps the
directory into place and updates LATEST.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

COLLECTOR_VERSION = "1.0.0"
ROLES = ("query", "expansion", "incident", "attack")
USER_AGENT = "unicc-capstone-source-collector/1.0 (research use; contact via repository)"


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
class CollectError(RuntimeError):
    """Hard failure: network, parse or environment problem. Nothing is written."""


class SourceUnavailable(Exception):
    """The source cannot be used (blocked, gone, licence). A manifest is still written."""

    def __init__(self, reason: str, status: str = "unavailable"):
        super().__init__(reason)
        assert status in ("unavailable", "licence_blocked")
        self.reason = reason
        self.status = status


# --------------------------------------------------------------------------
# CVE normalisation
# --------------------------------------------------------------------------
_CVE_FULL = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
_CVE_FIND = re.compile(r"(?<![A-Za-z0-9])CVE-(\d{4})-(\d{4,})(?!\d)", re.IGNORECASE)


def normalize_cve_id(value: Any) -> str | None:
    """Return canonical `CVE-YYYY-NNNN+` or None when malformed."""
    if not isinstance(value, str):
        return None
    s = value.strip().upper().replace("‑", "-").replace("–", "-")
    m = _CVE_FULL.match(s)
    if not m:
        return None
    year = int(m.group(1))
    if year < 1999 or year > _dt.date.today().year + 1:
        return None
    return s


def normalize_cves(values: Iterable[Any]) -> tuple[list[str], int]:
    """Normalise, deduplicate (sorted) and count malformed inputs."""
    seen: set[str] = set()
    bad = 0
    for v in values:
        n = normalize_cve_id(v)
        if n is None:
            bad += 1
        else:
            seen.add(n)
    return sorted(seen), bad


def find_cves(text: str | None) -> list[str]:
    """Extract well-formed CVE ids from free text (normalised, deduplicated, sorted)."""
    if not text:
        return []
    out = {normalize_cve_id(m.group(0)) for m in _CVE_FIND.finditer(text)}
    out.discard(None)
    return sorted(out)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Spec and context
# --------------------------------------------------------------------------
@dataclass
class SourceSpec:
    name: str
    role: str
    urls: list[str]
    license_name: str
    license_url: str
    license_note: str
    description: str = ""

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"{self.name}: bad role {self.role!r}")


@dataclass
class Context:
    spec: SourceSpec
    raw_dir: Path
    upstream: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)
    malformed_cve_ids: int = 0

    def cves(self, values: Iterable[Any]) -> list[str]:
        """Normalise CVE ids, counting malformed ones in the manifest."""
        good, bad = normalize_cves(values)
        self.malformed_cve_ids += bad
        return good

    def log(self, msg: str) -> None:
        print(f"[{self.spec.name}] {msg}", flush=True)


# --------------------------------------------------------------------------
# HTTP with retry
# --------------------------------------------------------------------------
class FetchError(CollectError):
    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


def _backoff(attempt: int) -> float:
    return min(60.0, 2.0 ** attempt)


def http_download(url: str, dest: Path, retries: int = 5, timeout: float = 120.0) -> dict[str, Any]:
    """Stream `url` to `dest`. Retries 429/5xx/transport errors with backoff.

    Returns {url, size, sha256, etag, last_modified}. Raises FetchError.
    """
    import httpx

    dest.parent.mkdir(parents=True, exist_ok=True)
    last = "unknown error"
    for attempt in range(retries):
        try:
            h = hashlib.sha256()
            size = 0
            with httpx.stream("GET", url, follow_redirects=True, timeout=timeout,
                              headers={"User-Agent": USER_AGENT}) as r:
                if r.status_code in (429,) or r.status_code >= 500:
                    last = f"HTTP {r.status_code}"
                    raise httpx.TransportError(last)
                if r.status_code >= 400:
                    raise FetchError(f"GET {url} failed: HTTP {r.status_code}", r.status_code)
                with open(dest, "wb") as f:
                    for chunk in r.iter_bytes(1 << 20):
                        f.write(chunk)
                        h.update(chunk)
                        size += len(chunk)
                return {"url": url, "size": size, "sha256": h.hexdigest(),
                        "etag": r.headers.get("etag"), "last_modified": r.headers.get("last-modified")}
        except FetchError:
            raise
        except Exception as e:  # transport errors, timeouts, 5xx
            last = f"{type(e).__name__}: {e}"
            if attempt < retries - 1:
                wait = _backoff(attempt)
                print(f"  retry {attempt + 1}/{retries - 1} for {url} in {wait:.0f}s ({last})", flush=True)
                time.sleep(wait)
    raise FetchError(f"GET {url} failed after {retries} attempts: {last}")


def http_get_text(url: str, retries: int = 5, timeout: float = 60.0) -> str:
    """GET a small text resource fully in memory (nothing touches disk)."""
    import httpx

    last = "unknown error"
    for attempt in range(retries):
        try:
            r = httpx.get(url, follow_redirects=True, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if r.status_code == 429 or r.status_code >= 500:
                last = f"HTTP {r.status_code}"
            elif r.status_code >= 400:
                raise FetchError(f"GET {url} failed: HTTP {r.status_code}", r.status_code)
            else:
                return r.text
        except FetchError:
            raise
        except httpx.HTTPError as e:
            last = f"{type(e).__name__}: {e}"
        if attempt < retries - 1:
            wait = _backoff(attempt)
            print(f"  retry {attempt + 1}/{retries - 1} for {url} in {wait:.0f}s ({last})", flush=True)
            time.sleep(wait)
    raise FetchError(f"GET {url} failed after {retries} attempts: {last}")


# --------------------------------------------------------------------------
# git helpers (shallow, optionally sparse, .git removed afterwards)
# --------------------------------------------------------------------------
def _run_git(args: list[str], retries: int = 3, cwd: Path | None = None) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    cmd = ["git", "-c", "core.longpaths=true", *args]
    last = ""
    for attempt in range(retries):
        try:
            p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
        except FileNotFoundError as e:
            raise CollectError("git executable not found on PATH") from e
        if p.returncode == 0:
            return p.stdout
        last = (p.stderr or p.stdout).strip()[-500:]
        if attempt < retries - 1:
            wait = _backoff(attempt)
            print(f"  git retry {attempt + 1}/{retries - 1} in {wait:.0f}s ({last[-120:]})", flush=True)
            time.sleep(wait)
    raise CollectError(f"git {' '.join(args[:2])} failed after {retries} attempts: {last}")


def git_ls_remote_head(url: str) -> str:
    out = _run_git(["ls-remote", url, "HEAD"])
    sha = out.split()[0] if out.strip() else ""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise CollectError(f"could not resolve HEAD of {url}")
    return sha


def long_path(path: Path | str) -> str:
    """Windows extended-length form so >260 char paths (deep upstream trees) can be opened."""
    s = os.path.abspath(str(path))
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        s = "\\\\?\\" + s
    return s


def _rmtree(path: Path) -> None:
    def onerr(func, p, _exc):  # read-only pack files on Windows
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if os.path.exists(long_path(path)):
        shutil.rmtree(long_path(path), onerror=onerr)


def git_clone(url: str, dest: Path, sparse: bool) -> None:
    """Shallow clone into `dest` (must not exist). With sparse=True only root files are checked out."""
    _rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--depth", "1", "--quiet"]
    if sparse:
        args += ["--filter=blob:none", "--sparse"]
    _run_git([*args, url, str(dest)])


def git_sparse_set(repo: Path, paths: list[str]) -> None:
    _run_git(["sparse-checkout", "set", "--cone", *paths], cwd=repo)


def git_head(repo: Path) -> str:
    return _run_git(["rev-parse", "HEAD"], cwd=repo).strip()


def git_finish(repo: Path) -> None:
    """Drop .git so the raw directory holds only upstream files."""
    _rmtree(repo / ".git")


# --------------------------------------------------------------------------
# File helpers
# --------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def dir_stats(path: Path) -> tuple[int, int]:
    n = total = 0
    for root, _d, files in os.walk(long_path(path)):
        for fn in files:
            n += 1
            total += os.path.getsize(os.path.join(root, fn))
    return n, total


def utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def write_jsonl(path: Path, records: Iterable[dict]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
def _manifest_base(spec: SourceSpec, ctx: Context | None, retrieved: str) -> dict[str, Any]:
    return {
        "source": spec.name,
        "role": spec.role,
        "description": spec.description,
        "upstream_urls": spec.urls,
        "upstream_version": dict(ctx.upstream) if ctx else {},
        "retrieved_at_utc": retrieved,
        "license": {"name": spec.license_name, "url": spec.license_url, "permits": spec.license_note},
        "collector_version": COLLECTOR_VERSION,
    }


def run_source(module: Any, out_root: Path, date: str | None = None) -> dict[str, Any]:
    """Run one collector module and publish `<out_root>/<source>/<date>/`. Returns the manifest."""
    spec: SourceSpec = module.SPEC
    date = date or utc_today()
    src_dir = out_root / spec.name
    final = src_dir / date
    tmp = src_dir / f".{date}.tmp"
    _rmtree(tmp)
    raw = tmp / "raw"
    raw.mkdir(parents=True)
    ctx = Context(spec=spec, raw_dir=raw)
    retrieved = utc_now_iso()
    try:
        try:
            records_iter = module.collect(ctx)
            n = write_jsonl(tmp / "records.jsonl", records_iter)
            manifest = _manifest_base(spec, ctx, retrieved)
            manifest.update({
                "status": "ok",
                "reason": None,
                "record_count": n,
                "malformed_cve_ids_dropped": ctx.malformed_cve_ids,
                "records_sha256": sha256_file(tmp / "records.jsonl"),
                "extra": ctx.extra,
            })
            if n == 0:
                raise CollectError(f"{spec.name}: collector produced 0 records (parser or upstream broke)")
        except SourceUnavailable as e:
            ctx.log(f"{e.status}: {e.reason}")
            manifest = _manifest_base(spec, ctx, retrieved)
            manifest.update({
                "status": e.status, "reason": e.reason, "record_count": 0,
                "malformed_cve_ids_dropped": 0, "records_sha256": None, "extra": ctx.extra,
            })
        nfiles, nbytes = dir_stats(raw)
        manifest["raw_file_count"] = nfiles
        manifest["raw_bytes"] = nbytes
        if nfiles <= 20:
            manifest["raw_files"] = sorted(
                ({"path": str(p.relative_to(raw)).replace("\\", "/"), "bytes": p.stat().st_size,
                  "sha256": sha256_file(p)} for p in raw.rglob("*") if p.is_file()),
                key=lambda d: d["path"])
        (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                                           encoding="utf-8", newline="\n")
        _rmtree(final)
        os.replace(tmp, final)
        (src_dir / "LATEST").write_text(date + "\n", encoding="utf-8", newline="\n")
        return manifest
    except BaseException:
        _rmtree(tmp)
        raise


def default_out_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "sources"


def main_guard(fn):  # pragma: no cover
    try:
        return fn()
    except CollectError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
