"""Build the C1 CVE document store.

    python -m threat_retrieval_engine.store.build --feeds <feeds dir> --sources <data/sources> --out <data/store>
        [--workers N] [--v1-corpus <corpus_store.db>] [--previous <build dir>] [--build-id ID]

Inputs (read only):
  <feeds>/nvd_cve_data/*.json              NVD CVE API 2.0 yearly files (streamed)
  <feeds>/cvelistV5-live/cves/<year>/...   CVE List V5 records
  <feeds>/cisa_kev-*.csv                   CISA KEV catalogue (latest by name)
  <feeds>/epss_scores-*.csv                EPSS scores (latest by name)
  <sources>/{exploitdb,metasploit_modules,nuclei_templates,cwe_catalog}/<LATEST>/records.jsonl

Output: <out>/<build_id>/{store.sqlite, manifest.json}, build_id = <UTC timestamp>-<short input hash>, and
<out>/LATEST naming the newest successful build. The build is written to a temporary directory and only
renamed into place after the reconciliation check passes: for every input feed, records read must equal
records stored or merged plus records rejected with a reason. Any mismatch fails the build (exit 1).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import aliases as A
from . import feeds as F
from . import similar
from .merge import build_row, content_hash, pick_cvelist, pick_nvd
from .schema import CVE_COLUMNS, DDL, JSON_COLUMNS, STORE_VERSION
from .text import alias_norm, cve_sort_key, name_key, slug_tokens

REPO_ROOT = Path(__file__).resolve().parents[2]
ALIAS_INPUTS = ("exploitdb", "metasploit_modules", "nuclei_templates")
POC_INPUT = "poc_in_github"
CWE_INPUT = "cwe_catalog"
READ_THREADS = 12
VERDICTS_PATH = Path(__file__).resolve().parent / "data" / "nickname_verdicts.jsonl"
WORD_RE = re.compile(r"[A-Za-z0-9]+")


class ReconciliationError(RuntimeError):
    pass


# =========================================================================== helpers
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _jdump(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def _year(cid: str) -> int:
    return int(cid.split("-")[1])


def latest_source_dir(sources: Path, name: str) -> Path:
    if name in A.QUERY_SIDE_SOURCES:
        raise ValueError(f"{name} is a benchmark query source and is never read by the store build")
    lf = sources / name / "LATEST"
    if not lf.is_file():
        raise FileNotFoundError(f"source {name} not collected: {lf} missing")
    d = sources / name / lf.read_text(encoding="utf-8").strip()
    if not (d / "records.jsonl").is_file():
        raise FileNotFoundError(f"{d / 'records.jsonl'} missing")
    return d


def read_jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if line:
                yield i, json.loads(line)


def code_fingerprint() -> dict:
    files = sorted(Path(__file__).resolve().parent.glob("*.py"))
    h = hashlib.sha256()
    for p in files:
        h.update(p.name.encode())
        h.update(p.read_bytes())
    commit = F.git_head(REPO_ROOT)
    return {"store_package_sha256": h.hexdigest(), "git_commit": commit, "store_version": STORE_VERSION}


# =========================================================================== inputs
def resolve_inputs(feeds: Path, sources: Path) -> dict:
    nvd_dir = feeds / "nvd_cve_data"
    nvd_files = sorted(nvd_dir.glob("*.json"))
    if not nvd_files:
        raise FileNotFoundError(f"no NVD yearly files in {nvd_dir}")
    cl_root = feeds / "cvelistV5-live" / "cves"
    if not cl_root.is_dir():
        raise FileNotFoundError(f"CVE List tree not found: {cl_root}")
    kev = F.latest_dated(feeds, "cisa_kev")
    epss = F.latest_dated(feeds, "epss_scores")
    if kev is None or epss is None:
        raise FileNotFoundError("KEV or EPSS CSV missing in feeds dir")
    alias_dirs = {n: latest_source_dir(sources, n) for n in ALIAS_INPUTS + (POC_INPUT,)}
    cwe_dir = latest_source_dir(sources, CWE_INPUT)
    for d in list(alias_dirs.values()) + [cwe_dir]:
        if "benchmark" in {p.lower() for p in d.resolve().parts}:
            raise ValueError(f"refusing to read benchmark data as a store input: {d}")
    return {"nvd_files": nvd_files, "cl_root": cl_root, "kev": kev, "epss": epss, "alias_dirs": alias_dirs,
            "cwe_dir": cwe_dir}


def year_groups(nvd_files: list[Path], cl_root: Path, extra_ids: set[str]) -> list[dict]:
    """One job per NVD file / CVE ID year. The smallest NVD file year holds every earlier ID year too."""
    nvd_years = sorted(int(p.stem) for p in nvd_files if p.stem.isdigit())
    if len(nvd_years) != len(nvd_files):
        raise ValueError("NVD files must be named <year>.json")
    first = nvd_years[0]

    def gkey(y: int) -> int:
        return first if y <= first else y

    cl_years = sorted(int(d.name) for d in cl_root.iterdir() if d.is_dir() and d.name.isdigit())
    keys = sorted({gkey(y) for y in nvd_years + cl_years + [_year(c) for c in extra_ids]})
    groups = []
    for k in keys:
        years = sorted({y for y in cl_years + [_year(c) for c in extra_ids] + nvd_years if gkey(y) == k} | {k})
        groups.append({
            "key": k, "years": years,
            "nvd_files": [str(p) for p in nvd_files if p.stem.isdigit() and int(p.stem) == k],
            "cl_dirs": [str(cl_root / str(y)) for y in years if (cl_root / str(y)).is_dir()],
        })
    return groups


def alias_prepass(alias_dirs: dict[str, Path], kev_rows: dict[str, dict]) -> tuple[dict, dict, dict, dict]:
    """Raw alias candidates from the exploit sources and KEV names, grouped by CVE, plus the PoC-in-GitHub
    repositories by CVE (weak evidence, used inside the workers).

    Returns (candidates by CVE, PoC repos by CVE, per-source record ledger {source: {record_id: [cves]}},
    input info)."""
    by_cve: dict[str, list[A.Candidate]] = defaultdict(list)
    ledger: dict[str, dict[str, list[str]]] = {}
    pocs: dict[str, list[tuple[str, str]]] = {}
    snippets: dict[tuple[str, str], str] = {}
    info = {}
    for name, d in alias_dirs.items():
        led: dict[str, list[str]] = {}
        man = json.loads((d / "manifest.json").read_text(encoding="utf-8")) if (d / "manifest.json").is_file() else {}
        if man.get("role") not in (None, "expansion"):
            raise ValueError(f"{name} has role {man.get('role')!r}; only expansion sources feed aliases")
        n = 0
        for line_no, r in read_jsonl(d / "records.jsonl"):
            n += 1
            if name == POC_INPUT:
                rid = r.get("full_name") or f"line{line_no}"
                rid = rid if rid not in led else f"{rid}@line{line_no}"
                cves = sorted({c for c in (F.normalize_cve_id(x) for x in [r.get("cve_id")]) if c})
                led[rid] = cves
                for c in cves:
                    pocs.setdefault(c, []).append((rid, r.get("description") or ""))
                snippets[(name, rid)] = (rid + " " + (r.get("description") or "")).strip()[:300]
                continue
            if name == "exploitdb":
                rid, title, desc = str(r.get("edb_id")), r.get("title") or "", ""
            elif name == "metasploit_modules":
                rid, title, desc = r.get("module_path") or f"line{line_no}", r.get("name") or "", r.get("description") or ""
            else:
                rid, title, desc = r.get("template_id") or r.get("path") or f"line{line_no}", r.get("name") or "", ""
            rid = rid if rid not in led else f"{rid}@line{line_no}"
            cves = sorted({c for c in (F.normalize_cve_id(x) for x in r.get("cve_ids") or []) if c})
            led[rid] = cves
            snippets[(name, rid)] = title[:300]
            for c in A.candidates_from_record(name, rid, cves, title, desc):
                by_cve[c.cve_id].append(c)
        ledger[name] = led
        info[name] = {"dir": str(d), "records": n, "records_sha256": sha256_file(d / "records.jsonl"),
                      "role": man.get("role"), "licence": (man.get("license") or {}).get("name"),
                      "retrieved_at_utc": man.get("retrieved_at_utc"), "upstream_version": man.get("upstream_version")}
    for cid, k in kev_rows.items():
        for c in A.candidates_from_record("kev", cid, [cid], k.get("vulnerability_name") or ""):
            by_cve[cid].append(c)
        snippets[("kev", cid)] = (k.get("vulnerability_name") or "")[:300]
    info["_snippets"] = snippets
    return dict(by_cve), pocs, ledger, info


def load_cwe_names(cwe_dir: Path) -> tuple[dict[str, str], dict]:
    names = {}
    n = 0
    for _, r in read_jsonl(cwe_dir / "records.jsonl"):
        n += 1
        if r.get("cwe_id") and r.get("name"):
            names[r["cwe_id"]] = r["name"]
    man = json.loads((cwe_dir / "manifest.json").read_text(encoding="utf-8"))
    info = {"dir": str(cwe_dir), "records": n, "records_sha256": sha256_file(cwe_dir / "records.jsonl"),
            "cwe_version": (man.get("upstream_version") or {}).get("cwe_version"),
            "licence": (man.get("license") or {}).get("name"), "licence_url": (man.get("license") or {}).get("url"),
            "retrieved_at_utc": man.get("retrieved_at_utc")}
    return names, info


# =========================================================================== worker
def _read_bytes(p: str) -> tuple[str, bytes | None, str | None]:
    try:
        with open(p, "rb") as f:
            return p, f.read(), None
    except OSError as e:
        return p, None, str(e)[:120]


def _cand_tuple(c: A.Candidate) -> tuple:
    return (c.cve_id, c.alias, c.norm, c.kind, c.source, c.record_id, c.position, c.record_cves)


def process_group(job: dict) -> dict:
    """Parse one year group of NVD and CVE List records, merge every CVE of the group into its row and write
    the rows to a shard database. Runs in a worker process."""
    t0 = time.time()
    group_years = set(job["years"])
    rejects: list[F.Reject] = []
    counts: dict[str, Counter] = {"nvd": Counter(), "cve_list": Counter()}
    nvd_by_id: dict[str, list[dict]] = defaultdict(list)
    cl_by_id: dict[str, list[dict]] = defaultdict(list)
    inputs: list[dict] = []
    vocab: set[str] = set()
    vocab_tokens: set[str] = set()

    # ---- NVD
    for fp in job["nvd_files"]:
        p = Path(fp)
        h = hashlib.sha256()
        n = 0
        for idx, value, raw in F.iter_json_array(p, "vulnerabilities", h):
            n += 1
            if value is None:
                rejects.append(F.Reject("nvd", f"{p.name}#{idx}", "unparseable_json", raw or ""))
                continue
            rec, rej = F.compact_nvd(value, raw, p.name, idx)
            if rej:
                rejects.append(rej)
                continue
            if _year(rec["id"]) not in group_years:
                rejects.append(F.Reject("nvd", f"{p.name}#{idx}", "misfiled_cve_year", rec["id"]))
                continue
            nvd_by_id[rec["id"]].append(rec)
            for m in rec["cpe"]:
                parts = F.cpe_parts(m["criteria"])
                if parts:
                    vocab.add(name_key(parts[1]))
                    vocab.add(name_key(parts[2]))
                    vocab_tokens.update(slug_tokens(parts[1]))
                    if parts[0] == "o":  # operating systems and distributions
                        vocab_tokens.update(slug_tokens(parts[2]))
        counts["nvd"]["read"] += n
        inputs.append({"name": f"nvd_cve_data/{p.name}", "bytes": p.stat().st_size, "sha256": h.hexdigest(),
                       "records": n})

    # ---- CVE List
    root = Path(job["cl_root"])
    cl_hash_entries: list[str] = []
    def handle(p: str, raw: bytes | None, err: str | None) -> None:
        rel = Path(p).relative_to(root).as_posix()
        counts["cve_list"]["read"] += 1
        if not rel.rsplit("/", 1)[-1].upper().startswith("CVE-") or not rel.lower().endswith(".json"):
            rejects.append(F.Reject("cve_list", rel, "not_a_cve_record_file"))
            return
        if raw is None:
            rejects.append(F.Reject("cve_list", rel, "unreadable_file", err or ""))
            return
        sha = hashlib.sha256(raw).hexdigest()
        cl_hash_entries.append(f"{rel}\t{sha}")
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            rejects.append(F.Reject("cve_list", rel, "unparseable_json", str(e)[:120]))
            return
        rec, rej = F.compact_cvelist(data, rel, sha)
        if rej:
            rejects.append(rej)
            return
        if _year(rec["id"]) not in group_years or rel.split("/", 1)[0] != str(_year(rec["id"])):
            rejects.append(F.Reject("cve_list", rel, "misfiled_cve_year", rec["id"]))
            return
        cl_by_id[rec["id"]].append(rec)

    with ThreadPoolExecutor(job["read_threads"]) as ex:
        for d in job["cl_dirs"]:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
            loose = [e.path for e in entries if e.is_file()]
            if loose:
                for p, raw, err in ex.map(_read_bytes, loose):
                    handle(p, raw, err)
            for bucket in (e for e in entries if e.is_dir()):
                paths = sorted(e.path for e in os.scandir(bucket.path) if e.is_file())
                for p, raw, err in ex.map(_read_bytes, paths, chunksize=16):
                    handle(p, raw, err)
    t_parse = time.time() - t0

    # ---- merge
    kev: dict[str, dict] = job["kev"]
    epss: dict[str, tuple[float, float]] = job["epss"]
    ids = sorted(set(nvd_by_id) | set(cl_by_id) | set(kev) | set(epss), key=cve_sort_key)
    ctx = {"cwe_names": job["cwe_names"], "kev_file": job["kev_file"], "epss_file": job["epss_file"],
           "epss_meta": job["epss_meta"], "store_version": STORE_VERSION}
    pre_cands: dict[str, list[tuple]] = job["alias_candidates"]
    shard = sqlite3.connect(job["shard"])
    shard.execute("PRAGMA journal_mode=OFF")
    shard.execute("PRAGMA synchronous=OFF")
    cols = [c for c in CVE_COLUMNS if c not in ("content_hash", "similar_group")]
    shard.execute(f"CREATE TABLE cve ({', '.join(chr(34) + c + chr(34) for c in cols)})")
    shard.execute("CREATE TABLE sig (cve_id TEXT, exact TEXT, sig BLOB)")
    shard.execute("CREATE TABLE v1side (cve_id TEXT, nvd_desc TEXT)")
    insert = f"INSERT INTO cve VALUES ({', '.join('?' * len(cols))})"
    decisions: list[tuple] = []
    domain_info: dict[str, list[int]] = {}
    batch, sigs, v1rows = [], [], []
    nvd_conflicts = 0
    for cid in ids:
        nvd, nvd_drop = pick_nvd(nvd_by_id.get(cid, []))
        cl, cl_drop = pick_cvelist(cl_by_id.get(cid, []))
        for r, why in nvd_drop:
            rejects.append(F.Reject("nvd", f"{r['file']}#{r['index']}", why, cid))
        for r, why in cl_drop:
            rejects.append(F.Reject("cve_list", r["path"], why, cid))
        if nvd:
            counts["nvd"]["stored"] += 1
        if cl:
            counts["cve_list"]["stored"] += 1
        row, side = build_row(cid, nvd, cl, kev.get(cid), epss.get(cid), ctx)
        nvd_conflicts += "conflicts" in row["provenance"]
        batch.append(tuple(_jdump(row[c]) if c in JSON_COLUMNS and row[c] is not None else row[c] for c in cols))
        if row["searchable"]:
            sigs.append((cid, similar.exact_key(row["description"]), similar.signature(row["description"])))
        if nvd:
            v1rows.append((cid, nvd.get("desc_en") or ""))
        # alias candidates for this CVE: exploit sources and KEV (pre-pass), CNA title, own description
        cands = [A.Candidate(*t) for t in pre_cands.get(cid, [])]
        if side["title"]:
            cands += A.candidates_from_record("cve_list", f"{cid}#title", [cid], side["title"])
        desc_c = A.description_candidates(cid, side["desc_texts"])
        cands += desc_c
        if cands:
            own = side["own_names"]
            own_tokens = A.own_name_tokens(own)
            own_keys = frozenset(name_key(x) for x in own) | frozenset(alias_norm(x) for x in own)
            desc_nicks = frozenset(c.norm for c in desc_c)
            strong_keep = set()
            for c in cands:
                d = A.local_decision(c, own_tokens, own_keys, side["desc_texts"], desc_nicks)
                decisions.append((_cand_tuple(c), d))
                if d == "keep" and c.kind == "nickname":
                    strong_keep.add(c.norm)
        else:
            own_tokens = own_keys = desc_nicks = None
            strong_keep = set()
        # weak evidence: PoC-in-GitHub repositories and the CVE's own reference URLs, corroborated only
        ref_urls = [r["url"] for r in row["references"]]
        for dom in {A.evidence_unit(A.Candidate(cid, "", "", "", "cve_references", u, "", 1)) for u in ref_urls}:
            y = _year(cid)
            e = domain_info.get(dom[4:])
            if e is None:
                domain_info[dom[4:]] = [1, y, y]
            else:
                e[0] += 1
                e[1] = min(e[1], y)
                e[2] = max(e[2], y)
        weak = A.weak_candidates(cid, ref_urls, job["pocs"].get(cid, []), frozenset(strong_keep),
                                 (row["assigner"] or {}).get("short_name") or "")
        if weak:
            if own_tokens is None:
                own = side["own_names"]
                own_tokens = A.own_name_tokens(own)
                own_keys = frozenset(name_key(x) for x in own) | frozenset(alias_norm(x) for x in own)
                desc_nicks = frozenset()
            for c in weak:
                decisions.append((_cand_tuple(c), A.local_decision(c, own_tokens, own_keys, side["desc_texts"],
                                                                     desc_nicks)))
        if len(batch) >= 5000:
            shard.executemany(insert, batch)
            shard.executemany("INSERT INTO sig VALUES (?,?,?)", sigs)
            shard.executemany("INSERT INTO v1side VALUES (?,?)", v1rows)
            batch, sigs, v1rows = [], [], []
    if batch:
        shard.executemany(insert, batch)
        shard.executemany("INSERT INTO sig VALUES (?,?,?)", sigs)
        shard.executemany("INSERT INTO v1side VALUES (?,?)", v1rows)
    shard.commit()
    shard.close()
    cl_hash_entries.sort()
    return {
        "key": job["key"], "ids": len(ids), "rejects": [asdict(r) for r in rejects],
        "counts": {k: dict(v) for k, v in counts.items()}, "inputs": inputs,
        "cl_files": len(cl_hash_entries),
        "cl_hash": hashlib.sha256("\n".join(cl_hash_entries).encode("utf-8")).hexdigest(),
        "alias_decisions": decisions, "vocab": sorted(v for v in vocab if v),
        "vocab_tokens": sorted(v for v in vocab_tokens if v), "domain_info": domain_info,
        "state_conflicts": nvd_conflicts,
        "seconds": {"parse": round(t_parse, 1), "total": round(time.time() - t0, 1)},
    }


# =========================================================================== master
def _ledger_rejects(ledger: dict[str, dict[str, list[str]]], stored: dict[str, set[str]], universe: set[str],
                    reasons_by_record: dict[tuple[str, str], str]) -> tuple[list[F.Reject], dict]:
    out, recon = [], {}
    for src, recs in ledger.items():
        ok = rej = 0
        for rid, cves in recs.items():
            if rid in stored.get(src, set()):
                ok += 1
                continue
            rej += 1
            if not cves:
                reason = "no_valid_cve_id"
            elif not any(c in universe for c in cves):
                reason = "cve_not_in_universe"
            else:
                default = "no_corroborated_alias" if src == POC_INPUT else "no_alias_candidate"
                reason = reasons_by_record.get((src, rid), default)
            out.append(F.Reject(src, rid, reason, ",".join(cves[:5])))
        recon[src] = {"read": len(recs), "stored_or_merged": ok, "rejected": rej}
    return out, recon


def build(feeds: Path, sources: Path, out_root: Path, workers: int = 6, v1_corpus: Path | None = None,
          previous: Path | None = None, build_id: str | None = None, log=print,
          verdicts_path: Path | None = None) -> Path:
    t_start = time.time()
    verdicts_path = Path(verdicts_path) if verdicts_path is not None else VERDICTS_PATH
    if not verdicts_path.is_file():
        raise FileNotFoundError(f"nickname verdict file missing: {verdicts_path}")
    timings: dict[str, float] = {}
    started = datetime.now(timezone.utc)
    inp = resolve_inputs(feeds, sources)
    out_root.mkdir(parents=True, exist_ok=True)
    tmp = out_root / f".tmp-{started.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "shards").mkdir(parents=True)
    try:
        # ---------------------------------------------------------- pre-pass
        t = time.time()
        kev_rows, kev_rejects, kev_read = F.read_kev(inp["kev"])
        epss_rows, epss_meta, epss_rejects, epss_read = F.read_epss(inp["epss"])
        cwe_names, cwe_info = load_cwe_names(inp["cwe_dir"])
        alias_by_cve, poc_by_cve, ledger, alias_info = alias_prepass(inp["alias_dirs"], kev_rows)
        groups = year_groups(inp["nvd_files"], inp["cl_root"], set(kev_rows) | set(epss_rows))
        timings["prepass_s"] = round(time.time() - t, 1)
        log(f"pre-pass: KEV {len(kev_rows)}, EPSS {len(epss_rows)}, CWE names {len(cwe_names)}, "
            f"alias candidates for {len(alias_by_cve)} CVEs, {len(groups)} year groups ({timings['prepass_s']}s)")

        # ---------------------------------------------------------- workers
        t = time.time()
        jobs = []
        gkey_of_year = {y: g["key"] for g in groups for y in g["years"]}
        kev_by_g: dict[int, dict] = defaultdict(dict)
        for c, r in kev_rows.items():
            kev_by_g[gkey_of_year[_year(c)]][c] = r
        epss_by_g: dict[int, dict] = defaultdict(dict)
        for c, r in epss_rows.items():
            epss_by_g[gkey_of_year[_year(c)]][c] = r
        alias_by_g: dict[int, dict] = defaultdict(dict)
        for c, cs in alias_by_cve.items():
            g = gkey_of_year.get(_year(c))
            if g is not None:
                alias_by_g[g][c] = [_cand_tuple(x) for x in cs]
        poc_by_g: dict[int, dict] = defaultdict(dict)
        for c, ps in poc_by_cve.items():
            g = gkey_of_year.get(_year(c))
            if g is not None:
                poc_by_g[g][c] = ps
        for g in groups:
            jobs.append({**g, "cl_root": str(inp["cl_root"]), "kev": kev_by_g[g["key"]], "epss": epss_by_g[g["key"]],
                         "pocs": poc_by_g[g["key"]],
                         "epss_meta": epss_meta, "cwe_names": cwe_names, "alias_candidates": alias_by_g[g["key"]],
                         "kev_file": inp["kev"].name, "epss_file": inp["epss"].name,
                         "shard": str(tmp / "shards" / f"{g['key']}.sqlite"), "read_threads": READ_THREADS})
        # biggest first for load balance
        jobs.sort(key=lambda j: -sum(Path(p).stat().st_size for p in j["nvd_files"]))
        results = []
        if workers > 1:
            with ProcessPoolExecutor(max_workers=workers) as ex:
                for res in ex.map(process_group, jobs):
                    log(f"  group {res['key']}: {res['ids']} CVEs, {res['seconds']}")
                    results.append(res)
        else:
            for j in jobs:
                res = process_group(j)
                log(f"  group {res['key']}: {res['ids']} CVEs, {res['seconds']}")
                results.append(res)
        results.sort(key=lambda r: r["key"])
        timings["workers_s"] = round(time.time() - t, 1)

        # ---------------------------------------------------------- assemble store
        t = time.time()
        db_path = tmp / "store.sqlite"
        db = sqlite3.connect(db_path)
        db.execute("PRAGMA journal_mode=OFF")
        db.execute("PRAGMA synchronous=OFF")
        db.executescript(DDL)
        cols = [c for c in CVE_COLUMNS if c not in ("content_hash", "similar_group")]
        qcols = ", ".join(f'"{c}"' for c in cols)
        for res in results:
            shard = tmp / "shards" / f"{res['key']}.sqlite"
            db.execute("ATTACH DATABASE ? AS s", (str(shard),))
            db.execute(f"INSERT INTO cve ({qcols}, content_hash) SELECT {qcols}, '' FROM s.cve")
            db.commit()
            db.execute("DETACH DATABASE s")
        universe = {r[0] for r in db.execute("SELECT cve_id FROM cve")}
        timings["assemble_s"] = round(time.time() - t, 1)

        # ---------------------------------------------------------- aliases
        t = time.time()
        vocab = frozenset(v for res in results for v in res["vocab"])
        vocab_tokens = frozenset(v for res in results for v in res["vocab_tokens"])
        decisions = [(A.Candidate(*ct), d) for res in results for ct, d in res["alias_decisions"]]
        domain_info: dict[str, list[int]] = {}
        for res in results:
            for dom, (n, lo, hi) in res["domain_info"].items():
                e = domain_info.setdefault(dom, [0, lo, hi])
                e[0] += n
                e[1], e[2] = min(e[1], lo), max(e[2], hi)
        # corpus dictionary: candidate words written in lower case in at least DICTIONARY_MIN_DOCS descriptions
        words = A.candidate_words(decisions)
        lower_docs: Counter = Counter()
        for (desc,) in db.execute("SELECT description FROM cve WHERE searchable = 1"):
            for w in {t for t in WORD_RE.findall(desc) if t.islower()} & words:
                lower_docs[w] += 1
        voc = A.Vocabulary(dictionary=frozenset(w for w, n in lower_docs.items() if n >= A.DICTIONARY_MIN_DOCS),
                           names=vocab, name_tokens=vocab_tokens)
        sel = A.select(decisions, voc, domain_info)
        del lower_docs
        verdicts = A.load_verdicts(verdicts_path)
        status = A.apply_verdicts(sel.groups, verdicts)
        served = [c for g in sel.groups if status[(g.norm, g.cve_ids)] == "accepted" for c in g.rows]
        alias_rows = sel.rows + [c for c in served if c.cve_id in universe]
        db.executemany("INSERT OR IGNORE INTO aliases VALUES (?,?,?,?,?,?,?,?)",
                       [(c.cve_id, c.alias, c.norm, c.kind, c.source, c.record_id, c.position, c.record_cves)
                        for c in alias_rows if c.cve_id in universe])
        snippets = alias_info.pop("_snippets")
        cand_rows = []
        for g in sel.groups:
            gcves = ",".join(g.cve_ids)
            for c in g.rows:
                cand_rows.append((g.norm, g.alias, gcves, g.evidence_sha256, status[(g.norm, g.cve_ids)], c.cve_id,
                                  c.alias, c.source, c.record_id, c.position, c.record_cves,
                                  _snippet(c, snippets, db)))
        db.executemany("INSERT OR IGNORE INTO alias_candidates VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", cand_rows)
        # served names column: accepted nicknames and bulletin IDs, best supported first
        per_cve: dict[str, dict[str, list]] = defaultdict(dict)
        display = {g.norm: g.alias for g in sel.groups}
        for c in alias_rows:
            if c.kind in ("nickname", "advisory_id"):
                e = per_cve[c.cve_id].setdefault(c.norm, [0.0, display.get(c.norm, c.alias)])
                e[0] += 1.0 / max(1, c.record_cves)
        db.executemany("UPDATE cve SET aliases = ? WHERE cve_id = ?",
                       [("; ".join(name for _, (w, name) in sorted(d.items(), key=lambda kv: (-kv[1][0], kv[0]))), cid)
                        for cid, d in per_cve.items()])
        db.commit()
        stored_records: dict[str, set[str]] = defaultdict(set)
        for c in alias_rows:
            stored_records[c.source].add(c.record_id)
        for g in sel.groups:  # candidate evidence is stored (alias_candidates), served or not
            for c in g.rows:
                stored_records[c.source].add(c.record_id)
        record_reason: dict[tuple[str, str], str] = {}
        for c, d in decisions:
            key = (c.source, c.record_id)
            if d != "keep":
                record_reason.setdefault(key, f"no_alias_accepted:{d}")
            else:
                record_reason.setdefault(key, f"no_alias_accepted:{sel.rejected_names.get(c.norm, 'corpus_rules')}")
        vet = Counter(status.values())
        vetting = {"verdict_file": str(verdicts_path), "verdict_file_sha256": sha256_file(verdicts_path),
                   "verdicts": len(verdicts), "candidate_groups": len(sel.groups),
                   "candidate_rows": len(cand_rows), "accepted": vet["accepted"], "rejected": vet["rejected"],
                   "pending": vet["pending"], "stale": vet["stale"],
                   "verdicts_without_candidate": sum(1 for k in verdicts if k not in status)}
        alias_rejects, alias_recon = _ledger_rejects(ledger, stored_records, universe, record_reason)
        timings["aliases_s"] = round(time.time() - t, 1)
        log(f"aliases: {len(alias_rows)} served rows; {len(sel.groups)} nickname candidate groups; vetting {vetting}; "
            f"reasons {sel.reasons}")

        # ---------------------------------------------------------- similar groups
        t = time.time()
        sig_items = []
        for res in results:
            sc = sqlite3.connect(tmp / "shards" / f"{res['key']}.sqlite")
            sig_items.extend(sc.execute("SELECT cve_id, exact, sig FROM sig").fetchall())
            sc.close()
        descs = dict(db.execute("SELECT cve_id, description FROM cve WHERE searchable = 1"))
        groups_map, sim_stats = similar.group(sig_items, descs.__getitem__)
        db.executemany("UPDATE cve SET similar_group = ? WHERE cve_id = ?", [(g, c) for c, g in groups_map.items()])
        db.commit()
        del sig_items, descs
        timings["similar_s"] = round(time.time() - t, 1)
        log(f"similar groups: {sim_stats['groups']} groups, {sim_stats['cves_in_groups']} CVEs")

        # ---------------------------------------------------------- content hashes
        t = time.time()
        hashes = []
        for row in db.execute('SELECT cve_id, searchable, title, description, vendor_product, weakness, aliases, '
                              'kev_text, dense_text FROM cve'):
            d = dict(zip(("cve_id", "searchable", "title", "description", "vendor_product", "weakness", "aliases",
                          "kev_text", "dense_text"), row))
            hashes.append((content_hash(d), d["cve_id"]))
        db.executemany("UPDATE cve SET content_hash = ? WHERE cve_id = ?", hashes)
        db.commit()
        del hashes
        timings["hash_s"] = round(time.time() - t, 1)

        # ---------------------------------------------------------- rejected records + reconciliation
        all_rejects = [F.Reject(**r) for res in results for r in res["rejects"]]
        all_rejects += kev_rejects + epss_rejects + alias_rejects
        dup_keys = Counter((r.source, r.record_id) for r in all_rejects)
        if any(v > 1 for v in dup_keys.values()):
            raise ReconciliationError(f"a record was rejected twice: {[k for k, v in dup_keys.items() if v > 1][:5]}")
        db.executemany("INSERT INTO rejected_records VALUES (?,?,?,?)",
                       [(r.source, r.record_id, r.reason, r.detail) for r in all_rejects])
        db.commit()
        rej_by_src = Counter(r.source for r in all_rejects)
        recon: dict[str, dict] = {}
        nvd_read = sum(r["counts"]["nvd"].get("read", 0) for r in results)
        nvd_stored = sum(r["counts"]["nvd"].get("stored", 0) for r in results)
        cl_read = sum(r["counts"]["cve_list"].get("read", 0) for r in results)
        cl_stored = sum(r["counts"]["cve_list"].get("stored", 0) for r in results)
        kev_stored = db.execute("SELECT COUNT(*) FROM cve WHERE kev_listed = 1").fetchone()[0]
        epss_stored = db.execute("SELECT COUNT(*) FROM cve WHERE epss IS NOT NULL").fetchone()[0]
        recon["nvd"] = {"read": nvd_read, "stored_or_merged": nvd_stored, "rejected": rej_by_src["nvd"]}
        recon["cve_list"] = {"read": cl_read, "stored_or_merged": cl_stored, "rejected": rej_by_src["cve_list"]}
        recon["kev"] = {"read": kev_read, "stored_or_merged": kev_stored, "rejected": rej_by_src["kev"]}
        recon["epss"] = {"read": epss_read, "stored_or_merged": epss_stored, "rejected": rej_by_src["epss"]}
        recon.update(alias_recon)
        for v in recon.values():
            v["unexplained"] = v["read"] - v["stored_or_merged"] - v["rejected"]
        bad = {k: v for k, v in recon.items() if v["unexplained"] != 0}
        if bad:
            raise ReconciliationError(f"reconciliation failed: {bad}")
        n_rows = db.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        if n_rows != len(universe):
            raise ReconciliationError("row count differs from the CVE universe")

        # ---------------------------------------------------------- reports
        t = time.time()
        from .report import store_report
        report = store_report(db, kev_rows, epss_rows)
        report["aliases"] = alias_report(db, sel)
        report["nickname_vetting"] = vetting
        report["similar_groups"] = sim_stats
        report["rejected_by_source_and_reason"] = {
            f"{s}/{r}": n for (s, r), n in sorted(Counter((x.source, x.reason) for x in all_rejects).items())}
        report["state_conflicts_cve_list_vs_nvd"] = sum(r["state_conflicts"] for r in results)
        changes = None
        if previous is not None:
            changes = record_changes(db, previous)
        timings["report_s"] = round(time.time() - t, 1)

        # ---------------------------------------------------------- identity, manifest
        inputs = {
            "nvd": [i for res in results for i in res["inputs"]],
            "cve_list": {"root": str(inp["cl_root"]), "git_commit": F.git_head(inp["cl_root"].parent),
                         "files": sum(r["cl_files"] for r in results),
                         "content_sha256": hashlib.sha256("".join(r["cl_hash"] for r in results).encode()).hexdigest()},
            "kev": {"file": inp["kev"].name, "sha256": sha256_file(inp["kev"]), "bytes": inp["kev"].stat().st_size,
                    "records": kev_read},
            "epss": {"file": inp["epss"].name, "sha256": sha256_file(inp["epss"]), "bytes": inp["epss"].stat().st_size,
                     "records": epss_read, **epss_meta},
            "alias_sources": alias_info,
            "cwe_catalog": cwe_info,
        }
        ih = hashlib.sha256(json.dumps(
            {"nvd": [(i["name"], i["sha256"]) for i in inputs["nvd"]], "cve_list": inputs["cve_list"]["content_sha256"],
             "kev": inputs["kev"]["sha256"], "epss": inputs["epss"]["sha256"],
             "alias": {k: v["records_sha256"] for k, v in alias_info.items()}, "cwe": cwe_info["records_sha256"]},
            sort_keys=True).encode()).hexdigest()
        bid = build_id or f"{started.strftime('%Y%m%dT%H%M%SZ')}-{ih[:10]}"
        db.execute("INSERT INTO meta VALUES ('build_id', ?)", (bid,))
        db.execute("INSERT INTO meta VALUES ('store_version', ?)", (STORE_VERSION,))
        db.execute("INSERT INTO meta VALUES ('inputs_sha256', ?)", (ih,))
        db.commit()
        db.execute("ANALYZE")
        db.commit()
        db.close()
        timings["total_s"] = round(time.time() - t_start, 1)
        manifest = {
            "build_id": bid, "store_version": STORE_VERSION, "created_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "inputs_sha256": ih, "inputs": inputs, "code": code_fingerprint(),
            "method": {
                "alias_sources": list(A.ALLOWED_SOURCES), "alias_thresholds": A.thresholds(),
                "similar_group": {k: sim_stats[k] for k in ("method", "threshold_jaccard", "num_perm", "shingle_words")},
                "vendor_product_cap": 10, "description_priority": ["cve_list_cna", "nvd", "kev"],
                "workers": workers,
            },
            "reconciliation": recon,
            "report": report,
            "changes_vs_previous": changes,
            "worker_seconds": {str(r["key"]): r["seconds"] for r in results},
            "timings": timings,
            "store_bytes": db_path.stat().st_size,
        }
        from .export_candidates import write_candidates
        manifest["nickname_candidates"] = {"file": "nickname_candidates.jsonl",
                                           "groups": write_candidates(db_path, tmp / "nickname_candidates.jsonl")}
        if v1_corpus is not None:
            from .v1_compare import compare_v1
            t = time.time()
            nvd_desc: dict[str, str] = {}
            for res in results:
                sc = sqlite3.connect(tmp / "shards" / f"{res['key']}.sqlite")
                nvd_desc.update(sc.execute("SELECT cve_id, nvd_desc FROM v1side"))
                sc.close()
            manifest["v1_comparison"] = compare_v1(db_path, v1_corpus, kev_rows, epss_rows, nvd_desc,
                                                   workers=workers, log=log)
            del nvd_desc
            timings["v1_compare_s"] = round(time.time() - t, 1)
            manifest["store_bytes"] = db_path.stat().st_size
        shutil.rmtree(tmp / "shards")
        manifest["timings"] = timings
        (tmp / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        final = out_root / bid
        if final.exists():
            shutil.rmtree(final)
        os.replace(tmp, final)
        (out_root / "LATEST").write_text(bid + "\n", encoding="utf-8")
        log(f"build {bid}: {n_rows} CVEs in {timings['total_s']}s -> {final}")
        return final
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _snippet(c: A.Candidate, snippets: dict, db: sqlite3.Connection) -> str:
    """Short evidence text for the judges: the exploit title, PoC repository, URL or the CVE's own text."""
    if c.source == "cve_references":
        return c.record_id
    if c.source in ("cve_list", "cve_description"):
        row = db.execute("SELECT title, description FROM cve WHERE cve_id = ?", (c.cve_id,)).fetchone()
        text = (row[0] if c.source == "cve_list" else row[1]) or ""
        i = text.lower().find(c.alias.lower())
        return text[max(0, i - 120): i + 180] if i >= 0 else text[:300]
    return snippets.get((c.source, c.record_id), "")


def alias_report(db: sqlite3.Connection, sel: A.Selection) -> dict:
    q = lambda s: db.execute(s).fetchone()[0]  # noqa: E731
    by_src = dict(db.execute("SELECT source, COUNT(*) FROM aliases GROUP BY source ORDER BY source").fetchall())
    by_kind = dict(db.execute("SELECT kind, COUNT(*) FROM aliases GROUP BY kind").fetchall())
    return {
        "rows": q("SELECT COUNT(*) FROM aliases"),
        "rows_by_kind": by_kind,
        "rows_by_source": by_src,
        "cves_with_any_alias": q("SELECT COUNT(DISTINCT cve_id) FROM aliases"),
        "cves_with_nickname_or_advisory_id": q("SELECT COUNT(DISTINCT cve_id) FROM aliases WHERE kind != 'title'"),
        "cves_with_nickname": q("SELECT COUNT(DISTINCT cve_id) FROM aliases WHERE kind = 'nickname'"),
        "distinct_nicknames": q("SELECT COUNT(DISTINCT alias_norm) FROM aliases WHERE kind = 'nickname'"),
        "nickname_candidate_groups": len(sel.groups),
        "nickname_candidate_cves": len({c for g in sel.groups for c in g.cve_ids}),
        "candidate_decisions": sel.reasons,
    }


def record_changes(db: sqlite3.Connection, previous: Path) -> dict:
    prev_db = previous / "store.sqlite" if previous.is_dir() else previous
    old = sqlite3.connect(f"file:{prev_db.as_posix()}?mode=ro", uri=True)
    before = dict(old.execute("SELECT cve_id, content_hash FROM cve"))
    old.close()
    now = dict(db.execute("SELECT cve_id, content_hash FROM cve"))
    rows = [(c, "added") for c in now if c not in before]
    rows += [(c, "changed") for c, h in now.items() if c in before and before[c] != h]
    rows += [(c, "removed") for c in before if c not in now]
    db.executemany("INSERT INTO changes VALUES (?,?)", rows)
    db.commit()
    cnt = Counter(ch for _, ch in rows)
    return {"previous": str(previous), "added": cnt["added"], "changed": cnt["changed"], "removed": cnt["removed"],
            "unchanged": len(now) - cnt["added"] - cnt["changed"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--feeds", type=Path, required=True)
    ap.add_argument("--sources", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "data" / "store")
    ap.add_argument("--workers", type=int, default=min(6, os.cpu_count() or 1))
    ap.add_argument("--v1-corpus", type=Path, default=None, help="v1 corpus_store.db for the comparison report")
    ap.add_argument("--previous", type=Path, default=None, help="earlier build directory to diff content hashes")
    ap.add_argument("--build-id", default=None, help="override the build ID (tests)")
    ap.add_argument("--verdicts", type=Path, default=VERDICTS_PATH, help="nickname verdict file (JSONL)")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        build(a.feeds, a.sources, a.out, workers=a.workers, v1_corpus=a.v1_corpus, previous=a.previous,
              build_id=a.build_id, log=lambda m: print(m, flush=True), verdicts_path=a.verdicts)
    except ReconciliationError as e:
        print(f"BUILD FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
