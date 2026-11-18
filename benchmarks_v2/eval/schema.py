"""Loaders and strict validators for the benchmark data contract (docs/benchmark_format.md).

Standard library only (this module is also used on the server by the run command).

Every loader collects all problems it finds and raises one ``ValidationError`` whose message lists them as
``<file>:<line>: <field>: <problem>`` (at most ``MAX_REPORTED`` lines, then a count of the rest).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import sealed

SLICES = tuple(f"T{i}" for i in range(10))
SPLITS = ("train", "dev", "test")
ORIGINS = ("known_item", "equivalence", "judged", "authoring")
GRADES = (0, 1, 2)
# Confidence tiers in increasing order of strength (plan 4.7).
TIERS = ("UNSUPPORTED", "WEAK", "PARTIAL", "STRONG", "EXACT")
TIER_RANK = {t: i for i, t in enumerate(TIERS)}
UNANSWERABLE_SLICE = "T7"

QID_RE = re.compile(r"^(T[0-9])-([0-9]+)$")
CVE_DOC_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ATTACK_DOC_RE = re.compile(r"^attack:[A-Z]{1,2}\d{4}(\.\d{3})?$")

QUERY_FIELDS = ("qid", "slice", "split", "text", "answerable", "temporal_holdout", "source", "meta")
QREL_FIELDS = ("qid", "doc_id", "grade", "origin")
QREL_OPTIONAL = ("judge",)
JUDGE_FIELDS = ("round", "first", "second", "adjudicated")
EQUIV_FIELDS = ("set_id", "members", "reason")
RUN_FIELDS = ("qid", "variant", "ranked", "abstained", "latency_ms", "error")
RUN_OPTIONAL = ("extra",)  # harness addition, see METHODS.md "Run file additions"
RANKED_FIELDS = ("doc_id", "score", "tier", "probability")

MAX_REPORTED = 50


class ValidationError(ValueError):
    """Schema or consistency violation in benchmark data or a run file."""

    def __init__(self, source: str, problems: list[str]):
        self.source = source
        self.problems = list(problems)
        shown = self.problems[:MAX_REPORTED]
        more = len(self.problems) - len(shown)
        msg = f"{source}: {len(self.problems)} problem(s)\n  " + "\n  ".join(shown)
        if more > 0:
            msg += f"\n  ... and {more} more"
        super().__init__(msg)


def valid_doc_id(doc_id: Any) -> bool:
    return isinstance(doc_id, str) and bool(CVE_DOC_RE.match(doc_id) or ATTACK_DOC_RE.match(doc_id))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def read_jsonl(path: Path, problems: list[str]) -> list[tuple[int, dict]]:
    """Parse a JSON Lines file. Blank lines are allowed; every other line must be a JSON object."""
    rows: list[tuple[int, dict]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"{path.name}:{lineno}: not valid JSON ({exc.msg})")
                continue
            if not isinstance(obj, dict):
                problems.append(f"{path.name}:{lineno}: expected a JSON object, got {type(obj).__name__}")
                continue
            rows.append((lineno, obj))
    return rows


def _check_keys(obj: dict, required: Iterable[str], optional: Iterable[str], where: str, problems: list[str]) -> None:
    required = tuple(required)
    allowed = set(required) | set(optional)
    for k in required:
        if k not in obj:
            problems.append(f"{where}: {k}: missing required field")
    for k in obj:
        if k not in allowed:
            problems.append(f"{where}: {k}: unknown field (allowed: {', '.join(sorted(allowed))})")


# --------------------------------------------------------------------------------------------- queries
@dataclass(frozen=True)
class Query:
    qid: str
    slice: str
    split: str
    text: str
    answerable: bool
    temporal_holdout: bool
    source: dict
    meta: dict


def parse_query(obj: dict, where: str, problems: list[str]) -> Query | None:
    before = len(problems)
    _check_keys(obj, QUERY_FIELDS, (), where, problems)
    qid, sl, sp = obj.get("qid"), obj.get("slice"), obj.get("split")
    if "qid" in obj and (not isinstance(qid, str) or not QID_RE.match(qid)):
        problems.append(f"{where}: qid: {qid!r} is not of the form '<slice>-<n>' (e.g. 'T3-17')")
    if "slice" in obj and sl not in SLICES:
        problems.append(f"{where}: slice: {sl!r} is not one of T0..T9")
    if isinstance(qid, str) and QID_RE.match(qid) and sl in SLICES and QID_RE.match(qid).group(1) != sl:
        problems.append(f"{where}: qid: prefix of {qid!r} does not match slice {sl!r}")
    if "split" in obj and sp not in SPLITS:
        problems.append(f"{where}: split: {sp!r} is not one of {', '.join(SPLITS)}")
    if "text" in obj and (not isinstance(obj["text"], str) or not obj["text"].strip()):
        problems.append(f"{where}: text: must be a non-empty string")
    for b in ("answerable", "temporal_holdout"):
        if b in obj and not isinstance(obj[b], bool):
            problems.append(f"{where}: {b}: must be a JSON boolean, got {obj[b]!r}")
    if isinstance(obj.get("answerable"), bool) and sl in SLICES:
        if obj["answerable"] is False and sl != UNANSWERABLE_SLICE:
            problems.append(f"{where}: answerable: false is allowed only for {UNANSWERABLE_SLICE} (slice is {sl})")
        if obj["answerable"] is True and sl == UNANSWERABLE_SLICE:
            problems.append(f"{where}: answerable: {UNANSWERABLE_SLICE} queries must have answerable=false")
    src = obj.get("source")
    if "source" in obj:
        if not isinstance(src, dict):
            problems.append(f"{where}: source: must be an object")
        else:
            name = src.get("name")
            if not isinstance(name, str) or not name:
                problems.append(f"{where}: source.name: missing or not a string")
            elif name != "generated":
                if "id" not in src or not isinstance(src["id"], (str, int)) or isinstance(src["id"], bool):
                    problems.append(f"{where}: source.id: required (string or integer) for non-generated sources")
                if not isinstance(src.get("licence"), str) or not src.get("licence"):
                    problems.append(f"{where}: source.licence: required string for non-generated sources")
    if "meta" in obj and not isinstance(obj["meta"], dict):
        problems.append(f"{where}: meta: must be an object")
    if len(problems) > before:
        return None
    return Query(qid, sl, sp, obj["text"], obj["answerable"], obj["temporal_holdout"], dict(src), dict(obj["meta"]))


def load_queries(path: Path) -> list[Query]:
    path = Path(path)
    problems: list[str] = []
    out: list[Query] = []
    seen: dict[str, int] = {}
    for lineno, obj in read_jsonl(path, problems):
        where = f"{path.name}:{lineno}"
        q = parse_query(obj, where, problems)
        if q is None:
            continue
        if q.qid in seen:
            problems.append(f"{where}: qid: duplicate {q.qid!r} (first at line {seen[q.qid]})")
            continue
        seen[q.qid] = lineno
        out.append(q)
    if problems:
        raise ValidationError(str(path), problems)
    return out


# --------------------------------------------------------------------------------------------- qrels
@dataclass(frozen=True)
class Qrel:
    qid: str
    doc_id: str
    grade: int
    origin: str


def load_qrels(path: Path, queries: dict[str, Query] | None = None) -> list[Qrel]:
    """Load qrels. If ``queries`` is given, every qid must exist there and unanswerable queries may only
    carry grade 0."""
    path = Path(path)
    problems: list[str] = []
    out: list[Qrel] = []
    seen: dict[tuple[str, str], int] = {}
    for lineno, obj in read_jsonl(path, problems):
        where = f"{path.name}:{lineno}"
        before = len(problems)
        _check_keys(obj, QREL_FIELDS, QREL_OPTIONAL, where, problems)
        qid, doc, grade, origin = obj.get("qid"), obj.get("doc_id"), obj.get("grade"), obj.get("origin")
        if "qid" in obj and (not isinstance(qid, str) or not QID_RE.match(qid)):
            problems.append(f"{where}: qid: {qid!r} is not a valid qid")
        if "doc_id" in obj and not valid_doc_id(doc):
            problems.append(f"{where}: doc_id: {doc!r} is neither an upper-case CVE ID nor 'attack:<ID>'")
        if "grade" in obj and (not _is_int(grade) or grade not in GRADES):
            problems.append(f"{where}: grade: {grade!r} must be the integer 0, 1 or 2")
        if "origin" in obj and origin not in ORIGINS:
            problems.append(f"{where}: origin: {origin!r} is not one of {', '.join(ORIGINS)}")
        if origin == "judged":
            judge = obj.get("judge")
            if not isinstance(judge, dict):
                problems.append(f"{where}: judge: required object for origin 'judged'")
            else:
                for k in JUDGE_FIELDS:
                    if k not in judge:
                        problems.append(f"{where}: judge.{k}: missing")
                if "round" in judge and (not _is_int(judge["round"]) or judge["round"] < 1):
                    problems.append(f"{where}: judge.round: must be a positive integer")
        elif "judge" in obj and origin in ORIGINS:
            problems.append(f"{where}: judge: only allowed when origin is 'judged'")
        if queries is not None and isinstance(qid, str) and qid not in queries:
            problems.append(f"{where}: qid: {qid!r} is not in the query file")
        if (queries is not None and isinstance(qid, str) and qid in queries and not queries[qid].answerable
                and _is_int(grade) and grade > 0):
            problems.append(f"{where}: grade: unanswerable query {qid} cannot have a relevant document")
        if len(problems) > before:
            continue
        key = (qid, doc)
        if key in seen:
            problems.append(f"{where}: duplicate judgement for ({qid}, {doc}) (first at line {seen[key]})")
            continue
        seen[key] = lineno
        out.append(Qrel(qid, doc, grade, origin))
    if problems:
        raise ValidationError(str(path), problems)
    return out


# --------------------------------------------------------------------------------------------- equivalence
@dataclass
class Equivalence:
    """Equivalence classes over documents (transitive closure of the listed sets)."""

    unit_of: dict[str, str] = field(default_factory=dict)  # doc_id -> canonical unit id
    members: dict[str, list[str]] = field(default_factory=dict)  # unit id -> sorted member doc_ids
    merged_sets: list[list[str]] = field(default_factory=list)  # groups of set_ids merged because they overlap

    def unit(self, doc_id: str) -> str:
        return self.unit_of.get(doc_id, doc_id)

    def members_of(self, unit: str) -> list[str]:
        return self.members.get(unit, [unit])


def load_equivalence(path: Path | None) -> Equivalence:
    if path is None:
        return Equivalence()
    path = Path(path)
    problems: list[str] = []
    sets: list[tuple[str, list[str]]] = []
    seen: dict[str, int] = {}
    for lineno, obj in read_jsonl(path, problems):
        where = f"{path.name}:{lineno}"
        before = len(problems)
        _check_keys(obj, EQUIV_FIELDS, (), where, problems)
        sid, members, reason = obj.get("set_id"), obj.get("members"), obj.get("reason")
        if "set_id" in obj and (not isinstance(sid, str) or not sid):
            problems.append(f"{where}: set_id: must be a non-empty string")
        if "reason" in obj and not isinstance(reason, str):
            problems.append(f"{where}: reason: must be a string")
        if "members" in obj:
            if not isinstance(members, list) or len(members) < 2:
                problems.append(f"{where}: members: must be a list of at least two doc_ids")
            else:
                for m in members:
                    if not valid_doc_id(m):
                        problems.append(f"{where}: members: {m!r} is not a valid doc_id")
                if len(set(members)) != len(members):
                    problems.append(f"{where}: members: duplicate doc_id in set")
        if len(problems) > before:
            continue
        if sid in seen:
            problems.append(f"{where}: set_id: duplicate {sid!r} (first at line {seen[sid]})")
            continue
        seen[sid] = lineno
        sets.append((sid, list(members)))
    if problems:
        raise ValidationError(str(path), problems)
    return build_equivalence(sets)


def build_equivalence(sets: list[tuple[str, list[str]]]) -> Equivalence:
    """Union-find over documents; overlapping sets are merged (the relation must be transitive)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for _, members in sets:
        for m in members[1:]:
            ra, rb = find(members[0]), find(m)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
    groups: dict[str, list[str]] = {}
    for d in list(parent):
        groups.setdefault(find(d), []).append(d)
    eq = Equivalence()
    root_sets: dict[str, list[str]] = {}
    for sid, members in sets:
        root_sets.setdefault(find(members[0]), []).append(sid)
    for root, docs in groups.items():
        sids = sorted(root_sets.get(root, []))
        unit = "eq:" + sids[0]
        eq.members[unit] = sorted(docs)
        for d in docs:
            eq.unit_of[d] = unit
        if len(sids) > 1:
            eq.merged_sets.append(sids)
    return eq


# --------------------------------------------------------------------------------------------- run files
@dataclass(frozen=True)
class Ranked:
    doc_id: str
    score: float
    tier: str | None
    probability: float | None


@dataclass(frozen=True)
class RunRecord:
    qid: str
    variant: str
    ranked: tuple[Ranked, ...]
    abstained: bool
    latency_ms: float
    error: str | None
    extra: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        d = {
            "qid": self.qid,
            "variant": self.variant,
            "ranked": [{"doc_id": r.doc_id, "score": r.score, "tier": r.tier, "probability": r.probability}
                       for r in self.ranked],
            "abstained": self.abstained,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }
        if self.extra:
            d["extra"] = self.extra
        return d


def parse_run_record(obj: dict, where: str, problems: list[str], warnings: list[str] | None = None) -> RunRecord | None:
    before = len(problems)
    _check_keys(obj, RUN_FIELDS, RUN_OPTIONAL, where, problems)
    qid = obj.get("qid")
    if "qid" in obj and (not isinstance(qid, str) or not QID_RE.match(qid)):
        problems.append(f"{where}: qid: {qid!r} is not a valid qid")
    if "variant" in obj and (not isinstance(obj["variant"], str) or not obj["variant"]):
        problems.append(f"{where}: variant: must be a non-empty string")
    if "abstained" in obj and not isinstance(obj["abstained"], bool):
        problems.append(f"{where}: abstained: must be a JSON boolean")
    if "latency_ms" in obj and (not _is_number(obj["latency_ms"]) or obj["latency_ms"] < 0):
        problems.append(f"{where}: latency_ms: must be a non-negative finite number")
    if "error" in obj and obj["error"] is not None and not isinstance(obj["error"], str):
        problems.append(f"{where}: error: must be a string or null")
    if "extra" in obj and not isinstance(obj["extra"], dict):
        problems.append(f"{where}: extra: must be an object")
    ranked: list[Ranked] = []
    if "ranked" in obj:
        if not isinstance(obj["ranked"], list):
            problems.append(f"{where}: ranked: must be a list")
        else:
            docs: set[str] = set()
            for i, r in enumerate(obj["ranked"], 1):
                w = f"{where}: ranked[{i}]"
                if not isinstance(r, dict):
                    problems.append(f"{w}: must be an object")
                    continue
                b = len(problems)
                _check_keys(r, RANKED_FIELDS, (), w, problems)
                d = r.get("doc_id")
                if "doc_id" in r and (not isinstance(d, str) or not d):
                    problems.append(f"{w}.doc_id: must be a non-empty string")
                elif isinstance(d, str) and d in docs:
                    problems.append(f"{w}.doc_id: {d!r} appears twice; run files must be de-duplicated")
                if "score" in r and not _is_number(r["score"]):
                    problems.append(f"{w}.score: must be a finite number")
                t = r.get("tier")
                if t is not None and t not in TIER_RANK:
                    problems.append(f"{w}.tier: {t!r} is not one of {', '.join(TIERS)} or null")
                p = r.get("probability")
                if p is not None and (not _is_number(p) or not 0.0 <= p <= 1.0):
                    problems.append(f"{w}.probability: {p!r} must be a number in [0, 1] or null")
                if len(problems) > b:
                    continue
                docs.add(d)
                if warnings is not None and not valid_doc_id(d):
                    warnings.append(f"{w}.doc_id: {d!r} does not have a contract doc_id form; it can never be judged")
                ranked.append(Ranked(d, float(r["score"]), t, None if p is None else float(p)))
    if len(problems) > before:
        return None
    return RunRecord(qid, obj["variant"], tuple(ranked), obj["abstained"], float(obj["latency_ms"]), obj["error"],
                     dict(obj.get("extra") or {}))


@dataclass
class Run:
    path: str
    variant: str
    records: dict[str, RunRecord]
    sha256: str
    warnings: list[str]
    meta: dict | None = None


def load_run(path: Path) -> Run:
    path = Path(path)
    problems: list[str] = []
    warnings: list[str] = []
    records: dict[str, RunRecord] = {}
    lines: dict[str, int] = {}
    variants: set[str] = set()
    for lineno, obj in read_jsonl(path, problems):
        where = f"{path.name}:{lineno}"
        rec = parse_run_record(obj, where, problems, warnings)
        if rec is None:
            continue
        if rec.qid in records:
            problems.append(f"{where}: qid: {rec.qid} appears twice (first at line {lines[rec.qid]})")
            continue
        records[rec.qid] = rec
        lines[rec.qid] = lineno
        variants.add(rec.variant)
    if len(variants) > 1:
        problems.append(f"{path.name}: variant: a run file must hold one variant, found {sorted(variants)}")
    if not records and not problems:
        problems.append(f"{path.name}: run file is empty")
    if problems:
        raise ValidationError(str(path), problems)
    meta = None
    meta_path = Path(str(path) + ".meta.json")
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(str(meta_path), [f"not valid JSON ({exc.msg})"])
    return Run(str(path), variants.pop(), records, sha256_file(path), warnings, meta)


# --------------------------------------------------------------------------------------------- dataset
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Dataset:
    queries: dict[str, Query]
    qrels: dict[str, dict[str, int]]  # qid -> doc_id -> grade
    equivalence: Equivalence
    info: dict  # provenance: paths, version, manifest sha256, file hashes, warnings

    def select(self, split: str | None = None, slices: Iterable[str] | None = None) -> list[Query]:
        sl = set(slices) if slices else None
        out = [q for q in self.queries.values()
               if (split is None or q.split == split) and (sl is None or q.slice in sl)]
        return sorted(out, key=lambda q: (q.slice, int(q.qid.split("-")[1])))


def _manifest_hashes(manifest: Any) -> dict[str, str]:
    """Find per-file sha256 values in a manifest whose exact key layout the contract does not fix.

    Accepted shapes: ``{"files": {"queries.jsonl": "<hex>" | {"sha256": "<hex>", ...}}}`` or a list of
    ``{"path"|"name"|"file": ..., "sha256": ...}`` objects under ``files``.
    """
    out: dict[str, str] = {}
    files = manifest.get("files") if isinstance(manifest, dict) else None
    hexre = re.compile(r"^[0-9a-f]{64}$")
    if isinstance(files, dict):
        for name, v in files.items():
            h = v.get("sha256") if isinstance(v, dict) else v
            if isinstance(h, str) and hexre.match(h):
                out[str(name).replace("\\", "/")] = h
    elif isinstance(files, list):
        for v in files:
            if isinstance(v, dict):
                name = v.get("path") or v.get("name") or v.get("file")
                h = v.get("sha256")
                if isinstance(name, str) and isinstance(h, str) and hexre.match(h):
                    out[name.replace("\\", "/")] = h
    return out


def load_dataset(root: Path | None = None, split: str | None = None, *, queries_path: Path | None = None,
                 qrels_path: Path | None = None, equivalence_path: Path | None = None) -> Dataset:
    """Load a benchmark version directory (``data/benchmark/<version>``) or explicit files.

    With ``split == "test"`` the sealed files are read, which requires TRE_OPEN_SEALED=E1. Non-sealed files
    must not contain test-split queries; sealed files must contain only test-split queries.
    """
    sealed.check_split(split, "loading the test split")
    info: dict[str, Any] = {"root": None, "version": None, "manifest_sha256": None, "files": {},
                            "manifest_verified": False, "warnings": []}
    use_sealed = split == "test"
    if root is not None:
        root = Path(root)
        info["root"] = str(root)
        base = root / "sealed" if use_sealed else root
        queries_path = queries_path or base / "queries.jsonl"
        qrels_path = qrels_path or base / "qrels.jsonl"
        if equivalence_path is None and (root / "equivalence.jsonl").exists():
            equivalence_path = root / "equivalence.jsonl"
        manifest_path = root / "manifest.json"
        if manifest_path.exists():
            info["manifest_sha256"] = sha256_file(manifest_path)
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValidationError(str(manifest_path), [f"not valid JSON ({exc.msg})"])
            info["version"] = manifest.get("version") if isinstance(manifest, dict) else None
            info["manifest_hashes"] = _manifest_hashes(manifest)
        else:
            info["warnings"].append(f"no manifest.json in {root}; dataset version and hashes unknown")
    if queries_path is None or qrels_path is None:
        raise ValueError("need a dataset directory or explicit --queries and --qrels files")
    files = {"queries": Path(queries_path), "qrels": Path(qrels_path)}
    if equivalence_path is not None:
        files["equivalence"] = Path(equivalence_path)
    for k, p in files.items():
        if not p.exists():
            raise FileNotFoundError(f"{k} file not found: {p}")
        info["files"][k] = {"path": str(p), "sha256": sha256_file(p)}
    # Verify against the manifest where it lists the file.
    mh = info.pop("manifest_hashes", None)
    if mh is not None and root is not None:
        problems, verified = [], 0
        for k, p in files.items():
            rel = p.resolve().relative_to(root.resolve()).as_posix() if _is_under(p, root) else p.name
            h = mh.get(rel)
            if h is None:
                info["warnings"].append(f"manifest lists no sha256 for {rel}; not verified")
            elif h != info["files"][k]["sha256"]:
                problems.append(f"{rel}: sha256 {info['files'][k]['sha256']} does not match manifest {h}")
            else:
                verified += 1
        if problems:
            raise ValidationError(str(root / "manifest.json"), problems)
        info["manifest_verified"] = verified == len(files)

    qlist = load_queries(files["queries"])
    problems = []
    for q in qlist:
        if use_sealed and q.split != "test":
            problems.append(f"{files['queries'].name}: {q.qid}: split {q.split!r} found in the sealed file")
        if not use_sealed and root is not None and q.split == "test":
            problems.append(f"{files['queries'].name}: {q.qid}: test-split query outside sealed/")
    if problems:
        raise ValidationError(str(files["queries"]), problems)
    if root is None:
        # An explicit query file holding any test-split row is treated as sealed as a whole.
        sealed.check_query_splits({q.split for q in qlist}, f"loading {files['queries'].name} (has test-split rows)")
    qmap = {q.qid: q for q in qlist}
    qrels: dict[str, dict[str, int]] = {}
    for r in load_qrels(files["qrels"], qmap):
        qrels.setdefault(r.qid, {})[r.doc_id] = r.grade
    eq = load_equivalence(files.get("equivalence"))
    if eq.merged_sets:
        info["warnings"].append(f"{len(eq.merged_sets)} groups of overlapping equivalence sets merged: "
                                + "; ".join(",".join(s) for s in eq.merged_sets[:10]))
    return Dataset(qmap, qrels, eq, info)


def _is_under(p: Path, root: Path) -> bool:
    try:
        p.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
