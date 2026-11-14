"""T0 observation narratives.

Two inputs:

1. Team 3's own cases (`llm/evaluation/benchmark_data.py`, field `raw_text`): the fixed subset. They are
   public in the repository, so they are placed in the dev split (sealing them would be meaningless).
2. B2a narratives: JSON Lines files under ``<benchmark>/inputs/t0_narratives/*.jsonl`` (or
   ``--t0-narratives``). Re-running the build ingests them. One object per line:

   {
     "narrative_id": "B2a-0001",                     # unique and stable
     "text": "<incident paragraph, as sent to the service>",
     "targets": [{"doc_id": "CVE-2023-4966", "grade": 2},      # known from authoring
                 {"doc_id": "attack:S1202", "grade": 1}],      # optional related ATT&CK docs
     "source": {"name": "<incident-role source, e.g. acsc_advisories>", "id": "<write-up id>",
                "url": "<write-up URL>", "licence": "<licence name>"},
     "author": {"model": "claude-opus-5-5", "date": "YYYY-MM-DD"},
     "verification": {"model": "claude-sonnet-5-5", "passed": true,
                      "identified": ["CVE-2023-4966"]},        # what the verifier recovered blind
     "meta": {}                                                # optional, copied through
   }

   A narrative is ingested only when: verification.passed is true; every grade-2 target is in
   verification.identified; the source has the `incident` role in its B1 manifest (the leakage
   firewall); every target exists and is searchable (CVE) or is an active ATT&CK object; and it passes
   the overlap filter (<= 60% token share with each target's corpus text) and the expansion-copy check.
   The schema is also published as ``benchmarks_v2/build/t0_narrative.schema.json``.
"""
from __future__ import annotations

import ast
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from .common import CVE_ID_RE, REPO_ROOT, sha256_file
from .model import Item, qrel
from .text import content_tokens, token_set

_GENERIC_PRODUCT = {"version", "versions", "server", "update", "updates", "cumulative", "security", "firmware", "and"}

TEAM3_FILE = REPO_ROOT / "llm" / "evaluation" / "benchmark_data.py"


def load_team3_cases(path: Path = TEAM3_FILE) -> list[dict]:
    """Parse BENCHMARK_CASES without importing the llm package."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "BENCHMARK_CASES"
                                                 for t in node.targets):
            return ast.literal_eval(node.value)
    return []


def build_team3(u, kb, gate, path: Path = TEAM3_FILE) -> tuple[list[Item], dict]:
    stats = defaultdict(int)
    if not Path(path).is_file():
        return [], {"available": False}
    cases = load_team3_cases(path)
    stats["cases"] = len(cases)
    items = []
    for c in cases:
        gt = c.get("ground_truth_entities") or {}
        qrels = []
        missing = []
        mismatched = []
        prod = " ".join((c.get("ground_truth_patch") or {}).get("affected_versions") or [])
        ptoks = content_tokens(prod) - _GENERIC_PRODUCT
        for cid in gt.get("cves") or []:
            cid = cid.strip().upper()
            r = gate.resolve_cve(cid)
            if r is None:
                missing.append(cid)
                continue
            # Team 3's cases may use invented IDs that collide with real, unrelated records: a CVE is a target
            # only when its corpus text names the product the case says is affected; otherwise it is recorded
            # as a known non-relevant document (grade 0).
            if ptoks and not (ptoks & token_set(u.corpus_text(r[0]))):
                mismatched.append(r[0])
                qrels.append(qrel(r[0], 0, "authoring"))
                continue
            qrels.append(qrel(r[0], 2, "authoring"))
        ent_grade = 1 if any(q["grade"] == 2 for q in qrels) else 2
        named = []
        for nm in list(gt.get("threat_actors") or []) + list(gt.get("malware_families") or []):
            aid = kb.resolve(nm) if kb.available else None
            if aid is None:
                # try without trailing qualifiers such as "affiliates" or "RAT"
                for cut in (" affiliates", " RAT", " ransomware"):
                    if nm.endswith(cut) and kb.available:
                        aid = kb.resolve(nm[: -len(cut)])
                        if aid:
                            break
            if aid and f"attack:{aid}" not in {q["doc_id"] for q in qrels}:
                qrels.append(qrel(f"attack:{aid}", ent_grade, "authoring"))
                named.append({"name": nm, "doc_id": f"attack:{aid}"})
        meta = {"origin": "team3_benchmark_data", "case_description": c.get("description", ""),
                "cves_not_in_corpus": missing, "attack_entities": named,
                "cve_ids_unrelated_to_case_product": mismatched,
                "entity_grade_rule": "named ATT&CK group/software = grade 1 when the case has CVE targets, else 2"}
        it = Item(slice="T0", text=c["raw_text"], qrels=qrels, forced_split="dev", meta=meta,
                  source={"name": "team3_benchmark_data", "id": c["case_id"],
                          "licence": "repository content (llm/evaluation/benchmark_data.py)"})
        if gate.accept(it):
            items.append(it)
    stats["accepted"] = len(items)
    return items, dict(stats)


def validate_narrative(rec: dict) -> list[str]:
    errs = []
    for k, t in (("narrative_id", str), ("text", str), ("targets", list), ("source", dict),
                 ("verification", dict)):
        if not isinstance(rec.get(k), t):
            errs.append(f"{k} missing or not {t.__name__}")
    if errs:
        return errs
    for tg in rec["targets"]:
        if not isinstance(tg, dict) or not isinstance(tg.get("doc_id"), str) or tg.get("grade") not in (1, 2):
            errs.append(f"bad target {tg!r}")
    if not any(isinstance(t, dict) and t.get("grade") == 2 for t in rec["targets"]):
        errs.append("no grade-2 target")
    if not rec["source"].get("name"):
        errs.append("source.name missing")
    return errs


def build_b2a(u, kb, srcs, gate, narratives_dir: Path | None) -> tuple[list[Item], dict, list[dict]]:
    stats = defaultdict(int)
    inputs = []
    if narratives_dir is None or not Path(narratives_dir).is_dir():
        return [], {"available": False, "expected_dir": "<benchmark>/inputs/t0_narratives/*.jsonl"}, inputs
    files = sorted(Path(narratives_dir).glob("*.jsonl"))
    items = []
    seen = set()
    for p in files:
        inputs.append({"name": f"t0_narratives/{p.name}", "sha256": sha256_file(p)})
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            stats["records"] += 1
            rec = json.loads(line)
            errs = validate_narrative(rec)
            if errs:
                stats["schema_error"] += 1
                continue
            if rec["narrative_id"] in seen:
                stats["duplicate_id"] += 1
                continue
            seen.add(rec["narrative_id"])
            v = rec["verification"]
            g2 = [t["doc_id"] for t in rec["targets"] if t["grade"] == 2]
            if v.get("passed") is not True or not set(g2) <= set(v.get("identified") or []):
                stats["not_verified"] += 1
                continue
            sname = rec["source"]["name"]
            if srcs.role_of(sname) != "incident":
                stats["source_not_incident_role"] += 1
                continue
            qrels = []
            bad = False
            for t in rec["targets"]:
                d = t["doc_id"]
                if CVE_ID_RE.match(d):
                    r = gate.resolve_cve(d)
                    if r is None:
                        bad = True
                        break
                    qrels.append(qrel(r[0], t["grade"], "authoring" if r[1] == "known_item" else "equivalence"))
                elif d.startswith("attack:") and kb.available and d[7:] in kb.objects:
                    qrels.append(qrel(d, t["grade"], "authoring"))
                else:
                    bad = True
                    break
            if bad:
                stats["target_not_in_corpus"] += 1
                continue
            src = {"name": sname, "id": str(rec["source"].get("id", "")),
                   "licence": str(rec["source"].get("licence", ""))}
            meta = {"origin": "b2a", "narrative_id": rec["narrative_id"], "source_url": rec["source"].get("url", ""),
                    "author": rec.get("author") or {}, "verification": {k: v.get(k) for k in ("model", "passed")},
                    **(rec.get("meta") or {})}
            it = Item(slice="T0", text=rec["text"], qrels=qrels, source=src, meta=meta)
            if gate.accept(it):
                items.append(it)
    stats["accepted"] = len(items)
    stats["files"] = len(files)
    return items, dict(stats), inputs


def schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "B2a T0 narrative record (one JSON object per line)",
        "type": "object",
        "required": ["narrative_id", "text", "targets", "source", "author", "verification"],
        "properties": {
            "narrative_id": {"type": "string", "minLength": 1},
            "text": {"type": "string", "minLength": 1},
            "targets": {"type": "array", "minItems": 1, "items": {
                "type": "object", "required": ["doc_id", "grade"],
                "properties": {"doc_id": {"type": "string", "pattern": "^(CVE-\\d{4}-\\d{4,}|attack:[GSMT]\\d{4}(\\.\\d{3})?)$"},
                               "grade": {"enum": [1, 2]}}}},
            "source": {"type": "object", "required": ["name", "id"],
                       "properties": {"name": {"type": "string"}, "id": {"type": "string"}, "url": {"type": "string"},
                                      "licence": {"type": "string"}}},
            "author": {"type": "object", "properties": {"model": {"type": "string"}, "date": {"type": "string"}}},
            "verification": {"type": "object", "required": ["passed", "identified"],
                             "properties": {"model": {"type": "string"}, "passed": {"type": "boolean"},
                                            "identified": {"type": "array", "items": {"type": "string"}}}},
            "meta": {"type": "object"},
        },
    }


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
