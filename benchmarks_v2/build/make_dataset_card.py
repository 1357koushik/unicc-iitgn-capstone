"""Render docs/benchmark_dataset_card.md from a build's manifest.json and build_report.json.

    python benchmarks_v2/build/make_dataset_card.py [--out <data/benchmark>] [--version v2.0]

Only aggregate numbers are rendered; nothing from the sealed split's text.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks_v2.build.common import REPO_ROOT, SLICES, TARGET_SIZES, default_benchmark_dir  # noqa: E402

NAMES = {"T0": "Observation narratives", "T1": "Identifier", "T2": "Nickname", "T3": "Advisory wording",
         "T4": "Detection-rule wording", "T5": "Product and version", "T6": "Noisy", "T7": "Unanswerable",
         "T8": "Confusable siblings", "T9": "Actor, software, technique"}

ATTRIBUTION = [
    ("ghsa_reviewed", "T3 query text; T2 corroboration",
     "GitHub Advisory Database (github/advisory-database), CC-BY-4.0. Queries derived from advisory summaries; attribution: \"Contains data from the GitHub Advisory Database, licensed CC-BY-4.0\"."),
    ("et_open_rules", "T4 query text; T2 corroboration",
     "Proofpoint Emerging Threats Open ruleset (suricata-7.0.3). Rule msg titles only; BSD for sids 2000000-2799999, GPLv2 for low sids, recorded per query in `source.licence`. \"Emerging Threats Open rules, Copyright Proofpoint, Inc.\""),
    ("sigma_rules", "T4 query text; T2 corroboration",
     "SigmaHQ rules, Detection Rule License (DRL) 1.1. Titles / first description sentence; the rule author is kept in `meta.rule_author` as DRL requires."),
    ("attack_enterprise", "T9 ground truth (relationships), Team 3 entity resolution, leakage test",
     "MITRE ATT&CK Enterprise (attack-stix-data). \"© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.\" No description text is used in queries."),
    ("exploitdb / metasploit_modules / nuclei_templates / poc_in_github", "leakage test only",
     "Expansion sources: read only to prove no query copies them (GPL-2.0 index / BSD-3-Clause / MIT / CC0-1.0)."),
    ("NVD CVE feeds, CVE List V5, CISA KEV, FIRST EPSS", "corpus universe, targets, T5/T8 structured data, overlap text",
     "NVD data is public domain (NIST); CVE List © The MITRE Corporation, CVE Terms of Use; CISA KEV is a US-government public catalogue; EPSS by FIRST.org (used for the universe only)."),
    ("Team 3 `llm/evaluation/benchmark_data.py`", "T0 fixed subset", "Repository content."),
]

METHOD = {
    "T0": "Team 3's own cases (`raw_text`) form the fixed subset, pinned to dev because they are public in the repository. "
          "CVE targets are known from the case (grade 2, origin `authoring`) unless the ID collides with an unrelated real record "
          "(the CVE's corpus text does not name the case's affected product): then it is a grade-0 known non-relevant document. "
          "Named ATT&CK groups/software resolved by exact name or alias are grade 1 (grade 2 when the case has no CVE target). "
          "B2a narratives are ingested from `<benchmark>/inputs/t0_narratives/*.jsonl` (schema in `benchmarks_v2/build/slice_t0.py` "
          "and `t0_narrative.schema.json`) when verified, from an `incident`-role source, with existing targets, and passing the overlap and expansion checks.",
    "T1": "Generated from the CVE universe (seeded sample of searchable CVEs): canonical, lower and mixed case, IDs inside sentences, "
          "two or three IDs, and malformed-but-recoverable forms (spaces, underscores, en dash, missing hyphen, brackets, trailing "
          "punctuation, colon, double space). Only existing IDs; non-existent IDs live in T7. Exempt from the overlap rule (identifiers).",
    "T2": "Names compiled from general knowledge in `benchmarks_v2/build/nicknames.py`, independently of any expansion source and of the alias "
          "table. A (name, CVE) pair is kept only when the name occurs in that CVE's NVD description or references, its CVE List text or "
          "references, or a query-side record (GHSA, ET Open, Sigma) for that CVE; the evidence is stored per item in `meta.corroboration`. "
          "Queries are the name in up to three of ten written templates, round-robin over names.",
    "T3": "Reviewed GHSA advisories (not withdrawn) with a CVE alias, seeded order, at most two per package. Query = summary with CVE IDs "
          "stripped (summary + first sentence of details when the summary has fewer than three content tokens). Target = the alias CVE; an "
          "alias rejected as a duplicate maps to its canonical CVE (origin `equivalence`).",
    "T4": "Sigma rules first, then ET Open rules, each in seeded order; enabled and disabled rules both used. Rule-vendor prefixes "
          "(`ET <CATEGORY>`, `GPL <CATEGORY>`), CVE/CAN IDs (including bare continuation IDs) and ET variant markers (M1, M2...) are stripped "
          "and recorded in `meta.stripped`; a Sigma title left generic is replaced by the first description sentence. Texts with fewer than "
          "two informative tokens are dropped; at most two queries per target set.",
    "T5": "From NVD CPE configurations (65%) and, for CVEs without CPE data, the CNA `affected` block (35%, mostly 2024-2026). One query "
          "per product: '<vendor> <product> <version> <flaw type>' in six templates, with a concrete version the anchor CVE affects "
          "(preferring one not written in its description) and a phrasing of its CWE class. Qrels: every CVE of that product whose "
          "version data includes the version and whose CWE class matches = grade 2; same version, other class = grade 1; CVEs whose "
          "applicability cannot be decided are left unjudged. Only CVEs with vendor, product, a parseable version and a mapped CWE are anchors.",
    "T6": "Seeded perturbations of dev/test T0, T2 and T3 queries: typos (swap, deletion, keyboard neighbour, doubling), missing spaces, "
          "analyst abbreviations, pasted log-like fragments (private IPs only) and combinations. `meta.parent_qid`; qrels and split inherited; "
          "a perturbation that would lose a target to the overlap rule is not used.",
    "T7": "Four categories of about 100: off-topic questions; security topics absent from a CVE/ATT&CK corpus (governance, careers, "
          "compliance clauses); IOC-only queries (random hashes, public IPv4, domains, defanged URLs) checked absent from NVD descriptions "
          "and ATT&CK text; well-formed CVE IDs verified absent from NVD, CVE List, KEV, EPSS and from every NVD description. answerable=false, no qrels.",
    "T8": "Product groups (CPE or CNA namespace) with 3-400 CVEs. The target is discriminated either by a component named in its description "
          "and in no sibling's (file, module, function or 'the X component'), or by a CWE class no sibling has. Qrels: target grade 2; up to "
          "ten siblings grade 0 (origin `authoring`), same flaw class first. By construction no sibling matches the discriminator.",
    "T9": "Template questions over ATT&CK Enterprise: ID queries (60), exact unique names (60), unique aliases (30) - the release gate "
          "subset, `meta.gate_exact` - and relationship questions (techniques/software of a group, groups using software, software "
          "techniques, mitigations of a technique, sub-techniques, groups using a technique). Ground truth from STIX relationships between "
          "active objects (answers grade 2, subject grade 1). Checked not to copy any ATT&CK description sentence. Exempt from the overlap rule.",
}


def fmt_hist(h: dict) -> str:
    if not h or not h.get("n"):
        return "n=0"
    return f"n={h['n']}, p50={h['p50']}, p90={h['p90']}, max={h['max']}, >0.6={h['share_gt_0.6']:.1%}, bins={h['bins_0.1']}"


def render(b: Path) -> str:
    m = json.loads((b / "manifest.json").read_text(encoding="utf-8"))
    rep = json.loads((b / "build_report.json").read_text(encoding="utf-8"))
    S = rep["slices"]
    L = []
    w = L.append
    w("# Retrieval benchmark collection v2 — dataset card")
    w("")
    w("Generated by `python benchmarks_v2/build/make_dataset_card.py` from the build's `manifest.json` and `build_report.json`.")
    w("The data itself lives outside git under `data/benchmark/<version>/` (format: `docs/benchmark_format.md`).")
    w("")
    w("## Purpose")
    w("")
    w("An independent test collection for the Retrieval Engine v2 (plan section 6): per-slice quality, abstention, calibration and "
      "recency measurements with a sealed test split. Query text is independent of corpus text; expansion sources never supply query text.")
    w("")
    w("## Build")
    w("")
    w(f"- Version `{m['version']}`, build date **{m['build_date']}**, seed `{m['seed']}`")
    w(f"- Builder `{m['builder']['entry_point']}` v{m['builder']['version']}, last builder commit `{m['builder']['commit']}`, code sha256 `{m['builder']['code_sha256']}`")
    w(f"- {m['totals']['queries']} queries, {m['totals']['qrels']} qrels, {m['totals']['equivalence_sets']} equivalence sets; "
      f"{m['sealed']['test_queries']} test queries sealed under `{m['sealed']['dir']}/`")
    w("")
    w("## Slices and sizes")
    w("")
    w("| Slice | Name | Target | Train | Dev | Test | Total | Temporal holdout | Qrels |")
    w("|---|---|---|---|---|---|---|---|---|")
    tot = {"train": 0, "dev": 0, "test": 0}
    for sl in SLICES:
        e = S[sl]
        c = e["by_split"]
        for k in tot:
            tot[k] += c[k]
        w(f"| {sl} | {NAMES[sl]} | {TARGET_SIZES[sl]} | {c['train']} | {c['dev']} | {c['test']} | {e['actual']} | {e['temporal_holdout']} | {e['qrels']} |")
    w(f"| all | | {sum(TARGET_SIZES.values())} | {tot['train']} | {tot['dev']} | {tot['test']} | {sum(tot.values())} | | |")
    w("")
    w("Temporal holdout: a grade-2 CVE target published in the 90 days before the build date; such groups never go to train.")
    w("")
    short = [sl for sl in SLICES if S[sl].get("shortfall")]
    if short:
        w("### Shortfalls")
        w("")
        for sl in short:
            w(f"- **{sl}** short by {S[sl]['shortfall']}: {S[sl]['shortfall_reason']}")
        w("")
    w("## Construction method per slice")
    w("")
    for sl in SLICES:
        g = S[sl]["gate"]
        w(f"- **{sl} {NAMES[sl]}.** {METHOD[sl]} Candidates examined: {g['examined']}; rejected: "
          + (", ".join(f"{k} {v}" for k, v in g["rejected"].items()) or "none") + ".")
    st = rep["slice_stats"]
    if "T2" in st:
        w("")
        w(f"T2 corroboration: {st['T2'].get('names_corroborated')} of {st['T2'].get('name_strings')} candidate name strings corroborated "
          f"({st['T2'].get('pair_uncorroborated', 0)} uncorroborated name-CVE pairs dropped); {st['T2'].get('names_with_queries')} names have queries.")
        w(f"Uncorroborated (dropped) names: {', '.join(st['T2'].get('uncorroborated_names', []))}.")
    if "T3" in st:
        w("")
        w(f"T3 ecosystems: {', '.join(f'{k} {v}' for k, v in st['T3'].get('by_ecosystem', {}).items())}.")
    w("")
    w("## Quality controls")
    w("")
    w("### Overlap filter")
    w("")
    w("A (query, target) pair is dropped when more than 60% of the query's content tokens (lower-cased, CVE IDs and stopwords removed, "
      "light plural stemming) occur in the target's corpus text: NVD description, CVE List description and title, and KEV name. The CVE "
      "List title is included because GitHub-CNA titles repeat GHSA summaries verbatim. A query left without a grade-2 target is dropped. "
      "Distribution of each query's maximum target overlap (bins of 0.1 from 0 to 1):")
    w("")
    w("| Slice | Before filter | After filter | Pairs dropped |")
    w("|---|---|---|---|")
    for sl in SLICES:
        o = S[sl]["overlap"]
        if o["exempt"]:
            w(f"| {sl} | exempt | exempt | - |")
        else:
            w(f"| {sl} | {fmt_hist(o['before_filter'])} | {fmt_hist(o['after_filter'])} | {o['pairs_dropped']} |")
    w("")
    w("T1 (identifiers), T7 (no targets) and T9 (ATT&CK names and IDs by design; it has its own no-copy rule) are exempt.")
    w("")
    eqs = rep["equivalence"]
    w("### Equivalence sets")
    w("")
    w(f"{eqs['sets']} sets with {eqs['members']} members: {eqs['by_reason'].get('rejected_duplicate', 0)} from CVEs rejected as duplicates "
      f"(reject reason parsed; {eqs['rejected_duplicate_with_target']} of {eqs['rejected_duplicate_reason']} duplicate rejections name a "
      f"target in the universe), {eqs['by_reason'].get('published_duplicate_statement', 0)} from published descriptions that state without "
      "hedging that they are a duplicate of / the same as another CVE. Hedged notes ('might be a duplicate') are not used. Each set "
      "records its reason.")
    w("")
    sp = rep["splits"]
    w("### Splits")
    w("")
    w(f"Queries sharing any CVE document (any grade), equivalence set, nickname, ATT&CK subject or T6 parent form one group "
      f"({sp['groups']} groups; largest {sp['largest_groups'][:5]}); a group gets one split. Allowed splits are the intersection over "
      "the slices in the group (6.3: T3/T4 40/20/40, T1 50/50 dev/test, others 40/60 dev/test). Seeded greedy balancing, largest groups "
      "first. T6 children follow their parents (parents only from dev/test). T9 groups by question subject; an ATT&CK answer document "
      "may appear in dev and test (there is no T9 train split).")
    w("")
    w("### Leakage tests (`tests/test_benchmark_leakage.py`)")
    w("")
    w("Run with `TRE_BENCHMARK_DIR=<data/benchmark/v2.0>`; skipped when the data is absent. They check: no CVE or equivalence set in "
      "two splits; T6 children follow parents; no query text in any expansion record (exact; normalised; normalised containment for "
      "queries of 4+ tokens; token near-duplicate |Q∩R|/max(|Q|,|R|) >= 0.9; >= 90% of a 3+-token query covered by an Exploit-DB title, "
      "Metasploit name or nuclei name; against Exploit-DB titles, Metasploit names and descriptions, nuclei names, PoC-in-GitHub "
      "descriptions; CVE IDs masked, identifier-only queries skipped); no T9 query copies an ATT&CK description sentence (same tests "
      "plus shared 6-token runs); every qrels and equivalence doc_id exists in the universe; test split only under `sealed/`, read-only, "
      "and the guard refuses without `TRE_OPEN_SEALED=E1`; only T7 is unanswerable.")
    w("")
    w("## Known biases and limitations")
    w("")
    w("- **T3 over-represents open-source packages** (GHSA covers package ecosystems: Maven, PyPI, npm, Packagist, Go...); T0 and T4 balance it.")
    w("- T0 is small until B2a narratives land; model-written narratives will be cleaner than analyst text (T6 offsets part of this).")
    w("- The 60% rule removes the most lexical pairs, so the remaining T3/T4 queries are harder than raw advisory/rule wording; the "
      "before-filter distributions above show how much of the raw wording copies corpus text (most GHSA summaries do).")
    w("- T2 contains only names whose mapping could be corroborated in NVD/CVE List or query-side data; famous names without such "
      "evidence (e.g. EternalBlue) are absent, which biases T2 toward names researchers published with a web page or advisory.")
    w("- T5 and T8 labels come from structured product data (CPE, CNA affected, CWE); errors there propagate. T5 leaves CVEs with "
      "undecidable version applicability unjudged rather than non-relevant. Version comparison is numeric only.")
    w("- T7 'security topics absent from the corpus' is a judgement made when writing the list; T9 templates are short and regular.")
    w("- Labels are known-item or constructed; pooled judging (B3) adds judged labels later. Absent qrels mean unjudged.")
    w("")
    w("## Sources and licences")
    w("")
    w("| Source | Used for | Licence and attribution |")
    w("|---|---|---|")
    for s, use, lic in ATTRIBUTION:
        w(f"| {s} | {use} | {lic} |")
    w("")
    w("Input snapshots (from the manifest):")
    w("")
    w("| Input | Date / version | sha256 or commit |")
    w("|---|---|---|")
    for i in m["inputs"]:
        ver = i.get("date") or i.get("commit") or ""
        h = i.get("sha256") or i.get("files_read_sha256") or i.get("commit") or ""
        w(f"| {i['name']} | {ver} | `{h}` |")
    w("")
    w("## Files")
    w("")
    w("| File | Rows | Bytes | sha256 |")
    w("|---|---|---|---|")
    for rel, f in sorted(m["files"].items()):
        w(f"| `{rel}` | {f['rows'] if f['rows'] is not None else '-'} | {f['bytes']} | `{f['sha256']}` |")
    w("")
    w("`manifest.json` itself is not listed (it records the builder commit). Split hashes: `queries.jsonl`/`qrels.jsonl` hold train+dev, "
      "`sealed/*` hold test.")
    w("")
    w("## How to rebuild and check")
    w("")
    w("```")
    w(f'python benchmarks_v2/build/build_collection.py --version {m["version"]} --out "<repo>/data/benchmark"')
    w(f'python benchmarks_v2/build/check_b2.py --version {m["version"]} --out "<repo>/data/benchmark"')
    w(f'python benchmarks_v2/build/make_dataset_card.py --version {m["version"]} --out "<repo>/data/benchmark"')
    w("```")
    w("")
    w(f"Inputs: B1 sources under `data/sources/` (LATEST snapshots) and the raw feeds under `knowledge_foundation/feeds/`; defaults "
      "resolve from the repository (or the main checkout from a git worktree), overridable with `--sources`, `--feeds` or "
      "`TRE_SOURCES_DIR` / `TRE_FEEDS_DIR`. Same inputs, seed and build date give byte-identical files (`--build-date` defaults to the "
      "newest input snapshot date). To add B2a narratives, write `data/benchmark/inputs/t0_narratives/*.jsonl` and re-run the three commands.")
    w("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=default_benchmark_dir())
    ap.add_argument("--version", default="v2.0")
    ap.add_argument("--card", type=Path, default=REPO_ROOT / "docs" / "benchmark_dataset_card.md")
    a = ap.parse_args()
    text = render(a.out / a.version)
    a.card.write_bytes(text.encode("utf-8"))
    print(f"wrote {a.card}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
