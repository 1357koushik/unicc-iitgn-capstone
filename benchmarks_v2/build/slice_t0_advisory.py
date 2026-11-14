"""T0 advisory excerpts: deterministic excerpts of real incident advisories (ACSC, NCSC UK; role `incident`).

For every advisory: split into paragraphs, drop headings, dates, bullet/numbered lists, navigation,
recommendation and contact sentences; join the remaining consecutive prose sentences into runs; cut runs
into excerpts of 2-8 sentences and at most 1,200 characters; keep up to 3 non-overlapping excerpts with
the strongest activity signal (CVE IDs, affected products, named actors or malware, exploitation words).

Targets: grade 2 for CVEs named in the excerpt, or advisory CVEs whose product is named in the excerpt and
whose vendor is named in the excerpt or the advisory title (when more than 10 advisory CVEs match that way the match is too generic and they become
grade 1); grade 1 for the advisory's other CVEs (at most 30); grade 2 for ATT&CK groups and software
named by exact name or alias, and for ATT&CK techniques cited by ID (e.g. "[T1213.002]"). An excerpt needs at least one grade-2 target. About 60% of excerpts that
contain CVE IDs have every ID replaced by a neutral phrase (seeded; `meta.id_masked`).
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict

from .common import rng
from .model import Item, qrel
from .slice_products import find_span, slug_tokens
from .text import CVE_FIND_RE, sentences

INCIDENT_SOURCES = ("acsc_advisories", "ncsc_uk_advisories")
MAX_PER_ADVISORY = 3
MIN_SENT, MAX_SENT, MAX_CHARS = 2, 8, 1200
MASK_SHARE = 0.6
SINGLE_MIN_WORDS = 20   # fallback: one long factual sentence, only for advisories with no 2+ sentence excerpt
REMOVED = "\x00removed"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_TECH = re.compile(r"(?<![A-Za-z0-9])(T\d{4}(?:\.\d{3})?)(?![\d.])")
_BULLET = re.compile(r"^\s*(?:[-*•–]|\d+[.)]|[a-z][.)])\s+")
_DATE_LINE = re.compile(r"^\s*\d{1,2} [A-Z][a-z]+ \d{4}\s*$")
_BOILER = re.compile(
    r"\b(recommend\w*|should|advis(?:e|es|ed|ory is)|urg(?:e|es|ed|ing)|encourag\w+|consider|we suggest|contact\w*|"
    r"report (?:it|any|this|to|incidents)|visit|for more information|further information|sign up|subscribe|1300|e-?mail|"
    r"click|download|read more|see (?:the|our)|following (?:guidance|mitigations|actions)|mitigat\w+|apply (?:the|all|any)|"
    r"update to|upgrade to|ensure|copyright|licen[cs]e|cookie|this (?:page|publication|alert|advisory|report|blog) "
    r"(?:is|was|provides|describes|contains)|priority actions|network defenders|best practice|step \d)\b", re.I)
_SIGNAL = re.compile(r"\b(exploit\w*|actively|observed|in the wild|compromis\w+|actor\w*|threat|malware|ransomware|"
                     r"campaign\w*|target\w*|attack\w*|vulnerab\w+|affect\w*|backdoor\w*|intrusion\w*|espionage|"
                     r"state-sponsored|deploy\w*|webshell\w*|web shell\w*|phishing|access|breach\w*|stole|exfiltrat\w+)\b",
                     re.I)
# ATT&CK software/group names that are ordinary words and would match by accident
_COMMON = {"at", "net", "ping", "tor", "reg", "cmd", "expand", "page", "ftp", "route", "replace", "empire", "proton",
           "gold", "agent", "mosaic", "transparent", "cardinal", "olympic", "volatile", "ember", "sharp", "ruler",
           "flame", "carbon", "machete", "tasklist", "systeminfo", "ipconfig", "netstat", "whoami", "nltest",
           "dsquery", "arp", "certutil", "esentutl", "forfiles", "schtasks", "xcopy", "wiper", "pony", "zox"}


def _fix_encoding(s: str) -> str:
    s = re.sub(r"(?<=\w)�(?=s\b)", "'", s)
    return s.replace(" � ", " - ").replace("�", "'")


def _parse_cves(v) -> list[str]:
    if isinstance(v, list):
        items = v
    else:
        try:
            items = ast.literal_eval(v) if isinstance(v, str) and v.strip().startswith("[") else []
        except (ValueError, SyntaxError):
            items = []
        if not items:
            items = _CVE.findall(str(v or ""))
    return sorted({str(x).upper() for x in items if _CVE.fullmatch(str(x).strip())})


def runs_of_prose(text: str) -> list[list[str]]:
    """Prose sentences grouped into runs. Headings, date lines, lists and short label lines break a run;
    recommendation, contact and link sentences are removed (counted in a "[removed]" marker that
    `chunks` records) without breaking it, so the facts around a removed sentence stay together."""
    runs: list[list[str]] = []
    cur: list[str] = []

    def close():
        nonlocal cur
        if cur:
            runs.append(cur)
        cur = []

    for para in re.split(r"\n\s*\n", _fix_encoding(text or "")):
        para = para.strip()
        if not para:
            continue
        lines = [ln.strip() for ln in para.splitlines() if ln.strip()]
        if any(_BULLET.match(ln) for ln in lines) or _DATE_LINE.match(para):
            close()
            continue
        flat = " ".join(lines)
        words = flat.split()
        if not re.search(r"[.!]$", flat) or len(words) < 8 or flat.endswith("?"):
            close()          # heading, label line, version line or question heading
            continue
        for s in sentences(flat):
            if _BOILER.search(s) or "http" in s.lower() or "www." in s.lower() or len(s.split()) < 4:
                if cur:
                    cur.append(REMOVED)
                continue
            cur.append(s)
    close()
    return runs


def chunks(run: list[str], min_sent: int = MIN_SENT) -> list[list[str]]:
    """2-8 kept sentences, <= MAX_CHARS; the number of removed sentences inside a chunk is appended as an
    int at the end of the list by `split_chunk`."""
    while run and run[-1] == REMOVED:
        run = run[:-1]
    out, cur, size = [], [], 0
    for s in run:
        if s == REMOVED:
            if cur:
                cur.append(s)
            continue
        if cur and (sum(1 for x in cur if x != REMOVED) >= MAX_SENT or size + 1 + len(s) > MAX_CHARS):
            out.append(cur)
            cur, size = [], 0
        if len(s) > MAX_CHARS:
            continue
        cur.append(s)
        size += len(s) + 1
    if cur:
        if sum(1 for x in cur if x != REMOVED) < MIN_SENT and out and \
                sum(1 for x in out[-1] if x != REMOVED) < MAX_SENT and \
                sum(len(x) + 1 for x in out[-1]) + size <= MAX_CHARS:
            out[-1] += cur
        else:
            out.append(cur)
    out = [[x for x in c] for c in out]
    for c in out:
        while c and c[-1] == REMOVED:
            c.pop()
    return [c for c in out if sum(1 for x in c if x != REMOVED) >= min_sent]


def split_chunk(ch: list[str]) -> tuple[str, int, int]:
    kept = [x for x in ch if x != REMOVED]
    return " ".join(kept), len(kept), sum(1 for x in ch if x == REMOVED)


class _ProductNames:
    """Vendor/product names per CVE from the NVD CNA affected block, CPE keys and KEV."""

    def __init__(self, u):
        self.u = u
        self._cache: dict[str, list[tuple[list[str], list[str]]]] = {}

    def names(self, cid: str) -> list[tuple[list[str], list[str]]]:
        if cid in self._cache:
            return self._cache[cid]
        out = []
        r = self.u.nvd.get(cid)
        if r:
            for a in r["aff"]:
                v, p = slug_tokens(a["v"]), slug_tokens(a["p"])
                if v and p and "".join(v) not in ("na", "") and "".join(p) not in ("na", ""):
                    out.append((v, p))
            for key in r["cpe"]:
                _, vs, ps = key.split(":", 2)
                out.append((slug_tokens(vs), slug_tokens(ps)))
        k = self.u.kev.get(cid)
        if k:
            out.append((slug_tokens(k["vendor"]), slug_tokens(k["product"])))
        # parenthetical abbreviations, e.g. "Endpoint Manager Mobile (EPMM)" -> EPMM
        raw = [(a["v"], a["p"]) for a in (r["aff"] if r else [])] + ([(k["vendor"], k["product"])] if k else [])
        for v, p in raw:
            for ab in re.findall(r"\(([A-Za-z][A-Za-z0-9-]{2,15})\)", p or ""):
                out.append((slug_tokens(v), slug_tokens(ab)))
        seen, uniq = set(), []
        for v, p in out:
            key = ("".join(v), "".join(p))
            if key not in seen and v and p:
                seen.add(key)
                uniq.append((v, p))
        self._cache[cid] = uniq
        return uniq

    def named_in(self, cid: str, text: str, title: str = "") -> bool:
        """Product named in the excerpt and vendor named in the excerpt or the advisory title."""
        return any(find_span(p, text) and (find_span(v, text) or find_span(v, title)) for v, p in self.names(cid))


def _attack_index(kb) -> list[tuple[str, str]]:
    """(surface name, attack_id) for active groups and software, unique names only, common words excluded."""
    surf: dict[str, set] = defaultdict(set)
    for aid, o in kb.objects.items():
        if o["kind"] not in ("group", "software"):
            continue
        forms = [o["name"]] + list(o.get("aliases") or [])
        # "Sandworm Team" -> "Sandworm", "Lazarus Group" -> "Lazarus" (kept only when unique)
        forms += [re.sub(r"\s+(Team|Group)$", "", f) for f in forms if re.search(r"\s+(Team|Group)$", f)]
        for n in forms:
            n = n.strip()
            if len(n) < 4 or n.lower() in _COMMON:
                continue
            surf[n].add(aid)
    return sorted((n, next(iter(ids))) for n, ids in surf.items() if len(ids) == 1)


def _named_entities(text: str, index: list[tuple[str, str]]) -> list[tuple[str, str]]:
    found = []
    for n, aid in index:
        if n in text and re.search(r"(?<![A-Za-z0-9])" + re.escape(n) + r"(?![A-Za-z0-9])", text):
            found.append((n, aid))
    return found


def mask_ids(text: str) -> tuple[str, list[str]]:
    ids = [m.group(0).upper() for m in CVE_FIND_RE.finditer(text)]
    t = re.sub(r"\s*\(\s*(?:CVE[-_ ]?\d{4}[-_ ]\d{4,}\s*(?:,|and|&|/)?\s*)+\)", "", text, flags=re.I)
    k = 0

    def rep(_m):
        nonlocal k
        k += 1
        return "a vulnerability" if k == 1 else "another vulnerability"

    t = CVE_FIND_RE.sub(rep, t)
    t = re.sub(r"\ban? a vulnerability\b", "a vulnerability", t)
    return re.sub(r"\s{2,}", " ", t).strip(), ids


def build_advisory_excerpts(u, kb, srcs, gate, seed: int) -> tuple[list[Item], dict]:
    stats = defaultdict(int)
    pn = _ProductNames(u)
    aidx = _attack_index(kb) if kb.available else []
    items: list[Item] = []
    for sname in INCIDENT_SOURCES:
        s = srcs.get(sname, "query_text")
        if s is None:
            stats[f"{sname}_missing"] += 1
            continue
        if s.role != "incident":
            raise RuntimeError(f"{sname} must have role incident")
        lic = s.licence
        recs = sorted(s.records(), key=lambda r: r["advisory_id"])
        stats[f"{sname}_advisories"] = len(recs)
        for rec in recs:
            adv_cves = sorted(set(_parse_cves(rec.get("cve_ids"))) | {x.upper() for x in _CVE.findall(rec.get("text") or "")})
            runs = runs_of_prose(rec.get("text") or "")
            produced = 0
            for fallback in (False, True):
                if fallback and produced:
                    break
                produced += _excerpts_for(rec, sname, lic, runs, fallback, adv_cves, pn, aidx, kb, gate, seed,
                                          items, stats)
            if produced == 0:
                stats[f"{sname}_advisories_without_excerpt"] += 1
            stats[f"{sname}_excerpts"] += produced
    stats["accepted"] = len(items)
    stats["single_sentence_fallback"] = sum(1 for i in items if i.meta.get("single_sentence_fallback"))
    return items, dict(stats)


def _excerpts_for(rec, sname, lic, runs, fallback, adv_cves, pn, aidx, kb, gate, seed, items, stats) -> int:
    """Excerpts for one advisory; with `fallback`, at most one single long sentence."""
    cands = []
    for pos, run in enumerate(runs):
        pieces = chunks(run) if not fallback else [[x] for x in run if x != REMOVED
                                                   and len(x.split()) >= SINGLE_MIN_WORDS]
        for j, ch in enumerate(pieces):
            text, nkept, nremoved = split_chunk(ch)
            named = sorted({m.upper() for m in _CVE.findall(text)})
            prod = [c for c in adv_cves if c not in named and pn.named_in(c, text, rec.get("title") or "")]
            ents = _named_entities(text, aidx)
            techs = sorted({t for t in _TECH.findall(text) if kb.available and t in kb.objects
                            and kb.objects[t]["kind"] == "technique"})
            ents += [(t, t) for t in techs]
            score = 3 * len(named) + 2 * bool(prod) + 2 * len(ents) + len(_SIGNAL.findall(text))
            cands.append(((-score, pos, j), text, named, prod, ents, (nkept, nremoved)))
    produced = 0
    for _, text, named, prod, ents, nsent in sorted(cands)[:MAX_PER_ADVISORY * 3]:
        if produced >= (1 if fallback else MAX_PER_ADVISORY):
            break
        qrels, seen = [], set()
        generic = len(prod) > 10
        for c in named + ([] if generic else prod):
            r = gate.resolve_cve(c)
            if r and r[0] not in seen:
                seen.add(r[0])
                qrels.append(qrel(r[0], 2, "authoring" if r[1] == "known_item" else "equivalence"))
        for n, aid in ents:
            d = f"attack:{aid}"
            if d not in seen:
                seen.add(d)
                qrels.append(qrel(d, 2, "authoring"))
        if not any(q["grade"] == 2 for q in qrels):
            stats["excerpt_without_grade2_target"] += 1
            continue
        g1 = 0
        for c in adv_cves:
            if g1 >= 30:
                break
            r = gate.resolve_cve(c)
            if r and r[0] not in seen:
                seen.add(r[0])
                qrels.append(qrel(r[0], 1, "authoring"))
                g1 += 1
        idx = produced
        masked, mids = False, []
        if named and rng(seed, "t0mask", sname, rec["advisory_id"], text[:80]).random() < MASK_SHARE:
            text, mids = mask_ids(text)
            masked = True
        meta = {"t0_kind": "advisory_excerpt", "advisory_title": rec.get("title", ""),
                "advisory_published": rec.get("published", ""), "advisory_doc_type": rec.get("doc_type", ""),
                "sentences": nsent[0], "boilerplate_sentences_removed": nsent[1],
                "single_sentence_fallback": fallback, "id_masked": masked, "masked_ids": mids,
                "cves_named": named, "cves_by_product_name": prod,
                "product_match_too_generic": generic,
                "attack_entities": [{"name": n, "doc_id": f"attack:{a}"} for n, a in ents]}
        it = Item(slice="T0", text=text, qrels=qrels, meta=meta,
                  link_keys={f"advisory:{sname}:{rec['advisory_id']}"},
                  source={"name": sname, "id": rec["advisory_id"], "licence": lic, "url": rec.get("url", "")})
        if gate.accept(it):
            items.append(it)
            produced += 1
            stats["excerpts_id_masked"] += masked
    return produced
