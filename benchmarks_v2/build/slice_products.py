"""T5 (product and version) and T8 (confusable siblings) slices, built from structured product data:
NVD CPE configurations and, for CVEs without CPE data, the CNA `affected` block (CVE List format, carried
in the NVD feed)."""
from __future__ import annotations

import re
from collections import defaultdict

from .common import rng, stable_key
from .cwe_phrases import classes_of, phrases
from .model import Item, qrel
from .text import overlap, token_set

_NUM_VER = re.compile(r"^\d+(?:\.\d+){0,5}$")
_NA = {"", "n/a", "na", "unknown", "unspecified", "-", "*", "all"}


def vparse(s: str) -> tuple | None:
    s = (s or "").strip()
    if s[:1] in ("v", "V") and _NUM_VER.match(s[1:]):
        s = s[1:]
    if not _NUM_VER.match(s):
        return None
    t = [int(x) for x in s.split(".")]
    while len(t) > 1 and t[-1] == 0:
        t.pop()
    return tuple(t)


def _lt(a: tuple, b: tuple) -> bool:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def cpe_applies(specs: list, v: tuple) -> bool | None:
    unknown = False
    for ver, s_inc, s_exc, e_inc, e_exc in specs:
        if ver not in ("*", "-", ""):
            pv = vparse(ver)
            if pv is None:
                unknown = True
            elif pv == v:
                return True
            continue
        if ver == "-" or not any((s_inc, s_exc, e_inc, e_exc)):
            unknown = True
            continue
        ok = True
        for b, kind in ((s_inc, "si"), (s_exc, "se"), (e_inc, "ei"), (e_exc, "ee")):
            if not b:
                continue
            pb = vparse(b)
            if pb is None:
                unknown = True
                ok = False
                break
            if kind == "si" and _lt(v, pb):
                ok = False
            elif kind == "se" and not _lt(pb, v):
                ok = False
            elif kind == "ei" and _lt(pb, v):
                ok = False
            elif kind == "ee" and not _lt(v, pb):
                ok = False
        if ok:
            return True
    return None if unknown else False


def cna_applies(entries: list[dict], v: tuple) -> bool | None:
    unknown = False
    for e in entries:
        for ver, status, lt, lte, _vt in e["ver"]:
            if status != "affected":
                continue
            if lt or lte:
                lo = (0,) if ver.strip().lower() in _NA or ver.strip() == "0" else vparse(ver)
                hi = vparse(lt or lte)
                if lo is None or hi is None:
                    unknown = True
                    continue
                if not _lt(v, lo) and (_lt(v, hi) if lt else not _lt(hi, v)):
                    return True
            else:
                pv = vparse(ver)
                if pv is None:
                    if ver.strip().lower() not in _NA:
                        unknown = True
                elif pv == v:
                    return True
        if e.get("dflt") == "affected":
            unknown = True
    return None if unknown else False


def _vstr(v: tuple) -> str:
    return ".".join(str(x) for x in (v if len(v) > 1 else v + (0,)))


def humanize_cpe(key: str) -> str:
    _, vendor, product = key.split(":", 2)
    vendor = vendor.replace("\\", "").replace("_", " ").strip()
    product = product.replace("\\", "").replace("_", " ").strip()
    if product.lower().startswith(vendor.lower()):
        return product
    return f"{vendor} {product}"


def _norm_name(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9.+ ]", " ", (s or "").lower())).strip()


def humanize_cna(vendor: str, product: str) -> str:
    v = re.sub(r"\s+", " ", vendor).strip()
    p = re.sub(r"\s+", " ", product).strip()
    if p.lower().startswith(v.lower()) or v.lower() in _NA:
        return p
    return f"{v} {p}"


class ProductIndex:
    """product key -> searchable CVEs with usable product data."""

    def __init__(self, u):
        self.u = u
        self.cpe: dict[str, list[str]] = defaultdict(list)
        self.cna: dict[str, list[str]] = defaultdict(list)
        self.cna_entries: dict[tuple[str, str], list[dict]] = defaultdict(list)
        self.cna_label: dict[str, str] = {}
        self.cna_versions: dict[str, set] = defaultdict(set)
        for cid in sorted(u.nvd):
            r = u.nvd[cid]
            if r["st"] == "Rejected" or not r["desc"]:
                continue
            if r["cpe"]:
                if r["cpe_trunc"]:
                    continue
                for key in r["cpe"]:
                    if key[:2] in ("a:", "o:"):
                        self.cpe[key].append(cid)
            else:
                for e in r["aff"]:
                    if _norm_name(e["v"]) in _NA or _norm_name(e["p"]) in _NA:
                        continue
                    key = f"cna:{_norm_name(e['v'])}:{_norm_name(e['p'])}"
                    if cid not in self.cna[key]:
                        self.cna[key].append(cid)
                    self.cna_entries[(key, cid)].append(e)
                    self.cna_label.setdefault(key, humanize_cna(e["v"], e["p"]))
                    for ver, status, lt, lte, _ in e["ver"]:
                        if status == "affected":
                            pv = vparse(ver)
                            if pv is not None and pv != (0,):
                                self.cna_versions[key].add(pv)

    def classes(self, cid: str) -> list[str]:
        return classes_of(self.u.nvd[cid]["cwe"])

    def label(self, key: str) -> str:
        return self.cna_label[key] if key.startswith("cna:") else humanize_cpe(key)

    def members(self, key: str) -> list[str]:
        return self.cna[key] if key.startswith("cna:") else self.cpe[key]

    def applies(self, key: str, cid: str, v: tuple) -> bool | None:
        if key.startswith("cna:"):
            return cna_applies(self.cna_entries[(key, cid)], v)
        return cpe_applies(self.u.nvd[cid]["cpe"][key], v)

    def known_versions(self, key: str) -> list[tuple]:
        if key.startswith("cna:"):
            return sorted(self.cna_versions[key])
        vs = set()
        for cid in self.cpe[key]:
            for ver, s_inc, *_ in self.u.nvd[cid]["cpe"][key]:
                for x in (ver, s_inc):
                    pv = vparse(x) if x not in ("*", "-") else None
                    if pv is not None and pv != (0,):
                        vs.add(pv)
        return sorted(vs)


def _pick_phrase(cls: str, target_tokens: set, r) -> str:
    opts = list(phrases(cls))
    r.shuffle(opts)
    return min(opts, key=lambda p: overlap(p, target_tokens))


# ----------------------------------------------------------------------------------------------- T5
T5_TEMPLATES = ["{p} {v} {f}", "{f} in {p} {v}", "{p} version {v} {f} vulnerability", "is {p} {v} affected by {f}?",
                "{p} {v} {f} advisory", "known {f} issues for {p} {v}"]


def build_t5(u, pidx: ProductIndex, gate, seed: int, target: int, cna_share: float = 0.35) -> tuple[list[Item], dict]:
    stats = defaultdict(int)
    items: list[Item] = []
    fams = [("cna", [k for k in pidx.cna if 2 <= len(pidx.cna[k]) <= 150]),
            ("cpe", [k for k in pidx.cpe if 2 <= len(pidx.cpe[k]) <= 150])]
    quota = {"cna": int(round(target * cna_share)), "cpe": target - int(round(target * cna_share))}
    for fam, keys in fams:
        stats[f"{fam}_products_eligible"] = len(keys)
    for rnd in (0, 1):
        for fam, keys in fams:
            limit = quota[fam] if rnd == 0 else target - len(items)
            got = 0
            for key in sorted(keys, key=lambda k: stable_key(seed, "t5", k)):
                if got >= limit or len(items) >= target:
                    break
                if any(i.meta["product_key"] == key for i in items):
                    continue
                it = _t5_for_product(u, pidx, key, seed, stats)
                if it is None:
                    continue
                if gate.accept(it):
                    items.append(it)
                    got += 1
    stats["accepted"] = len(items)
    stats["accepted_by_namespace"] = {f: sum(1 for i in items if i.meta["namespace"] == f) for f in ("cpe", "cna")}
    return items, dict(stats)


def _t5_for_product(u, pidx, key, seed, stats) -> Item | None:
    r = rng(seed, "t5", key)
    cves = pidx.members(key)
    known = pidx.known_versions(key)
    if len(known) < 2:
        stats["too_few_versions"] += 1
        return None
    targets = [c for c in cves if pidx.classes(c)]
    r.shuffle(targets)
    for t in targets[:3]:
        cls = r.choice(pidx.classes(t))
        vs = [v for v in known if pidx.applies(key, t, v) is True]
        if not vs:
            continue
        ttok = token_set(u.corpus_text(t))
        prefer = [v for v in vs if _vstr(v) not in ttok and ".".join(map(str, v)) not in ttok]
        v = r.choice(prefer or vs)
        g2, g1, unk = [], [], 0
        for c in cves:
            a = pidx.applies(key, c, v)
            if a is None:
                unk += 1
                continue
            if not a:
                continue
            cc = pidx.classes(c)
            if cls in cc:
                g2.append(c)
            elif cc:
                g1.append(c)
            else:
                unk += 1
        if not (1 <= len(g2) <= 10) or len(g1) > 40:
            stats["set_size_out_of_range"] += 1
            continue
        phrase = _pick_phrase(cls, ttok, r)
        text = r.choice(T5_TEMPLATES).format(p=pidx.label(key), v=_vstr(v), f=phrase)
        qrels = [qrel(c, 2, "known_item") for c in sorted(g2)] + [qrel(c, 1, "known_item") for c in sorted(g1)]
        return Item(slice="T5", text=text, qrels=qrels,
                    source={"name": "generated", "id": key, "licence": "derived from NVD/CVE List structured data"},
                    meta={"product_key": key, "namespace": "cna" if key.startswith("cna:") else "cpe",
                          "version": _vstr(v), "flaw_class": cls, "anchor_cve": t,
                          "grade2": len(g2), "grade1": len(g1), "unjudged_unknown_applicability": unk,
                          "version_in_target_text": _vstr(v) in ttok})
    stats["no_target_found"] += 1
    return None


# ----------------------------------------------------------------------------------------------- T8
_COMPONENT_RES = [
    re.compile(r"(?<![\w/.-])([A-Za-z0-9_\-]+\.(?:php|asp|aspx|jsp|jspx|do|action|cgi|pl|py|js|c|cc|cpp|h|dll|exe|sys|so|rb|java|go|sh|ashx|asmx|htm|html))(?![\w])"),
    re.compile(r"\b(mod_[a-z0-9_]+)\b"),
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\(\)"),
    re.compile(r"\b[Tt]he ([A-Z][\w\-]*(?: [A-Z][\w\-]*){0,3}) (?:component|module|plugin|subsystem|service|feature|driver|endpoint|API|interface|function|widget|extension|handler|parser)\b"),
]
T8_COMPONENT_TEMPLATES = ["{p} {c} {f}", "{f} in {c} of {p}", "{p} {f} through {c}", "{c} {f} {p}"]
T8_COMPONENT_NOFLAW = ["{p} {c} issue", "flaw in {c} of {p}", "{p} {c} bug"]
T8_FLAW_TEMPLATES = ["{p} {f}", "{f} affecting {p}", "{p} {f} bug", "which {p} issue is the {f}"]


def components(desc: str) -> list[str]:
    out = []
    for rx in _COMPONENT_RES:
        for m in rx.finditer(desc):
            c = m.group(1).strip()
            if 3 <= len(c) <= 60 and c not in out:
                out.append(c)
    return out


def build_t8(u, pidx: ProductIndex, gate, seed: int, target: int, max_siblings: int = 10) -> tuple[list[Item], dict]:
    stats = defaultdict(int)
    items: list[Item] = []
    keys = [k for k in list(pidx.cpe) + list(pidx.cna) if 3 <= len(pidx.members(k)) <= 400]
    stats["products_eligible"] = len(keys)
    used_targets: set[str] = set()
    for key in sorted(keys, key=lambda k: stable_key(seed, "t8", k)):
        if len(items) >= target:
            break
        it = _t8_for_product(u, pidx, key, seed, stats, used_targets, max_siblings)
        if it is None:
            continue
        if gate.accept(it):
            items.append(it)
            used_targets.add(it.targets()[0])
    stats["accepted"] = len(items)
    stats["accepted_by_family"] = {f: sum(1 for i in items if i.meta["discriminator"] == f)
                                   for f in ("component", "unique_flaw_class")}
    return items, dict(stats)


def _t8_for_product(u, pidx, key, seed, stats, used, max_siblings) -> Item | None:
    r = rng(seed, "t8", key)
    cves = list(pidx.members(key))
    descs = {c: u.description(c) for c in cves}
    low = {c: d.lower() for c, d in descs.items()}
    order = cves[:]
    r.shuffle(order)
    for t in order[:6]:
        if t in used:
            continue
        sibs = [c for c in cves if c != t]
        cls_t = pidx.classes(t)
        comps = [c for c in components(descs[t]) if not any(c.lower() in low[s] for s in sibs)]
        ttok = token_set(u.corpus_text(t))
        fam = None
        if comps:
            fam = "component"
            comp = r.choice(comps)
        else:
            sib_cls = [set(pidx.classes(s)) for s in sibs]
            known_sibs = [s for s in sib_cls if s]
            uniq = [c for c in cls_t if not any(c in s for s in sib_cls)]
            if uniq and len(known_sibs) >= 3:
                fam = "unique_flaw_class"
                cls = r.choice(uniq)
        if fam is None:
            continue
        label = pidx.label(key)
        if fam == "component":
            if cls_t:
                cls = r.choice(cls_t)
                text = r.choice(T8_COMPONENT_TEMPLATES).format(p=label, c=comp, f=_pick_phrase(cls, ttok, r))
            else:
                cls = None
                text = r.choice(T8_COMPONENT_NOFLAW).format(p=label, c=comp)
        else:
            text = r.choice(T8_FLAW_TEMPLATES).format(p=label, f=_pick_phrase(cls, ttok, r))
        # siblings: same flaw class first (most confusable), then nearest by publication date
        tp = u.published(t)
        same = sorted([s for s in sibs if cls and cls in pidx.classes(s)], key=lambda s: stable_key(seed, "sib", t, s))
        rest = sorted([s for s in sibs if s not in same], key=lambda s: (abs(_days(u.published(s)) - _days(tp)), s))
        chosen = (same + rest)[:max_siblings]
        qrels = [qrel(t, 2, "known_item")] + [qrel(s, 0, "authoring") for s in sorted(chosen)]
        meta = {"product_key": key, "namespace": "cna" if key.startswith("cna:") else "cpe", "discriminator": fam,
                "flaw_class": cls, "siblings_in_product": len(sibs), "siblings_listed": len(chosen),
                "siblings_same_flaw_class": sum(1 for s in chosen if s in same)}
        if fam == "component":
            meta["component"] = comp
        return Item(slice="T8", text=text, qrels=qrels,
                    source={"name": "generated", "id": key, "licence": "derived from NVD/CVE List structured data"},
                    meta=meta)
    stats["no_discriminator"] += 1
    return None


def _days(d: str) -> int:
    try:
        y, m, dd = (int(x) for x in d[:10].split("-"))
        return y * 372 + m * 31 + dd
    except ValueError:
        return 0
