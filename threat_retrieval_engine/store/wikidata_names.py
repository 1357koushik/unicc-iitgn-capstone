"""Named vulnerabilities from Wikidata (CC0): items typed as a vulnerability that carry a CVE ID (P3587).

    python -m threat_retrieval_engine.store.wikidata_names fetch     # refresh store/data/wikidata_named_vulnerabilities.jsonl

Why: the C1 alias sources (exploit titles, Metasploit, nuclei, KEV, CNA text) do not carry many coined names
("Downfall", "BEAST", "GHOST", "VENOM"). Wikidata records them as items of type vulnerability (Q631425),
named vulnerability (Q125498109), exploit (Q11287) or hardware bug (Q65088746), or a subclass of these, with
the English label and alternative labels as names. Software items that also carry CVE IDs (browsers,
libraries) are excluded by the type filter. Leakage firewall (plan 4.3 / 6.1): Wikidata is not a benchmark
query source, and the benchmark files are never read here.

Load rules (``load``): a name is dropped when it is itself a CVE ID, shorter than 4 normalised characters
(``GDS``, ``MDS``), or made only of generic flaw words (``CRLF injection``); an item naming more CVEs than
``MAX_NICKNAME_SPREAD`` is dropped (a product or bug class, not a disclosure).
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .aliases import MAX_NICKNAME_SPREAD, is_generic_tokens
from .text import alias_norm

DATA_FILE = Path(__file__).resolve().parent / "data" / "wikidata_named_vulnerabilities.jsonl"
ENDPOINT = "https://query.wikidata.org/sparql"
QUERY = """SELECT DISTINCT ?item ?label ?alt ?cve WHERE {
  ?item wdt:P3587 ?cve . ?item wdt:P31 ?t . ?t wdt:P279* ?root .
  VALUES ?root { wd:Q631425 wd:Q11287 wd:Q65088746 wd:Q125498109 }
  OPTIONAL { ?item rdfs:label ?label FILTER(LANG(?label)="en") }
  OPTIONAL { ?item skos:altLabel ?alt FILTER(LANG(?alt)="en") } }"""
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
MIN_NORM_CHARS = 4
# flaw-class words missing from the alias module's generic vocabulary (a CWE class is not a nickname)
EXTRA_GENERIC = frozenset({"crlf"})


def fetch(out: Path = DATA_FILE, timeout: float = 120.0) -> int:
    url = ENDPOINT + "?" + urllib.parse.urlencode({"query": QUERY})
    req = urllib.request.Request(url, headers={"Accept": "text/csv", "User-Agent": "retrieval-research-client/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        rows = list(csv.DictReader(io.StringIO(r.read().decode("utf-8"))))
    items: dict[str, dict] = {}
    for x in rows:
        it = items.setdefault(x["item"], {"item": x["item"], "label": x.get("label") or "", "names": set(),
                                          "cves": set()})
        for n in (x.get("label"), x.get("alt")):
            if n:
                it["names"].add(n.strip())
        if x.get("cve"):
            it["cves"].add(x["cve"].strip().upper())
    header = {"header": True, "source": "wikidata", "licence": "CC0 1.0", "endpoint": ENDPOINT, "query": QUERY,
              "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "items": len(items)}
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(header, sort_keys=True) + "\n")
        for k in sorted(items):
            it = items[k]
            f.write(json.dumps({"item": it["item"], "label": it["label"], "names": sorted(it["names"]),
                                "cves": sorted(it["cves"])}, sort_keys=True) + "\n")
    return len(items)


def usable_name(name: str) -> bool:
    if not name or _CVE.match(name.strip()):
        return False
    if len(alias_norm(name)) < MIN_NORM_CHARS:
        return False
    toks = re.findall(r"[A-Za-z0-9]+", name)
    return bool(toks) and not is_generic_tokens([t.lower() for t in toks], EXTRA_GENERIC)


def load(path: Path = DATA_FILE) -> list[tuple[str, str, tuple[str, ...], str]]:
    """[(display name, alias_norm, CVE IDs, wikidata item)] after the load rules."""
    out = []
    if not Path(path).is_file():
        return out
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        if r.get("header"):
            continue
        cves = tuple(sorted(set(r["cves"])))
        if not cves or len(cves) > MAX_NICKNAME_SPREAD:
            continue
        for n in r["names"]:
            if usable_name(n):
                out.append((n, alias_norm(n), cves, r["item"]))
    return out


if __name__ == "__main__":
    if sys.argv[1:] == ["fetch"]:
        print(f"{fetch()} items -> {DATA_FILE}")
    else:
        print(__doc__)
