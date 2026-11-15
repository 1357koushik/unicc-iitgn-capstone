"""Entity-name gazetteer for the query parser: ATT&CK names and aliases of groups, software, techniques and
campaigns -> doc_ids, with ambiguity and a short/common-word policy stored as data.

Build side (`build_entries`, `corpus_df`, `assign_policy`) runs inside the C9 build; the result is the
`gazetteer` and `gazetteer_keys` tables plus the policy JSON in `meta`. Run side (`Gazetteer.match`) is what
the parser (C4) and the v1 pipeline apply to text.

Names.  Every name and alias of an active group, software, technique or campaign; for a sub-technique also
the qualified form "Parent: Sub" (ATT&CK's own display form, unambiguous where the bare sub-technique name is
not, e.g. "Domain Accounts"). Names of revoked objects point to their replacement, but only when no active
object uses the name. Mitigation names are left out: they are generic phrases ("User Training", "Audit")
that would fire on ordinary text; mitigations are reached by ID or retrieval. Short forms analysts write
("Sandworm", "Lazarus", "LockBit") are derived from the long names (`derive_short_forms`). Keys are C1 `alias_norm`
(lower-case alphanumerics), so "APT 29", "APT29" and "apt-29" are one key.

Token alignment.  A text span matches a key when its letter/digit runs, joined, equal the key and the span has
no more runs than the ATT&CK spelling: "CobaltStrike" matches "Cobalt Strike", "APT 29" matches "APT29",
but "bad news" does not match the software "BADNEWS".

Short/common-word policy (decided here; see `POLICY`).  A key is `restricted` when
  * it has at most 3 characters (at, cmd, Net, Reg, ...), or
  * it is a term of the CVE corpus: it occurs, token-aligned and in any letter case, in at least
    `corpus_term_min_df` searchable CVE descriptions of the C1 store build. That catches ordinary words
    (page, ping, route, expand), and names ATT&CK shares with products that have CVEs (CHROMIUM, Mantis,
    James, Spark, Pandora, Confluence, DragonFly), which in this service's queries usually mean the product.
    It is a corpus measurement, not a word list; the count of every key is stored (`gazetteer_keys.df_cve`).
A restricted name matches only with a marker that it is meant as the entity:
  1. `whole_query`: the query is the name alone (quotes and punctuation ignored), e.g. the query "Net";
  2. `quoted`: the name is written in quotes, e.g. 'the "at" utility';
  3. `kind_marker`: a word naming its kind is within `marker_window` tokens, e.g. "net command",
     "the cmd utility", "ATT&CK software Net".
Every other key (`anywhere`) matches wherever it occurs, case-insensitively. ATT&CK IDs always match.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .text import ATTACK_ID_IN_TEXT, alias_norm, fine_token_spans, fine_tokens, normalize_attack_id

GAZETTEER_KINDS = ("group", "software", "technique", "campaign")
ORIGIN_RANK = {"name": 0, "qualified_name": 1, "alias": 2, "revoked_name": 3, "derived_short_form": 4}

POLICY = {
    "version": 1,
    "short_max_chars": 3,
    # A key named in >= 10 searchable CVE descriptions (about 1 in 40,000) is a term of the corpus. Measured on
    # store build 20261115T014008Z-f7f744ffa8: 84% of keys occur in none, and the distribution has no gap.
    # At 10 and above the names are overwhelmingly ordinary words or products with CVEs of their own (Page,
    # Server, Python, Confluence, CHROMIUM, Spark, Empire, Sliver, ScreenConnect); below 10 they are mostly
    # incidental mentions of the malware itself (Cobalt Strike 4, Conti 4, Stuxnet 4, BloodHound 4). The
    # value was set from this corpus list alone, not from benchmark queries.
    "corpus_term_min_df": 10,
    "marker_window": 2,
    # Kind words, not entity names: a word that is itself an ATT&CK name (e.g. "Wiper") is not a marker, and
    # check_c9 fails on any string literal in the package that equals an ATT&CK group/software name.
    "kind_markers": {
        "group": ["group", "groups", "actor", "actors", "apt", "gang", "crew", "intrusion", "adversary"],
        "software": ["software", "malware", "tool", "tools", "utility", "utilities", "backdoor", "trojan", "rat",
                     "ransomware", "implant", "loader", "dropper", "downloader", "binary", "command",
                     "commands", "worm", "botnet", "stealer", "keylogger", "rootkit", "framework", "exe"],
        "technique": ["technique", "techniques", "subtechnique", "subtechniques", "ttp", "ttps"],
        "campaign": ["campaign", "campaigns", "operation"],
    },
    "quote_chars": "\"'`“”‘’«»",
    "rules": ["restricted keys match only by whole_query, quoted or kind_marker",
              "anywhere keys match by token-aligned case-insensitive lookup",
              "ATT&CK IDs always match and follow revocation to the replacement",
              "overlapping candidates: ID first, then the longest span, then the leftmost"],
}


# =========================================================================== build side
# Derived short forms (origin `derived_short_form`). Analysts write "Sandworm" for "Sandworm Team", "Lazarus" for
# "Lazarus Group" and "LockBit" for "LockBit 2.0"/"LockBit 3.0"; ATT&CK lists only the long forms.
#  * A trailing generic word is stripped from group, software and campaign names and aliases, repeatedly while
#    one remains ("Ajax Security Team" -> "Ajax Security"). The words: GENERIC_TRAILING_WORDS.
#  * A trailing version is stripped from software names and aliases: a separator then digits with optional
#    dots and a letter, optionally after "v"/"ver"/"version" ("LockBit 3.0", "BlackEnergy 3", "Foo v2",
#    "Bar-2.1b"). Digits glued to letters are part of the name and stay ("T9000", "BS2005", "APT29").
#  * The remainder must keep at least one letter run and differ from the source. A derived form never
#    displaces a real name or alias: if its key already names another object (real names and aliases, active
#    or revoked), it is recorded in `gazetteer_collisions` and not added. If several objects derive one key,
#    all are candidates (ambiguous by design, e.g. every LockBit version). Derived keys go through the same
#    short/corpus-term policy as real ones, which keeps "Cobalt" (Cobalt Group) and "Medusa" restricted.
GENERIC_TRAILING_WORDS = ("team", "group", "gang", "crew", "apt", "actor", "actors", "cluster", "campaign")
DERIVE_KINDS = ("group", "software", "campaign")
_VERSION_TAIL = re.compile(r"[\s._-]+(?:v(?:er(?:sion)?)?\.?\s*)?\d+(?:\.\d+)*[a-z]?$", re.IGNORECASE)
_TRAIL_WORD = re.compile(r"^(?P<head>.*\S)[\s._-]+(?P<word>[A-Za-z]+)[\s.]*$")


def derive_short_forms(surface: str, kind: str) -> list[str]:
    """Short forms derived from one ATT&CK name or alias, shortest last (empty when no rule applies)."""
    if kind not in DERIVE_KINDS:
        return []
    out: list[str] = []
    cur = (surface or "").strip()
    for _ in range(4):
        nxt = cur
        m = _TRAIL_WORD.match(cur)
        if m and m.group("word").lower() in GENERIC_TRAILING_WORDS:
            nxt = m.group("head").strip(" -_.")
        elif kind == "software":
            nxt = _VERSION_TAIL.sub("", cur).strip(" -_.")
        if nxt == cur or not re.search(r"[A-Za-z]", nxt):
            break
        cur = nxt
        if alias_norm(cur) and alias_norm(cur) != alias_norm(surface):
            out.append(cur)
    return list(dict.fromkeys(out))


def build_entries(docs: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    """(gazetteer rows {key, doc_id, doc_kind, surface, origin, fine_tokens}, derived-form collisions
    {key, surface, derived_from, existing})."""
    rows: dict[tuple[str, str], dict] = {}

    def add(surface: str, doc: dict, origin: str) -> None:
        key = alias_norm(surface)
        if not key:
            return
        r = {"key": key, "doc_id": doc["doc_id"], "doc_kind": doc["doc_kind"], "surface": surface,
             "origin": origin, "fine_tokens": len(fine_tokens(surface))}
        old = rows.get((key, doc["doc_id"]))
        if old is None or ORIGIN_RANK[origin] < ORIGIN_RANK[old["origin"]]:
            if old is not None:
                r["fine_tokens"] = max(r["fine_tokens"], old["fine_tokens"])
            rows[(key, doc["doc_id"])] = r
        else:
            old["fine_tokens"] = max(old["fine_tokens"], r["fine_tokens"])

    active = [d for d in docs.values() if d["doc_kind"] in GAZETTEER_KINDS and d["state"] == "active"]
    for d in active:
        add(d["name"], d, "name")
        if d["title"] != d["name"]:
            add(d["title"], d, "qualified_name")
        for a in d["aliases_list"]:
            add(a, d, "alias")
    active_keys = {k for k, _ in rows}
    for d in docs.values():
        if d["doc_kind"] not in GAZETTEER_KINDS or d["state"] != "revoked" or not d.get("revoked_by"):
            continue
        target = docs[d["revoked_by"]]
        for s in [d["name"], *d["aliases_list"]]:
            k = alias_norm(s)
            if k and k not in active_keys:
                add(s, target, "revoked_name")
    # derived short forms go only into keys that no real name or alias uses for another object
    real: dict[str, set[str]] = defaultdict(set)
    for (k, doc_id) in rows:
        real[k].add(doc_id)
    collisions: dict[tuple[str, str], dict] = {}
    for d in sorted(active, key=lambda x: x["doc_id"]):
        for s in [d["name"], *d["aliases_list"]]:
            for short in derive_short_forms(s, d["doc_kind"]):
                k = alias_norm(short)
                if k in real:
                    if real[k] != {d["doc_id"]}:
                        collisions.setdefault((k, d["doc_id"]), {
                            "key": k, "surface": short, "derived_from": f"{d['doc_id']} ({s})",
                            "existing": sorted(real[k])})
                    continue
                add(short, d, "derived_short_form")
    return [rows[k] for k in sorted(rows)], [collisions[k] for k in sorted(collisions)]


def _prefixes(keys: Iterable[str]) -> set[str]:
    out = set()
    for k in keys:
        for i in range(1, len(k) + 1):
            out.add(k[:i])
    return out


_FINE_STR = re.compile(r"[^\W\d_]+|\d+")


def corpus_df(texts: Iterable[str], entries: list[dict], log: Callable[[str], None] | None = None) -> Counter:
    """For each key: the number of texts in which it occurs token-aligned, in any letter case."""
    max_ft: dict[str, int] = defaultdict(int)
    for e in entries:
        max_ft[e["key"]] = max(max_ft[e["key"]], e["fine_tokens"])
    pref = _prefixes(max_ft)
    longest = max(max_ft.values()) if max_ft else 0
    df: Counter = Counter()
    n = 0
    for text in texts:
        n += 1
        if not text:
            continue
        toks = [t.lower() if t.isascii() else alias_norm(t) for t in _FINE_STR.findall(text)]
        seen = set()
        last = len(toks)
        for i in range(last):
            if toks[i] not in pref:
                continue
            acc = ""
            for j in range(i, min(last, i + longest)):
                acc += toks[j]
                if acc not in pref:
                    break
                if acc in max_ft and j - i + 1 <= max_ft[acc]:
                    seen.add(acc)
        df.update(seen)
        if log and n % 100000 == 0:
            log(f"  corpus-term scan: {n} texts")
    return df


def assign_policy(entries: list[dict], df: Counter, policy: dict = POLICY) -> list[dict]:
    """gazetteer_keys rows {key, n_docs, kinds, policy, reason, df_cve}."""
    by_key = defaultdict(list)
    for e in entries:
        by_key[e["key"]].append(e)
    out = []
    for k in sorted(by_key):
        es = by_key[k]
        reasons = []
        if len(k) <= policy["short_max_chars"]:
            reasons.append("short")
        if df.get(k, 0) >= policy["corpus_term_min_df"]:
            reasons.append("corpus_term")
        out.append({"key": k, "n_docs": len({e["doc_id"] for e in es}),
                    "kinds": ",".join(sorted({e["doc_kind"] for e in es})),
                    "policy": "restricted" if reasons else "anywhere", "reason": "+".join(reasons) or None,
                    "df_cve": int(df.get(k, 0))})
    return out


# =========================================================================== run side
@dataclass(frozen=True)
class Candidate:
    doc_id: str
    doc_kind: str
    surface: str        # the ATT&CK spelling of the name or alias that matched
    origin: str         # name | qualified_name | alias | revoked_name | id | revoked_id


@dataclass(frozen=True)
class Mention:
    start: int
    end: int
    text: str                     # the span as written in the input
    key: str                      # normalised key, or the ATT&CK ID for ID mentions
    candidates: tuple[Candidate, ...]
    policy: str                   # anywhere | restricted | id
    matched_by: str               # id | anywhere | whole_query | quoted | kind_marker

    @property
    def doc_ids(self) -> tuple[str, ...]:
        return tuple(c.doc_id for c in self.candidates)

    @property
    def ambiguous(self) -> bool:
        return len(self.candidates) > 1

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted({c.doc_kind for c in self.candidates}))


@dataclass
class Gazetteer:
    entries: dict[str, list[Candidate]]                     # key -> candidates (sorted by doc_id)
    key_info: dict[str, dict]                               # key -> gazetteer_keys row
    max_fine: dict[str, int]                                # key -> most letter/digit runs a span may have
    policy: dict
    resolve_id: Callable[[str], tuple[str, str, str] | None]  # ATT&CK ID -> (doc_id, doc_kind, origin)
    _prefix: set[str] = field(default_factory=set)
    _longest: int = 0
    _markers: dict[str, frozenset] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._prefix = _prefixes(self.entries)
        self._longest = max(self.max_fine.values()) if self.max_fine else 0
        self._markers = {k: frozenset(alias_norm(w) for w in v) for k, v in self.policy["kind_markers"].items()}

    @classmethod
    def from_rows(cls, entries: Iterable[dict], keys: Iterable[dict], policy: dict,
                  resolve_id: Callable[[str], tuple[str, str, str] | None]) -> "Gazetteer":
        ent: dict[str, list[Candidate]] = defaultdict(list)
        mf: dict[str, int] = defaultdict(int)
        for e in entries:
            ent[e["key"]].append(Candidate(e["doc_id"], e["doc_kind"], e["surface"], e["origin"]))
            mf[e["key"]] = max(mf[e["key"]], int(e["fine_tokens"]))
        for k in ent:
            ent[k].sort(key=lambda c: c.doc_id)
        return cls(dict(ent), {k["key"]: dict(k) for k in keys}, dict(mf), policy, resolve_id)

    def __len__(self) -> int:
        return len(self.entries)

    # ------------------------------------------------------------------ exact lookup
    def lookup(self, name: str, kinds: Iterable[str] | None = None) -> list[Candidate]:
        ks = set(kinds) if kinds else None
        return [c for c in self.entries.get(alias_norm(name), []) if ks is None or c.doc_kind in ks]

    def is_restricted(self, name: str) -> bool:
        info = self.key_info.get(alias_norm(name))
        return bool(info) and info["policy"] == "restricted"

    # ------------------------------------------------------------------ matching
    def _quoted(self, text: str, start: int, end: int) -> bool:
        q = self.policy["quote_chars"]
        a = start - 1
        while a >= 0 and text[a] == " ":
            a -= 1
        b = end
        while b < len(text) and text[b] == " ":
            b += 1
        return a >= 0 and b < len(text) and text[a] in q and text[b] in q

    def _marker(self, toks: list, i: int, j: int, kinds: Iterable[str]) -> bool:
        w = self.policy["marker_window"]
        near = {t[0] for t in toks[max(0, i - w):i]} | {t[0] for t in toks[j + 1:j + 1 + w]}
        return any(near & self._markers.get(k, frozenset()) for k in kinds)

    def match(self, text: str, *, query: bool = True, kinds: Iterable[str] | None = None) -> list[Mention]:
        """Entity mentions in `text`, non-overlapping, in text order. `query=False` for document text: the
        whole-query marker then never applies. `kinds` filters candidates (a mention with none left is
        dropped)."""
        if not text:
            return []
        ks = set(kinds) if kinds else None
        found: list[tuple[int, int, int, Mention]] = []   # (priority, -length, start, mention)
        for m in ATTACK_ID_IN_TEXT.finditer(text):
            aid = normalize_attack_id(m.group(1))
            hit = self.resolve_id(aid) if aid else None
            if not hit or (ks and hit[1] not in ks):
                continue
            c = Candidate(hit[0], hit[1], aid, hit[2])
            found.append((0, -(m.end(1) - m.start(1)), m.start(1),
                          Mention(m.start(1), m.end(1), m.group(1), aid, (c,), "id", "id")))
        toks = fine_token_spans(text)
        n = len(toks)
        for i in range(n):
            acc = ""
            for j in range(i, min(n, i + self._longest)):
                acc += toks[j][0]
                if acc not in self._prefix:
                    break
                cands = self.entries.get(acc)
                if not cands or j - i + 1 > self.max_fine[acc]:
                    continue
                if ks:
                    cands = [c for c in cands if c.doc_kind in ks]
                    if not cands:
                        continue
                start, end = toks[i][1], toks[j][2]
                info = self.key_info.get(acc, {"policy": "anywhere"})
                if info["policy"] == "restricted":
                    if query and i == 0 and j == n - 1:
                        how = "whole_query"
                    elif self._quoted(text, start, end):
                        how = "quoted"
                    elif self._marker(toks, i, j, {c.doc_kind for c in cands}):
                        how = "kind_marker"
                    else:
                        continue
                else:
                    how = "anywhere"
                found.append((1, -(end - start), start,
                              Mention(start, end, text[start:end], acc, tuple(cands), info["policy"], how)))
        found.sort(key=lambda x: (x[0], x[1], x[2]))
        taken: list[Mention] = []
        for _, _, _, m in found:
            if all(m.end <= t.start or m.start >= t.end for t in taken):
                taken.append(m)
        return sorted(taken, key=lambda m: m.start)

