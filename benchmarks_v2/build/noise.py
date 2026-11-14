"""T6 noisy variants: deterministic, seeded perturbations of T0, T2 and T3 queries.

Noise types: typos (adjacent swap, deletion, keyboard-neighbour substitution, doubled letter),
missing spaces, analyst abbreviations, and pasted log-like fragments. Children inherit the parent's
qrels and split (`meta.parent_qid`).
"""
from __future__ import annotations

import re

from .common import rng, stable_key
from .model import Item

_KEYB = {c: n for c, n in zip("qwertyuiopasdfghjklzxcvbnm", [
    "wa", "qes", "wrd", "etf", "rgy", "thu", "yji", "uko", "ilp", "o", "qsz", "awdx", "sefc", "drgv", "fthb",
    "gyjn", "hukm", "jil", "kp", "xas", "zcsd", "xvdf", "cbfg", "vnhg", "bmhj", "nj"])}
ABBREV = [
    (r"\bremote code execution\b", "RCE"), (r"\bvulnerability\b", "vuln"), (r"\bvulnerabilities\b", "vulns"),
    (r"\bauthentication\b", "auth"), (r"\binformation\b", "info"), (r"\bconfiguration\b", "config"),
    (r"\bprivilege escalation\b", "privesc"), (r"\bdenial of service\b", "DoS"), (r"\bcross-site scripting\b", "XSS"),
    (r"\bSQL injection\b", "SQLi"), (r"\bMicrosoft\b", "MS"), (r"\bWindows\b", "win"), (r"\bserver\b", "srv"),
    (r"\bapplication\b", "app"), (r"\bversion\b", "ver"), (r"\bpassword\b", "pwd"), (r"\bdirectory\b", "dir"),
    (r"\bexecution\b", "exec"), (r"\bmanagement\b", "mgmt"), (r"\bnetwork\b", "net"), (r"\bdatabase\b", "db"),
    (r"\bbefore\b", "b4"), (r"\bplease\b", "pls"), (r"\bwith\b", "w/"), (r"\bwithout\b", "w/o"),
    (r"\bthrough\b", "thru"), (r"\bmessage\b", "msg"), (r"\brequest\b", "req"), (r"\bkernel\b", "krnl"),
]
_LOG_HOSTS = ["fw01", "web-prod-03", "dc02", "vpn-gw", "app-srv-7", "mail01", "ids-sensor"]
_LOG_PROCS = ["sshd[2231]", "kernel", "httpd", "suricata[884]", "nginx", "sudo", "audit"]


def _private_ip(r) -> str:
    return r.choice([f"10.{r.randrange(256)}.{r.randrange(256)}.{r.randrange(1, 255)}",
                     f"192.168.{r.randrange(256)}.{r.randrange(1, 255)}",
                     f"172.{r.randrange(16, 32)}.{r.randrange(256)}.{r.randrange(1, 255)}"])


def log_fragment(r) -> str:
    ts = f"{r.choice(['Jan', 'Mar', 'Jun', 'Sep', 'Nov'])} {r.randrange(1, 29):2d} {r.randrange(24):02d}:{r.randrange(60):02d}:{r.randrange(60):02d}"
    host, proc = r.choice(_LOG_HOSTS), r.choice(_LOG_PROCS)
    kind = r.randrange(4)
    if kind == 0:
        return f"{ts} {host} {proc}: [UFW BLOCK] IN=eth0 SRC={_private_ip(r)} DST={_private_ip(r)} PROTO=TCP DPT={r.choice([22, 80, 443, 445, 3389, 8080])}"
    if kind == 1:
        return f'{_private_ip(r)} - - [{r.randrange(1, 29):02d}/Oct/2026:{r.randrange(24):02d}:{r.randrange(60):02d}:11 +0000] "GET /index.php?id={r.randrange(1, 999)} HTTP/1.1" 500 {r.randrange(200, 9000)}'
    if kind == 2:
        return f"{ts} {host} {proc}: alert sid:{r.randrange(2000000, 2060000)} rev:{r.randrange(1, 9)} prio:{r.randrange(1, 4)}"
    return f"level=warn ts={ts.replace(' ', 'T')} host={host} msg=\"unexpected child process\" pid={r.randrange(1000, 65000)}"


def typo(text: str, r, n: int = 2) -> str:
    chars = list(text)
    letters = [i for i, c in enumerate(chars) if c.isalpha()]
    for _ in range(n):
        if len(letters) < 4:
            break
        i = r.choice(letters[1:-1])
        op = r.randrange(4)
        if op == 0 and i + 1 < len(chars) and chars[i + 1].isalpha():
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
        elif op == 1:
            chars[i] = ""
        elif op == 2:
            c = chars[i].lower()
            if c in _KEYB:
                sub = r.choice(_KEYB[c])
                chars[i] = sub.upper() if chars[i].isupper() else sub
        else:
            chars[i] = chars[i] * 2
    return "".join(chars)


def drop_spaces(text: str, r, n: int = 2) -> str:
    idx = [m.start() for m in re.finditer(" ", text)]
    if not idx:
        return text
    kill = set(r.sample(idx, min(n, len(idx))))
    return "".join(c for i, c in enumerate(text) if i not in kill)


def abbreviate(text: str, r) -> tuple[str, int]:
    count = 0
    for pat, rep in ABBREV:
        new, k = re.subn(pat, rep, text, flags=re.I)
        if k:
            text, count = new, count + k
    return text, count


NOISE_TYPES = ["typos", "missing_spaces", "abbreviations", "log_fragment", "typos+missing_spaces",
               "abbreviations+typos", "lowercase+typos", "log_fragment+typos"]


def perturb(text: str, kind: str, r) -> str | None:
    t = text
    for part in kind.split("+"):
        if part == "typos":
            t = typo(t, r, 1 if len(t) < 25 else 2)
        elif part == "missing_spaces":
            t = drop_spaces(t, r)
        elif part == "abbreviations":
            t, k = abbreviate(t, r)
            if k == 0:
                return None
        elif part == "lowercase":
            t = t.lower()
        elif part == "log_fragment":
            frag = log_fragment(r)
            t = f"{frag} {t}" if r.random() < 0.5 else f"{t}\n{frag}"
    return t if t != text else None


def build_t6(parents: list[Item], gate, seed: int, target: int) -> tuple[list[Item], dict]:
    """parents: finalised T0/T2/T3 items with qid and split; only dev/test parents are used (T6 has no
    train split, and a child must follow its parent)."""
    stats = {"parents_eligible": 0, "no_change": 0}
    elig = [p for p in parents if p.split in ("dev", "test")]
    stats["parents_eligible"] = len(elig)
    # interleave slices so T0 and T2 are represented, then T3 fills
    order = sorted(elig, key=lambda p: ({"T0": 0, "T2": 1, "T3": 2}[p.slice], stable_key(seed, "t6", p.qid)))
    by_slice = {s: [p for p in order if p.slice == s] for s in ("T0", "T2", "T3")}
    want = {"T0": len(by_slice["T0"]), "T2": min(len(by_slice["T2"]), target * 35 // 100)}
    want["T3"] = target - want["T0"] - want["T2"]
    items: list[Item] = []
    for sl in ("T0", "T2", "T3"):
        got = 0
        for p in by_slice[sl]:
            if got >= want[sl] or len(items) >= target:
                break
            r = rng(seed, "t6", p.qid)
            kinds = NOISE_TYPES[:]
            r.shuffle(kinds)
            child = None
            for kind in kinds:
                t = perturb(p.text, kind, r)
                if t is None:
                    continue
                child = Item(slice="T6", text=t, qrels=[dict(q) for q in p.qrels], source=dict(p.source),
                             meta={"parent_qid": p.qid, "parent_slice": p.slice, "noise": kind},
                             link_keys=set(p.link_keys) | {f"parent:{p.qid}"})
                child.split = p.split
                child.forced_split = p.split
                child.temporal_holdout = p.temporal_holdout
                # a child must inherit every qrel, so a perturbation that would lose a target pair to the
                # overlap filter is not used
                if gate.overlap.score(child) <= gate.overlap.threshold and gate.accept(child) \
                        and len(child.qrels) == len(p.qrels):
                    break
                child = None
            if child is None:
                stats["no_change"] += 1
                continue
            items.append(child)
            got += 1
        stats[f"from_{sl}"] = got
    stats["accepted"] = len(items)
    return items, stats
