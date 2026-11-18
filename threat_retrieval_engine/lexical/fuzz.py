"""Fuzz corpus for the lexical query builder (used by check_c2 and the tests; plan S1 reuses it).

The generator mixes random bytes-as-text, FTS5 syntax fragments (quotes, NEAR, column filters, ``*``, ``^``,
parentheses, AND/OR/NOT), SQL-injection fragments, non-Latin scripts, control and bidi characters, and very
long inputs. ``run_fuzz`` sends every query through ``LexicalIndex.search`` and reports any exception
(including ``sqlite3`` FTS5 syntax errors) and any query slower than the limit.
"""
from __future__ import annotations

import random
import sqlite3
import time

SYNTAX = ['"', '""', "'", "(", ")", "*", "^", ":", "-", "+", "{", "}", "NEAR(", "NEAR/3", ",", "AND", "OR", "NOT",
          "title:", "{ids title}:", "lex:", "rank", "bm25(", "rowid", ";", "--", "/*", "*/", "\\", "%", "_", ".",
          "/", "=", "' OR 1=1 --", '"; DROP TABLE lex; --', "\x00", "‮", "﻿", "​", "\t", "\n"]
WORDS = ["overflow", "remote", "code", "execution", "apache", "log4j", "2.15.0", "CVE-2021-44228", "cwe-79",
         "cross-site", "sql", "injection", "/etc/passwd", "cmd.exe", "185.123.45.10", "漏洞", "переполнение",
         "हिन्दी", "😀", "école", "Straße", "ＣＶＥ", "mysql_real_escape_string", "the", "of"]


def fuzz_queries(n: int = 10_000, seed: int = 20261115) -> list[str]:
    rnd = random.Random(seed)
    out: list[str] = []
    while len(out) < n:
        kind = rnd.random()
        if kind < 0.25:  # random code points (any plane, including surrogates replaced)
            s = "".join(chr(rnd.randint(0, 0x10FFFF)) for _ in range(rnd.randint(0, 60)))
            s = s.encode("utf-8", "replace").decode("utf-8", "replace")
        elif kind < 0.55:  # syntax soup
            s = "".join(rnd.choice(SYNTAX + WORDS) + rnd.choice(["", " ", ""]) for _ in range(rnd.randint(1, 30)))
        elif kind < 0.8:  # words with operators between them
            s = " ".join(rnd.choice(WORDS) + rnd.choice(["", "*", '"', ")", ":", "^"]) + " " + rnd.choice(SYNTAX)
                         for _ in range(rnd.randint(1, 12)))
        elif kind < 0.95:  # printable ASCII noise
            s = "".join(chr(rnd.randint(32, 126)) for _ in range(rnd.randint(0, 200)))
        else:  # long inputs
            unit = rnd.choice(WORDS + SYNTAX)
            s = (unit + rnd.choice([" ", "", "-", "."])) * rnd.randint(1000, 30_000)
        out.append(s)
    return out


def run_fuzz(ix, queries: list[str], per_query_limit_s: float = 1.0, k: int = 100) -> dict:
    errors, slow = [], []
    worst = 0.0
    t_all = time.perf_counter()
    for i, q in enumerate(queries):
        t0 = time.perf_counter()
        try:
            ix.search(q, k=k)
        except (sqlite3.Error, Exception) as exc:  # any exception is a failure
            errors.append({"index": i, "query": q[:120], "error": f"{type(exc).__name__}: {exc}"[:300]})
        dt = time.perf_counter() - t0
        worst = max(worst, dt)
        if dt > per_query_limit_s:
            slow.append({"index": i, "query": q[:120], "seconds": round(dt, 3)})
    return {"queries": len(queries), "errors": errors, "slow": slow, "worst_s": round(worst, 4),
            "total_s": round(time.perf_counter() - t_all, 2), "limit_s": per_query_limit_s}
