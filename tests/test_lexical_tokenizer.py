"""C2: shared domain tokenizer and the Porter2 stemmer."""
from __future__ import annotations

import random
import sqlite3

import pytest

from threat_retrieval_engine.text import TokenizerConfig, fts5_tokenize_option, is_valid_token, normalize, tokenize
from threat_retrieval_engine.text.porter2 import stem

NOSTEM = TokenizerConfig(stemmer="none")


# --------------------------------------------------------------------------- Porter2
@pytest.mark.parametrize("word,expected", [
    # examples from the Snowball English stemmer description and its vocabulary file
    ("consign", "consign"), ("consigned", "consign"), ("consigning", "consign"), ("consignment", "consign"),
    ("consist", "consist"), ("consisted", "consist"), ("consistency", "consist"), ("consistent", "consist"),
    ("consistently", "consist"), ("consisting", "consist"), ("consists", "consist"),
    ("knack", "knack"), ("knackeries", "knackeri"), ("knaves", "knave"), ("knavish", "knavish"),
    ("knightly", "knight"), ("generously", "generous"), ("generate", "generat"), ("communism", "communism"),
    ("caresses", "caress"), ("ponies", "poni"), ("ties", "tie"), ("cats", "cat"), ("gas", "gas"), ("gaps", "gap"),
    ("agreed", "agre"), ("feed", "feed"), ("hopping", "hop"), ("hoping", "hope"), ("running", "run"),
    ("happy", "happi"), ("cry", "cri"), ("by", "by"), ("say", "say"),
    ("relational", "relat"), ("conditional", "condit"), ("rational", "ration"), ("valenci", "valenc"),
    ("hesitanci", "hesit"), ("digitizer", "digit"), ("conformabli", "conform"), ("radicalli", "radic"),
    ("differentli", "differ"), ("vileli", "vile"), ("analogousli", "analog"), ("vietnamization", "vietnam"),
    ("predication", "predic"), ("operator", "oper"), ("feudalism", "feudal"), ("decisiveness", "decis"),
    ("hopefulness", "hope"), ("callousness", "callous"), ("formaliti", "formal"), ("sensitiviti", "sensit"),
    ("sensibiliti", "sensibl"),
    ("triplicate", "triplic"), ("formative", "format"), ("formalize", "formal"), ("electriciti", "electr"),
    ("electrical", "electr"), ("hopeful", "hope"), ("goodness", "good"),
    ("revival", "reviv"), ("allowance", "allow"), ("inference", "infer"), ("airliner", "airlin"),
    ("adjustable", "adjust"), ("defensible", "defens"), ("irritant", "irrit"), ("replacement", "replac"),
    ("adjustment", "adjust"), ("dependent", "depend"), ("adoption", "adopt"), ("communism", "communism"),
    ("activate", "activ"), ("angulariti", "angular"), ("homologous", "homolog"), ("effective", "effect"),
    ("bowdlerize", "bowdler"),
    ("skies", "sky"), ("dying", "die"), ("news", "news"), ("inning", "inning"), ("succeed", "succeed"),
    ("yelling", "yell"), ("yesterday", "yesterday"),
    # domain words
    ("vulnerabilities", "vulner"), ("vulnerability", "vulner"), ("exploited", "exploit"),
    ("execution", "execut"), ("injection", "inject"), ("overflow", "overflow"), ("attackers", "attack"),
])
def test_porter2(word, expected):
    assert stem(word) == expected


def test_porter2_leaves_non_alpha_and_short_words():
    for w in ("a", "is", "log4j", "2.15.0", "cve-2021-44228", "Über"):
        assert stem(w) == w


# --------------------------------------------------------------------------- tokenizer
def test_identifiers_are_single_tokens():
    t = tokenize("Exploit of CVE-2017-0144 (CWE-787) from 198.51.100.24 on OpenSSL 1.0.1g and log4j 2.15.0", NOSTEM)
    for tok in ("cve-2017-0144", "cwe-787", "198.51.100.24", "1.0.1g", "2.15.0"):
        assert tok in t
    # no fragments of identifiers
    assert "2017" not in t and "0144" not in t and "15" not in t and "198" not in t


@pytest.mark.parametrize("text", ["CVE 2021 44228", "cve_2021_44228", "Cve-2021-44228", "CVE-2021–44228",
                                  "ＣＶＥ－２０２１－４４２２８", "cve:2021-44228", "CVE2021-44228"])
def test_cve_variants_normalise(text):
    assert tokenize(text) == ["cve-2021-44228"]


@pytest.mark.parametrize("text,expected", [("CWE79", "cwe-79"), ("CWE 79", "cwe-79"), ("cwe-079", "cwe-79")])
def test_cwe_variants_normalise(text, expected):
    assert tokenize(text) == [expected]


def test_compounds_emit_whole_and_parts():
    t = tokenize("log4j-core mysql_real_escape_string /etc/passwd org.apache.logging cmd.exe", NOSTEM)
    assert t == ["log4j-core", "log4j", "core", "mysql_real_escape_string", "mysql", "real", "escape", "string",
                 "etc/passwd", "etc", "passwd", "org.apache.logging", "org", "apache", "logging", "cmd.exe", "cmd",
                 "exe"]


def test_compounds_whole_only_without_split():
    t = tokenize("log4j-core cross-site", NOSTEM.with_(split_compounds=False))
    assert t == ["log4j-core", "cross-site"]


def test_digit_parts_are_dropped_and_versions_kept():
    assert tokenize("2.0-beta9", NOSTEM) == ["2.0-beta9", "beta9", "beta"]
    assert tokenize("v3.2.1", NOSTEM) == ["3.2.1"]
    assert tokenize("t1059.001", NOSTEM) == ["t1059.001", "t1059"]


def test_trailing_digit_variant():
    assert tokenize("log4j2 windows10 http2 x64 sha256", NOSTEM) == [
        "log4j2", "log4j", "windows10", "windows", "http2", "http", "x64", "sha256", "sha"]
    assert tokenize("log4j2", NOSTEM.with_(trailing_digits=False)) == ["log4j2"]
    long_hex = "d41d8cd98f00b204e9800998ecf84271"
    assert tokenize(long_hex, NOSTEM) == [long_hex]


def test_stemming_only_plain_words():
    t = tokenize("Exploited vulnerabilities in cross-site scripting log4j-core attacker's")
    assert t == ["exploit", "vulner", "in", "cross-site", "cross", "site", "script", "log4j-core", "log4j", "core",
                 "attack"]


def test_unicode_normalisation_and_case():
    assert tokenize("ÉCOLE École ÉCOLE", NOSTEM) == ["école"] * 3
    assert tokenize("Straße", NOSTEM) == ["strasse"]
    assert tokenize("ﬁle", NOSTEM) == ["file"]  # ligature, NFKC
    assert normalize("C:\\Windows\\System32") == "c:/windows/system32"


def test_non_latin_scripts_keep_words():
    t = tokenize("हिन्दी 漏洞 Ünïcödé русский", NOSTEM)
    assert t == ["हिन्दी", "漏洞", "ünïcödé", "русский"]


def test_empty_and_punctuation_only():
    assert tokenize("") == [] and tokenize(None) == []
    assert tokenize("\"\"''()*^:+- ... /// ___") == []


def test_tokens_never_contain_fts_syntax():
    rnd = random.Random(7)
    alphabet = "abcXYZ019 -._/\\\"'()*^:+{}[]<>!?,;\t\n\u00a0\u3000é漏ि" + chr(0x1F600)
    for _ in range(3000):
        s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
        for t in tokenize(s):
            assert is_valid_token(t), (s, t)
            assert not any(c in t for c in " \"'()*^:+{}")


def test_is_valid_token_rejects_syntax():
    for bad in ("", "-a", "a-", 'a"b', "a b", "a*", "^a", "a:b", "(a)", "A"):
        assert not is_valid_token(bad)
    for good in ("a", "log4j-core", "2.15.0", "漏洞", "école"):
        assert is_valid_token(good)


@pytest.mark.parametrize("cfg", [TokenizerConfig(), NOSTEM, NOSTEM.with_(split_compounds=False)])
def test_fts5_round_trip(cfg):
    """Space-joined tokens re-tokenize to the same tokens under the FTS5 tokenizer option the index uses."""
    texts = ["Apache Log4j2 2.0-beta9 through 2.15.0 (CVE-2021-44228) JNDI; log4j-core in /etc/passwd",
             "हिन्दी 漏洞 Ünïcödé русский ＣＶＥ－２０２１－４４２２８ mysql_real_escape_string()",
             "\"NEAR(a b)\" col:x * ^y ((( AND OR NOT", "C:\\Windows\\System32\\cmd.exe 185.123.45.10 t1059.001"]
    db = sqlite3.connect(":memory:")
    tok = fts5_tokenize_option().replace('"', '""')
    db.execute(f'CREATE VIRTUAL TABLE t USING fts5(x, tokenize="{tok}")')
    db.execute("CREATE VIRTUAL TABLE v USING fts5vocab(t, instance)")
    for i, text in enumerate(texts, 1):
        toks = tokenize(text, cfg)
        db.execute("INSERT INTO t(rowid, x) VALUES (?, ?)", (i, " ".join(toks)))
        got = [r[0] for r in db.execute("SELECT term FROM v WHERE doc = ? ORDER BY offset", (i,))]
        assert got == toks
        for term in set(toks):  # every token is found as a quoted MATCH string
            n = db.execute("SELECT count(*) FROM t WHERE t MATCH ? AND rowid = ?", ('"' + term + '"', i)).fetchone()[0]
            assert n == 1, term


def test_config_key_and_validation():
    assert TokenizerConfig().key() != NOSTEM.key()
    with pytest.raises(ValueError):
        TokenizerConfig(stemmer="lancaster")
