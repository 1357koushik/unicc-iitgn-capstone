"""English Porter2 (Snowball "english") stemmer. Standard library only.

A faithful implementation of the algorithm published at
https://snowballstem.org/algorithms/english/stemmer.html, written here because the runtime has no
stemming package (the server installs offline from mirrored wheels) and the stemmer is small. Input is
expected to be lower-case ASCII letters; anything else is returned unchanged by ``stem``.

The tests (tests/test_lexical_tokenizer.py) check the published examples of every step.
"""
from __future__ import annotations

import re

_VOWELS = frozenset("aeiouy")
_DOUBLES = ("bb", "dd", "ff", "gg", "mm", "nn", "pp", "rr", "tt")
_LI_ENDING = frozenset("cdeghkmnrt")
_ALPHA = re.compile(r"^[a-z']+$")

_EXCEPTIONS = {
    "skis": "ski", "skies": "sky", "dying": "die", "lying": "lie", "tying": "tie",
    "idly": "idl", "gently": "gentl", "ugly": "ugli", "early": "earli", "only": "onli", "singly": "singl",
    "sky": "sky", "news": "news", "howe": "howe", "atlas": "atlas", "cosmos": "cosmos", "bias": "bias",
    "andes": "andes",
}
_EXCEPTIONS_1A = frozenset({"inning", "outing", "canning", "herring", "earring", "proceed", "exceed", "succeed"})

_STEP2 = (
    ("ization", "ize"), ("ational", "ate"), ("fulness", "ful"), ("ousness", "ous"), ("iveness", "ive"),
    ("tional", "tion"), ("biliti", "ble"), ("lessli", "less"), ("entli", "ent"), ("ation", "ate"),
    ("alism", "al"), ("aliti", "al"), ("ousli", "ous"), ("iviti", "ive"), ("fulli", "ful"), ("enci", "ence"),
    ("anci", "ance"), ("abli", "able"), ("izer", "ize"), ("ator", "ate"), ("alli", "al"), ("bli", "ble"),
    ("ogi", "og"), ("li", ""),
)
_STEP3 = (
    ("ational", "ate"), ("tional", "tion"), ("alize", "al"), ("icate", "ic"), ("iciti", "ic"), ("ative", ""),
    ("ical", "ic"), ("ness", ""), ("ful", ""),
)
_STEP4 = ("ement", "ance", "ence", "able", "ible", "ment", "ant", "ent", "ism", "ate", "iti", "ous", "ive", "ize",
          "ion", "al", "er", "ic")


def _is_vowel(word: str, i: int) -> bool:
    return word[i] in _VOWELS


def _regions(word: str) -> tuple[int, int]:
    """Start indices of R1 and R2 (len(word) when the region is empty)."""
    n = len(word)
    r1 = n
    for prefix in ("gener", "commun", "arsen"):
        if word.startswith(prefix):
            r1 = len(prefix)
            break
    else:
        for i in range(1, n):
            if word[i] not in _VOWELS and word[i - 1] in _VOWELS:
                r1 = i + 1
                break
    r2 = n
    for i in range(r1 + 1, n):
        if word[i] not in _VOWELS and word[i - 1] in _VOWELS:
            r2 = i + 1
            break
    return r1, r2


def _ends_short_syllable(word: str) -> bool:
    """(a) non-vowel, vowel, non-vowel other than w, x or Y at the end; or (b) vowel, non-vowel as the
    whole word."""
    n = len(word)
    if n == 2:
        return word[0] in _VOWELS and word[1] not in _VOWELS
    if n >= 3:
        return (word[-3] not in _VOWELS and word[-2] in _VOWELS and word[-1] not in _VOWELS
                and word[-1] not in "wxY")
    return False


def _is_short(word: str, r1: int) -> bool:
    return r1 >= len(word) and _ends_short_syllable(word)


def _contains_vowel(s: str) -> bool:
    return any(c in _VOWELS for c in s)


def stem(word: str) -> str:
    if len(word) <= 2 or not _ALPHA.match(word):
        return word
    if word in _EXCEPTIONS:
        return _EXCEPTIONS[word]
    w = word.lstrip("'")
    if len(w) <= 2:
        return w
    # Mark consonant y: initial y, and y after a vowel.
    chars = list(w)
    if chars[0] == "y":
        chars[0] = "Y"
    for i in range(1, len(chars)):
        if chars[i] == "y" and chars[i - 1] in _VOWELS:
            chars[i] = "Y"
    w = "".join(chars)
    r1, r2 = _regions(w)

    # Step 0
    for suf in ("'s'", "'s", "'"):
        if w.endswith(suf):
            w = w[: -len(suf)]
            break

    # Step 1a
    if w.endswith("sses"):
        w = w[:-2]
    elif w.endswith("ied") or w.endswith("ies"):
        w = w[:-2] if len(w) > 4 else w[:-1]
    elif w.endswith("us") or w.endswith("ss"):
        pass
    elif w.endswith("s"):
        if _contains_vowel(w[:-2]):
            w = w[:-1]
    if w in _EXCEPTIONS_1A:
        return w

    # Step 1b
    for suf in ("eedly", "ingly", "edly", "eed", "ing", "ed"):
        if w.endswith(suf):
            if suf in ("eedly", "eed"):
                if len(w) - len(suf) >= r1:
                    w = w[: -len(suf)] + "ee"
            else:
                stem_part = w[: -len(suf)]
                if _contains_vowel(stem_part):
                    w = stem_part
                    if w.endswith(("at", "bl", "iz")):
                        w += "e"
                    elif w.endswith(_DOUBLES):
                        w = w[:-1]
                    elif _is_short(w, r1):
                        w += "e"
            break

    # Step 1c
    if len(w) > 2 and w[-1] in "yY" and w[-2] not in _VOWELS:
        w = w[:-1] + "i"

    # Step 2
    for suf, rep in _STEP2:
        if w.endswith(suf):
            if len(w) - len(suf) >= r1:
                if suf == "ogi":
                    if w[-4:-3] == "l":
                        w = w[:-3] + rep
                elif suf == "li":
                    if len(w) >= 3 and w[-3] in _LI_ENDING:
                        w = w[:-2]
                else:
                    w = w[: -len(suf)] + rep
            break

    # Step 3
    for suf, rep in _STEP3:
        if w.endswith(suf):
            if len(w) - len(suf) >= r1:
                if suf == "ative":
                    if len(w) - len(suf) >= r2:
                        w = w[: -len(suf)]
                else:
                    w = w[: -len(suf)] + rep
            break

    # Step 4
    for suf in _STEP4:
        if w.endswith(suf):
            if len(w) - len(suf) >= r2:
                if suf == "ion":
                    if len(w) >= 4 and w[-4] in "st":
                        w = w[:-3]
                else:
                    w = w[: -len(suf)]
            break

    # Step 5
    if w.endswith("e"):
        if len(w) - 1 >= r2 or (len(w) - 1 >= r1 and not _ends_short_syllable(w[:-1])):
            w = w[:-1]
    elif w.endswith("l"):
        if len(w) - 1 >= r2 and w[-2:-1] == "l":
            w = w[:-1]

    return w.replace("Y", "y")
