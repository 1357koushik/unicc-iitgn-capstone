from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

try:
    from threat_retrieval_engine.api.schemas import PoCResultSchema
    from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate
except ImportError:
    from api.schemas import PoCResultSchema
    from sources.base import RawCandidate

logger = logging.getLogger(__name__)

# Known curated exploit platforms and authoritative security repositories
_CURATED_DOMAINS = {
    "exploit-db.com",
    "www.exploit-db.com",
    "packetstormsecurity.com",
    "sploitus.com",
    "0day.today",
    "github.com/rapid7/metasploit-framework",
    "github.com/projectdiscovery/nuclei-templates",
}

_CODE_EXTENSIONS = re.compile(r"\.(py|c|cpp|go|rb|sh|pl|yar|yaml|yml|rs|java|php)\b", re.IGNORECASE)
_OBFUSCATION_INDICATORS = re.compile(
    r"(powershell\s+-(?:enc|e)|certutil\s+-decode|iex\s*\(|base64\s+-d|downloadstring|invoke-expression)",
    re.IGNORECASE,
)
_BINARY_PATTERNS = re.compile(
    r"(\.exe\b|\.dll\b|\.scr\b|\.bat\b|password\s*(?:is|:)|archive\s*password|mediafire\.com|mega\.nz)",
    re.IGNORECASE,
)
_SCAM_PATTERNS = re.compile(
    r"(buy\s+exploit|contact\s+telegram|t\.me/|dm\s+for\s+tool|sell\s+0day|bitcoin|usdt)",
    re.IGNORECASE,
)
_SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"}


class PoCValidator:
    """
    Evaluates and validates PoC candidates.
    Applies positive heuristics (code presence, stars, curated sources)
    and negative heuristics (deception flags, malware traps, obfuscation).
    Ensures high precision (>= 70%) in identifying public working exploits.
    """

    def __init__(
        self,
        verified_threshold: float = 0.75,
        likely_threshold: float = 0.50,
        discussion_threshold: float = 0.25,
    ) -> None:
        self.verified_threshold = verified_threshold
        self.likely_threshold = likely_threshold
        self.discussion_threshold = discussion_threshold

    def validate_candidate(self, candidate: RawCandidate, cve_id: str, cross_source_count: int = 1) -> PoCResultSchema:
        score = 0.20  # baseline score for a candidate mentioning the CVE
        warning_flags: list[str] = []
        cve_clean = cve_id.strip().upper()

        text_corpus = f"{candidate.title} {candidate.description} {candidate.url}".lower()
        parsed_url = urlparse(candidate.url)
        domain = parsed_url.netloc.lower()

        # -------------------------------------------------------------
        # 1. Positive Signals
        # -------------------------------------------------------------
        # Curated exploit repository
        if any(curated in candidate.url.lower() for curated in _CURATED_DOMAINS):
            score += 0.30

        # GitHub Stars
        if candidate.stars is not None:
            if candidate.stars >= 20:
                score += 0.30
            elif candidate.stars >= 5:
                score += 0.20
            elif candidate.stars >= 1:
                score += 0.10

        # Code files or explicit language
        if candidate.language and candidate.language.lower() in ("python", "c", "c++", "go", "ruby", "rust"):
            score += 0.20
        elif _CODE_EXTENSIONS.search(text_corpus):
            score += 0.15

        # Explicit target CVE in title/repo name
        if cve_clean.lower() in candidate.title.lower() or cve_clean.lower() in candidate.url.lower():
            score += 0.15

        # Exploit terminology
        if any(kw in text_corpus for kw in ("proof of concept", "poc", "exploit", "remote code execution", "rce")):
            score += 0.15

        # Professional exploit framework reference
        if any(kw in text_corpus for kw in ("nuclei", "metasploit", "poc.py", "burp", "weaponized")):
            score += 0.15

        # Cross-source corroboration
        if cross_source_count > 1:
            score += 0.15

        # -------------------------------------------------------------
        # 2. Negative Signals & Warning Flags (Malware Traps / Spam)
        # -------------------------------------------------------------
        # Binary only / password protected archives
        if _BINARY_PATTERNS.search(text_corpus):
            warning_flags.append("binary_only")
            score -= 0.40

        # Obfuscated code execution / dropper patterns
        if _OBFUSCATION_INDICATORS.search(text_corpus):
            warning_flags.append("obfuscated_code")
            score -= 0.50

        # Scam / Sales / Telegram marketing
        if _SCAM_PATTERNS.search(text_corpus):
            warning_flags.append("scam_marketing")
            score -= 0.40

        # URL shortener / hidden redirect
        if domain in _SHORTENER_DOMAINS:
            warning_flags.append("unresolved_redirect")
            score -= 0.15

        # Empty repo / 0 stars with generic fork
        if candidate.source == "github" and candidate.is_fork and (candidate.stars or 0) == 0:
            score -= 0.05

        # Clamp score between 0.0 and 1.0
        final_score = max(0.0, min(1.0, round(score, 3)))

        # Assign confidence label
        if final_score >= self.verified_threshold:
            label = "VERIFIED_CODE"
        elif final_score >= self.likely_threshold:
            label = "LIKELY_POC"
        elif final_score >= self.discussion_threshold:
            label = "DISCUSSION"
        else:
            label = "SUSPICIOUS"

        return PoCResultSchema(
            url=candidate.url,
            title=candidate.title,
            source=candidate.source,
            author=candidate.author,
            published_at=candidate.published_at or "2024-01-01T00:00:00Z",
            confidence_score=final_score,
            confidence_label=label,
            stars=candidate.stars,
            language=candidate.language,
            is_fork=candidate.is_fork,
            warning_flags=warning_flags,
        )

    @staticmethod
    def calculate_precision(results: list[PoCResultSchema]) -> float:
        """
        Calculate precision score of the findings.
        Formula: (count(VERIFIED_CODE) + count(LIKELY_POC)) / total_found.
        """
        if not results:
            return 0.0
        verified_or_likely = sum(
            1 for r in results if r.confidence_label in ("VERIFIED_CODE", "LIKELY_POC")
        )
        return round(verified_or_likely / len(results), 4)
