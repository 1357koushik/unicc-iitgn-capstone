from __future__ import annotations

"""Deterministic evidence ranking for public research discovery.

Scores express observed relevance signals, never the probability that supplied
code works. The service never downloads, clones, or executes a candidate.
"""

import logging
import re
from typing import Iterable
from urllib.parse import urlparse

try:
    from threat_retrieval_engine.api.schemas import PoCResultSchema
    from threat_retrieval_engine.poc_intelligence.sources.base import RawCandidate
except ImportError:
    from api.schemas import PoCResultSchema
    from sources.base import RawCandidate

logger = logging.getLogger(__name__)

# Curated exploit platforms and authoritative security repositories
_CURATED_DOMAINS = {
    "exploit-db.com",
    "www.exploit-db.com",
    "packetstormsecurity.com",
    "sploitus.com",
    "0day.today",
    "rapid7/metasploit-framework",
    "projectdiscovery/nuclei-templates",
}

_CODE_EXTENSIONS = re.compile(r"\.(py|c|cpp|go|rb|sh|pl|yar|yaml|yml|rs|java|php)\b", re.I)
_KNOWN_LANGUAGES = {"python", "c", "c++", "go", "golang", "ruby", "rust", "shell", "bash", "powershell", "yaml", "yara", "java", "php", "perl"}

_POC_TERMS = re.compile(r"\b(proof[ -]?of[ -]?concept|\bpoc\b|exploit(?:ation)?|exploit[ _-]?code|rce)\b", re.I)
_CODE_TERMS = re.compile(r"\b(script|payload|module|implementation|source code|reproducer|reproduction)\b", re.I)
_ADVISORY_TERMS = re.compile(r"\b(advisory|patch|fixed|mitigation|workaround|release notes?|cve record)\b", re.I)
_DETECTION_TERMS = re.compile(r"\b(scanner|detection|signature|rule|template|nuclei|yara)\b", re.I)

# Anti-deception / malware trap indicators
_BINARY_TERMS = re.compile(r"(\.exe\b|\.dll\b|\.scr\b|\.bat\b|password[- ]protected|archive password|password\s*(?:is|:)|mediafire\.com|mega\.nz)", re.I)
_OBFUSCATION_TERMS = re.compile(r"(powershell\s+-(?:enc|e)|certutil\s+-decode|iex\s*\(|invoke-expression|downloadstring|base64\s+-d)", re.I)
_SCAM_TERMS = re.compile(r"(buy\s+(?:the\s+)?exploit|contact\s+(?:me|us\s+)?(?:on\s+)?telegram|t\.me/|dm\s+for\s+tool|sell(?:ing)?\s+(?:a\s+)?0day|bitcoin|usdt)", re.I)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"}


class PoCValidator:
    """Classify findings from explicit evidence, with configurable deterministic weights."""

    def __init__(
        self,
        high_relevance_threshold: float = 0.70,
        possible_poc_threshold: float = 0.45,
        weights: dict[str, float] | None = None,
    ) -> None:
        self.high_relevance_threshold = high_relevance_threshold
        self.possible_poc_threshold = possible_poc_threshold
        self.weights = {
            "exact_cve": 0.35,
            "explicit_poc": 0.25,
            "implementation_evidence": 0.25,
            "cross_source_reference": 0.10,
            "curated_platform": 0.15,
            "community_validation_high": 0.15,
            "community_validation_med": 0.10,
            "advisory_or_detection": 0.05,
            "binary_only": -0.40,
            "obfuscated_code": -0.50,
            "scam_marketing": -0.40,
            "unresolved_redirect": -0.15,
            "archived_repo": -0.10,
        }
        if weights:
            self.weights.update(weights)

    @staticmethod
    def _text(candidate: RawCandidate) -> str:
        metadata = " ".join(str(v) for v in candidate.raw_metadata.values())
        return " ".join([candidate.title, candidate.description, candidate.url, *candidate.linked_urls, metadata])

    def validate_candidate(
        self,
        candidate: RawCandidate,
        cve_id: str,
        cross_source_count: int = 1,
        duplicate_group: str | None = None,
    ) -> PoCResultSchema:
        cve = cve_id.strip().upper()
        text = self._text(candidate)
        lower_text = text.lower()
        reasons: list[str] = []
        evidence = list(candidate.evidence)
        warnings: list[str] = []
        score = 0.0

        exact_cve = bool(re.search(rf"\b{re.escape(cve)}\b", text, re.IGNORECASE))
        if exact_cve:
            score += self.weights["exact_cve"]
            reasons.append(f"+{self.weights['exact_cve']:.2f} exact requested CVE appears in retrieved source data")
            evidence.append(f"Exact CVE match: {cve}")
        else:
            warnings.append("cve_not_observed_in_source")
            reasons.append("No exact CVE association was observed; finding is not relevant.")

        # Positive heuristics
        explicit_poc = bool(_POC_TERMS.search(text))
        has_lang = bool(candidate.language and candidate.language.lower() in _KNOWN_LANGUAGES)
        has_code_ext = bool(_CODE_EXTENSIONS.search(text))
        has_code_term = bool(_CODE_TERMS.search(text))
        has_code_evidence = bool(candidate.raw_metadata.get("code_evidence"))
        implementation = has_lang or has_code_ext or has_code_term or has_code_evidence

        advisory = bool(_ADVISORY_TERMS.search(text))
        detection = bool(_DETECTION_TERMS.search(text))

        is_curated = any(cur in lower_text for cur in _CURATED_DOMAINS)
        stars = candidate.stars or 0

        # Anti-deception / malware checks
        has_binary = bool(_BINARY_TERMS.search(text))
        has_obfuscation = bool(_OBFUSCATION_TERMS.search(text))
        has_scam = bool(_SCAM_TERMS.search(text))

        domain = urlparse(candidate.url).hostname or ""
        is_shortener = domain.lower() in _SHORTENERS

        if has_binary:
            warnings.append("binary_only")
            score += self.weights["binary_only"]
            reasons.append(f"{self.weights['binary_only']:.2f} mentions binary/executable (.exe/.dll) or password archive")

        if has_obfuscation:
            warnings.append("obfuscated_code")
            score += self.weights["obfuscated_code"]
            reasons.append(f"{self.weights['obfuscated_code']:.2f} obfuscation pattern detected (PowerShell -enc / certutil / iex)")

        if has_scam:
            warnings.append("scam_marketing")
            score += self.weights["scam_marketing"]
            reasons.append(f"{self.weights['scam_marketing']:.2f} commercial scam / payment / Telegram marketing detected")

        if is_shortener:
            warnings.append("unresolved_redirect")
            score += self.weights["unresolved_redirect"]
            reasons.append(f"{self.weights['unresolved_redirect']:.2f} URL shortener detected")

        if candidate.raw_metadata.get("archived"):
            warnings.append("archived_repository")
            score += self.weights["archived_repo"]
            reasons.append(f"{self.weights['archived_repo']:.2f} repository is archived / read-only")

        risky = bool(has_binary or has_obfuscation or has_scam)
        if risky and "untrusted_or_risky_content" not in warnings:
            warnings.append("untrusted_or_risky_content")

        if exact_cve and explicit_poc:
            score += self.weights["explicit_poc"]
            reasons.append(f"+{self.weights['explicit_poc']:.2f} explicit PoC/exploit terminology in source data")
            evidence.append("Explicit PoC/exploit terminology")

        if exact_cve and implementation:
            score += self.weights["implementation_evidence"]
            reasons.append(f"+{self.weights['implementation_evidence']:.2f} implementation or code evidence retrieved (language: {candidate.language or 'source code'})")
            evidence.append(f"Implementation/code evidence (lang: {candidate.language or 'source'})")

        if exact_cve and is_curated:
            score += self.weights["curated_platform"]
            reasons.append(f"+{self.weights['curated_platform']:.2f} hosted on curated security / exploit platform")
            evidence.append("Curated security repository / platform")

        if exact_cve and stars >= 20:
            score += self.weights["community_validation_high"]
            reasons.append(f"+{self.weights['community_validation_high']:.2f} community validation (>= 20 stars: {stars})")
            evidence.append(f"Community validation ({stars} stars)")
        elif exact_cve and stars >= 5:
            score += self.weights["community_validation_med"]
            reasons.append(f"+{self.weights['community_validation_med']:.2f} community validation (>= 5 stars: {stars})")
            evidence.append(f"Community validation ({stars} stars)")

        if exact_cve and cross_source_count > 1:
            score += self.weights["cross_source_reference"]
            reasons.append(f"+{self.weights['cross_source_reference']:.2f} cross-source corroboration: independently referenced across {cross_source_count} configured sources")
            evidence.append(f"Cross-source corroboration ({cross_source_count} sources)")

        if exact_cve and (advisory or detection) and not explicit_poc:
            score += self.weights["advisory_or_detection"]
            reasons.append(f"+{self.weights['advisory_or_detection']:.2f} related advisory, patch, scanner, or detection evidence")
            evidence.append("Advisory/patch/detection terminology")

        score = round(max(0.0, min(1.0, score)), 3)

        # Classification assignment
        if not exact_cve:
            match_type = label = "NOT_RELEVANT"
        elif risky or score < 0.25:
            match_type = "LOW_CONFIDENCE"
            label = "SUSPICIOUS" if risky else "LOW_CONFIDENCE"
        elif explicit_poc and implementation and score >= self.high_relevance_threshold:
            match_type = label = "HIGH_RELEVANCE_POC_CANDIDATE"
        elif explicit_poc and score >= self.possible_poc_threshold:
            match_type = label = "POSSIBLE_POC"
        elif advisory or detection:
            match_type = label = "ADVISORY_OR_PATCH" if advisory else "RELATED_DISCUSSION"
        elif exact_cve:
            match_type = label = "RELATED_DISCUSSION" if score >= 0.35 else "LOW_CONFIDENCE"
        else:
            match_type = label = "NOT_RELEVANT"

        metadata = dict(candidate.raw_metadata)
        repository_metadata = {
            key: metadata.get(key)
            for key in (
                "owner",
                "full_name",
                "stars",
                "forks",
                "language",
                "is_fork",
                "archived",
                "created_at",
                "updated_at",
                "default_branch",
            )
            if metadata.get(key) is not None
        }
        verification = "repository_metadata_and_search_evidence" if candidate.source == "github" else "public_post_metadata"

        return PoCResultSchema(
            cve_id=cve,
            url=candidate.url,
            title=candidate.title,
            source=candidate.source,
            author=candidate.author or "unknown",
            published_at=candidate.published_at,
            created_at=metadata.get("created_at"),
            updated_at=metadata.get("updated_at"),
            description=candidate.description,
            description_is_untrusted=True,
            linked_urls=candidate.linked_urls,
            repository_metadata=repository_metadata,
            match_type=match_type,
            confidence_score=score,
            confidence_label=label,
            stars=candidate.stars,
            language=candidate.language,
            is_fork=candidate.is_fork,
            warning_flags=list(dict.fromkeys(warnings)),
            evidence=list(dict.fromkeys(evidence)),
            score_reasons=reasons,
            duplicate_group=duplicate_group,
            source_references=[
                {"source": candidate.source, "url": candidate.url, "author": candidate.author or "unknown"}
            ],
            source_verification_status=verification,
        )

    def calculate_precision(self, results: Iterable[PoCResultSchema]) -> float:
        """Return a labelled relevance yield, not an externally measured precision rate."""
        res_list = list(results)
        if not res_list:
            return 0.0
        relevant = sum(
            r.match_type in {"HIGH_RELEVANCE_POC_CANDIDATE", "POSSIBLE_POC"}
            or r.confidence_label in {"HIGH_RELEVANCE_POC_CANDIDATE", "POSSIBLE_POC", "VERIFIED_CODE", "LIKELY_POC"}
            for r in res_list
        )
        return round(relevant / len(res_list), 4)
