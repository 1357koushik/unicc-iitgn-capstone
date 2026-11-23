from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any
import unicodedata


def utc_now() -> str:
    """Return an explicit UTC timestamp for source and result provenance."""
    return datetime.now(timezone.utc).isoformat()


def sanitize_untrusted_text(text: str, max_chars: int = 2000) -> str:
    """Sanitize untrusted text from external OSINT sources (R-3.1).

    Strips non-printable control characters, Unicode format characters
    (category 'Cf' including bidi overrides U+202A-U+202E, U+2066-U+2069 and
    zero-width spaces U+200B, U+FEFF, U+200C, U+200D, U+2060), collapses
    multiple whitespaces, and bounds length to max_chars to protect downstream
    LLM consumers from prompt injection, formatting bypasses, and DoS.
    """
    if not text:
        return ""
    chars = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat == "Cc":
            if ch not in ("\n", "\t", " "):
                continue
        elif cat == "Cf":
            continue
        chars.append(ch)
    cleaned = "".join(chars)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_chars]


@dataclass
class SearchConfig:
    """Per-source guardrails. Connectors must treat these as upper bounds."""

    result_limit: int = 10
    page_limit: int = 2
    request_limit: int = 4
    timeout_seconds: float = 100.0


@dataclass
class RawCandidate:
    """Untrusted source record before deterministic classification.

    ``url`` is the original platform record where possible. ``linked_urls`` holds
    artifacts mentioned by a social post, which permits grouping without claiming
    that a mention itself is an exploit implementation.
    """
    url: str
    title: str
    source: str
    author: str = "unknown"
    published_at: str | None = None
    description: str = ""
    stars: int | None = None
    forks: int | None = None
    language: str | None = None
    is_fork: bool | None = None
    linked_urls: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceSearchResponse:
    """Source-level outcome retained even when another connector succeeds."""

    source: str
    status: str
    retrieved_at: str = field(default_factory=utc_now)
    query: str = ""
    candidates: list[RawCandidate] = field(default_factory=list)
    next_cursor: str | None = None
    pages_fetched: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage_limitations: list[str] = field(default_factory=list)

    @property
    def result_count(self) -> int:
        return len(self.candidates)


class BasePoCSource(abc.ABC):
    """Consistent, bounded OSINT source contract.

    ``search`` remains as a compatibility shim for integrations which consumed a
    candidate list. Production orchestration calls ``search_with_status`` so a
    source outage is visible to analysts instead of silently looking like zero
    results.
    """

    source_name: str = "base"

    @abc.abstractmethod
    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        """Return normalized candidates, without executing or downloading code."""
        pass

    async def search_with_status(
        self, cve_id: str, config: SearchConfig | None = None
    ) -> SourceSearchResponse:
        config = config or SearchConfig()
        try:
            candidates = await self.search(cve_id, limit=config.result_limit)
            return SourceSearchResponse(
                source=self.source_name,
                status="success",
                query=cve_id,
                candidates=candidates[: config.result_limit],
                pages_fetched=1,
            )
        except TimeoutError:
            return SourceSearchResponse(
                source=self.source_name, status="timeout", query=cve_id,
                errors=["Source request timed out."],
            )
        except Exception as exc:  # Connector errors must not take down other sources.
            return SourceSearchResponse(
                source=self.source_name, status="error", query=cve_id,
                errors=[f"{type(exc).__name__}: {str(exc)[:240]}"],
            )
