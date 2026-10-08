from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class RawCandidate:
    """Internal normalized representation of a PoC / exploit candidate from any source."""
    url: str
    title: str
    source: str
    author: str
    published_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    description: str = ""
    stars: int | None = None
    forks: int | None = None
    language: str | None = None
    is_fork: bool | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)


class BasePoCSource(abc.ABC):
    """Abstract base class for all OSINT PoC scrapers."""

    source_name: str = "base"

    @abc.abstractmethod
    async def search(self, cve_id: str, limit: int = 10) -> list[RawCandidate]:
        """Search the data source for PoCs or exploits associated with a specific CVE ID."""
        pass
