from __future__ import annotations

try:
    from pydantic import BaseModel, Field
except ImportError:
    from dataclasses import dataclass, field as _field

    class BaseModel:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def dict(self) -> dict[str, Any]:
            return self.__dict__

        def model_dump(self) -> dict[str, Any]:
            return self.__dict__

    def Field(default: Any = ..., **kwargs: Any) -> Any:
        if default is ...:
            if "default_factory" in kwargs:
                return _field(default_factory=kwargs["default_factory"])
            return _field()
        return _field(default=default)


class MatchRequest(BaseModel):
    query: str = Field(..., description="Threat query string or incident report text")
    top_k: int = Field(5, ge=1, le=50, description="Number of top threat matches to return")
    alpha: float = Field(0.5, ge=0.0, le=1.0, description="Weighting parameter between dense vector and sparse lexical search")


class EvidenceBreakdownSchema(BaseModel):
    ioc_similarity: float = 0.0
    cve_similarity: float = 0.0
    ttp_similarity: float = 0.0
    semantic_similarity: float = 0.0


class AttributionSchema(BaseModel):
    matching_iocs: list[str] = Field(default_factory=list)
    matching_cves: list[str] = Field(default_factory=list)
    shared_malware: list[str] = Field(default_factory=list)
    matching_mitre_techniques: list[str] = Field(default_factory=list)


class CitationSchema(BaseModel):
    doc_id: str
    doc_title: str
    source_org: str
    published_date: str
    page_number: int | None = None
    text_snippet: str


class PoCResultSchema(BaseModel):
    url: str = Field(..., description="Direct URL to PoC repository, script, or exploit post")
    title: str = Field(..., description="Title, repo name, or text summary of the PoC")
    source: str = Field(..., description="Source platform: github, x, mastodon, bluesky")
    author: str = Field(..., description="Author, developer, or handle")
    published_at: str = Field(..., description="Publication timestamp (ISO 8601)")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Verification confidence score")
    confidence_label: str = Field("LIKELY_POC", description="VERIFIED_CODE | LIKELY_POC | DISCUSSION | SUSPICIOUS")
    stars: int | None = Field(None, description="GitHub stars if applicable")
    language: str | None = Field(None, description="Programming language if applicable")
    is_fork: bool | None = Field(None, description="Whether the repository is a fork")
    warning_flags: list[str] = Field(default_factory=list, description="Safety or deception warning flags")


class TopMatchSchema(BaseModel):
    rank: int
    chunk_id: str
    composite_score: float
    confidence_tier: str
    evidence_breakdown: EvidenceBreakdownSchema
    attribution: AttributionSchema
    stix_relationships: list[str] = Field(default_factory=list)
    citations: list[CitationSchema]
    pocs: list[PoCResultSchema] = Field(default_factory=list, description="Verified public PoCs or exploits for matched CVEs")


class PipelineProfileSchema(BaseModel):
    exact_match_ms: float = 0.0
    vector_database_ms: float = 0.0
    knowledge_graph_ms: float = 0.0
    scoring_ms: float = 0.0
    citation_ms: float = 0.0
    poc_discovery_ms: float = 0.0
    total_ms: float = 0.0


class MatchResponse(BaseModel):
    query_threat_id: str
    top_matches: list[TopMatchSchema]
    pipeline_profile: PipelineProfileSchema


class PoCFindRequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="Target CVE identifier (e.g. CVE-2024-3400)")
    max_results: int = Field(20, ge=1, le=100, description="Maximum total results to return")
    sources: list[str] = Field(
        default_factory=lambda: ["github", "x", "mastodon", "bluesky"],
        description="List of sources to search",
    )
    min_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Minimum confidence score threshold")


class PoCFindResponse(BaseModel):
    cve_id: str
    total_found: int
    precision_score: float = Field(..., description="Precision of findings: (VERIFIED_CODE + LIKELY_POC) / total")
    sources_queried: list[str]
    results: list[PoCResultSchema]
    latency_ms: float
    cached: bool = False

