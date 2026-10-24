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
    allowed_sources: list[str] | None = Field(None, description="List of allowed source_orgs. If None, all are allowed.")


class EvidenceBreakdownSchema(BaseModel):
    ioc_similarity: float = 0.0
    cve_similarity: float = 0.0
    ttp_similarity: float = 0.0
    semantic_similarity: float = 0.0
    features: dict[str, float] = Field(default_factory=dict)


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
    cve_id: str | None = Field(None, description="Normalized CVE searched; not inferred from an unrelated source.")
    url: str = Field(..., description="Original source record URL for independent review")
    title: str = Field(..., description="Repository name or neutral source summary")
    source: str = Field(..., description="Source platform: github, x, mastodon, bluesky")
    author: str = Field("unknown", description="Author, owner, or handle when supplied by the source")
    published_at: str | None = Field(None, description="Source publication timestamp when supplied")
    created_at: str | None = None
    updated_at: str | None = None
    retrieved_at: str | None = None
    description: str = ""
    linked_urls: list[str] = Field(default_factory=list, description="Artifacts linked by this source record")
    repository_metadata: dict[str, object] = Field(default_factory=dict)
    match_type: str = Field("LOW_CONFIDENCE", description="HIGH_RELEVANCE_POC_CANDIDATE | POSSIBLE_POC | RELATED_DISCUSSION | ADVISORY_OR_PATCH | LOW_CONFIDENCE | NOT_RELEVANT")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Deterministic relevance heuristic, not exploit success probability")
    confidence_label: str = Field("LOW_CONFIDENCE", description="Human-readable relevance category; no code execution validation claim")
    stars: int | None = Field(None, description="GitHub stars if applicable")
    language: str | None = Field(None, description="Programming language if applicable")
    is_fork: bool | None = Field(None, description="Whether the repository is a fork")
    warning_flags: list[str] = Field(default_factory=list, description="Safety or deception warning flags")
    evidence: list[str] = Field(default_factory=list, description="Observable facts used for classification")
    score_reasons: list[str] = Field(default_factory=list, description="Deterministic scoring contributions")
    duplicate_group: str | None = Field(None, description="Canonical artifact grouping key, when reliable")
    source_references: list[dict[str, object]] = Field(default_factory=list, description="Original records retained within this grouped finding")
    source_verification_status: str = Field("metadata_only", description="What this application actually retrieved, never proof that code executes")


class SourceStatusSchema(BaseModel):
    source: str
    status: str = Field(description="success | partial | not_configured | unauthorized | rate_limited | timeout | access_restricted | error | disabled")
    retrieved_at: str
    query: str = ""
    result_count: int = Field(0, ge=0)
    pages_fetched: int = Field(0, ge=0)
    next_cursor: str | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)


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
    match_type: str | None = Field(None, description="EXACT_ID | EXACT_HASH | LEARNED_MODEL | HEURISTIC_PRESENCE")
    tier_basis: str | None = Field(None, description="DETERMINISTIC_L1 | CALIBRATED_LOGISTIC_REGRESSION | UNCALIBRATED_BEHAVIORAL_HEURISTIC")
    calibrated: bool = Field(False, description="Whether the score represents a calibrated probability")
    degraded: bool = Field(False, description="Whether confidence was resolved in safe degraded mode")
    model_version: str | None = Field(None, description="Model or heuristic version identifier")


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
    precision_score: float = Field(..., description="Share of returned records meeting the configured relevance threshold; not a measured production precision claim")
    sources_queried: list[str]
    results: list[PoCResultSchema]
    latency_ms: float
    cached: bool = False
    source_statuses: list[SourceStatusSchema] = Field(default_factory=list)
    retrieved_at: str | None = None
    coverage_limitations: list[str] = Field(default_factory=list)

