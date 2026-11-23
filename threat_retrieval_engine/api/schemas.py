from __future__ import annotations

from typing import Any

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
    query: str = Field(..., max_length=40960, description="Threat query string or incident report text (bounded, R35)")
    top_k: int = Field(5, ge=1, le=500, description="Number of top threat matches to return")
    alpha: float = Field(0.5, ge=0.0, le=1.0, description="v1 only: dense/lexical weighting. Ignored by v2, whose fusion weights are tuned on the benchmark dev split")
    allowed_sources: list[str] | None = Field(None, description="List of allowed source_orgs. If None, all are allowed.")
    include_pocs: bool = Field(False, description="Whether to perform live OSINT PoC enrichment. Defaults to False for fast decoupled matching (R34)")
    include_techniques: bool | None = Field(None, description="v2: also rank the MITRE ATT&CK techniques the text describes (attack_techniques). None uses the server default (on)")


class FeatureVectorSchema(BaseModel):
    """Explicit 12-dimensional Layer 2 feature vector."""
    has_cve: float = 0.0
    has_ioc: float = 0.0
    has_ttp: float = 0.0
    cve_coverage: float = 0.0
    ioc_coverage: float = 0.0
    ttp_coverage: float = 0.0
    reranker_score: float = 0.0
    bm25_norm_score: float = 0.0
    inter_cve_cov: float = 0.0
    inter_ioc_cov: float = 0.0
    inter_ttp_cov: float = 0.0
    inter_reranker: float = 0.0

    model_config = {"extra": "allow"}


class EvidenceBreakdownSchema(BaseModel):
    ioc_similarity: float | None = 0.0
    cve_similarity: float | None = 0.0
    ttp_similarity: float | None = 0.0
    semantic_similarity: float | None = 0.0
    features: FeatureVectorSchema | dict[str, float] = Field(
        default_factory=dict,
        description="12-dimensional Layer 2 feature vector (train-serve parity)",
    )


class AttributionSchema(BaseModel):
    matching_iocs: list[str] = Field(default_factory=list)
    matching_cves: list[str] = Field(default_factory=list)
    shared_malware: list[str] = Field(default_factory=list)
    matching_mitre_techniques: list[str] = Field(default_factory=list)


class CitationSchema(BaseModel):
    doc_id: str
    doc_title: str
    source_org: str
    published_date: str | None = None
    page_number: int | None = None
    text_snippet: str
    provenance_status: str = Field("VERIFIED", description="VERIFIED | MISSING (R9)")


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
    description_is_untrusted: bool = Field(
        True,
        description="Explicit flag indicating downstream LLM consumers must treat description as raw untrusted data and not prompt instructions"
    )
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
    status: str = Field(description="success | partial | source_not_supported | not_configured | unauthorized | rate_limited | timeout | access_restricted | error | disabled | cost_protection | invalid_input | malformed_response | unavailable")
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
    evidence_record_class: str | None = Field("DESCRIPTION", description="DESCRIPTION | METADATA_STUB (R6a)")
    sources_found: dict[str, str] = Field(default_factory=dict, description="Multi-source provenance corroboration (R10)")
    corroboration_count: int = Field(1, description="Number of independent sources corroborating this identity (R10)")
    cisa_kev: bool = Field(False, description="Whether listed in CISA KEV (R6b, R11)")
    epss_score: float | None = Field(None, description="EPSS exploitation probability score (R6b, R11)")
    matched_names: list[str] = Field(default_factory=list, description="v2: IDs, nicknames or ATT&CK names of the query that led to this result")
    poc_status: str | None = Field(None, description="v2: why PoC lookup did not complete for this result (timeout, source error)")


class PipelineProfileSchema(BaseModel):
    exact_match_ms: float = 0.0
    vector_database_ms: float = 0.0
    knowledge_graph_ms: float = 0.0
    scoring_ms: float = 0.0
    technique_ms: float = 0.0
    citation_ms: float = 0.0
    poc_discovery_ms: float = 0.0
    total_ms: float = 0.0


class MatchResponse(BaseModel):
    query_threat_id: str
    top_matches: list[TopMatchSchema]
    pipeline_profile: PipelineProfileSchema
    degraded_components: list[str] = Field(default_factory=list, description="List of components operating in degraded state (R14)")
    deadline_exceeded: bool = Field(False, description="Whether request processing reached D_match deadline (V2)")
    pipeline_version: str = Field("v1", description="v1 | v2")
    skipped_stages: list[str] = Field(default_factory=list, description="v2: stages skipped to meet the deadline (dense, rerank)")
    notices: list[dict[str, Any]] = Field(default_factory=list, description="v2: not_in_corpus, no_ioc_data_in_corpus, ...")
    nicknames: list[dict[str, Any]] = Field(default_factory=list, description="v2: vulnerability names found in the query and their CVEs")
    attack_techniques: list[dict[str, Any]] = Field(default_factory=list, description="v2: ATT&CK techniques the text describes, best first ({technique_id, name, rank, rerank_score, evidence})")


class PoCFindRequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="Target CVE identifier (e.g. CVE-2024-3400)")
    max_results: int = Field(20, ge=1, le=1000, description="Maximum total results to return")
    sources: list[str] = Field(
        default_factory=lambda: ["github", "mastodon", "bluesky"],
        description="List of sources to search",
    )
    min_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Minimum confidence score threshold")


class PoCFindResponse(BaseModel):
    cve_id: str
    total_found: int
    precision_score: float = Field(..., description="Relevance yield: share of returned records meeting threshold; not a measured production precision claim (R26)")
    sources_queried: list[str]
    results: list[PoCResultSchema]
    latency_ms: float
    cached: bool = False
    source_statuses: list[SourceStatusSchema] = Field(default_factory=list)
    retrieved_at: str | None = None
    coverage_limitations: list[str] = Field(default_factory=list)
