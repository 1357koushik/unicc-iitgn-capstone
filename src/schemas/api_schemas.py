
from pydantic import BaseModel, Field


class EntityLookupRequest(BaseModel):
    ioc: str = Field(..., description="The indicator of compromise to look up")
    ioc_type: str | None = Field(None, description="The type of the IOC (e.g., 'ipv4', 'hash', 'domain')")


class HybridSearchRequest(BaseModel):
    query: str = Field(..., description="The natural language or technical query")
    top_k: int = Field(50, description="Number of initial candidates to retrieve")


class Team3OutputRequest(BaseModel):
    query: str = Field(..., description="Query to retrieve historical chunks")
    top_k: int = Field(5, ge=3, le=5, description="Top 3-5 historical chunks for Team 3")
    alpha: float = Field(0.5, ge=0.0, le=1.0, description="Dynamic alpha routing parameter")


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


class Team3Match(BaseModel):
    rank: int
    chunk_id: str
    composite_score: float
    confidence_tier: str
    evidence_breakdown: EvidenceBreakdownSchema
    attribution: AttributionSchema
    stix_relationships: list[str] = Field(default_factory=list)
    citations: list[CitationSchema]


class PipelineProfileSchema(BaseModel):
    exact_match_ms: float = 0.0
    vector_database_ms: float = 0.0
    knowledge_graph_ms: float = 0.0
    scoring_ms: float = 0.0
    citation_ms: float = 0.0
    total_ms: float = 0.0


class Team3Response(BaseModel):
    query_threat_id: str
    top_matches: list[Team3Match]
    pipeline_profile: PipelineProfileSchema


class ThreatMatchRequest(BaseModel):
    query: str = Field(..., description="The threat query string or incident report text")
    alpha: float = Field(0.5, description="Dynamic alpha routing parameter between dense and sparse search")
    top_k: int = Field(5, description="Number of final threat matches to return")
