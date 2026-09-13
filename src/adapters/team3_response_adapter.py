"""Convert ThreatMatchResponse -> Team 3 required response."""
from __future__ import annotations
from src.contracts.chunk_schema import ThreatMatchResponse
from src.schemas.api_schemas import (
    Team3Response, Team3Match, EvidenceBreakdownSchema,
    AttributionSchema, CitationSchema, PipelineProfileSchema,
)


def adapt_pipeline_to_team3(pipeline: ThreatMatchResponse) -> Team3Response:
    matches = []
    for rank_idx, m in enumerate(pipeline.top_matches, start=1):
        # Evidence breakdown from pipeline sub-scores
        eb = m.evidence_breakdown
        breakdown = EvidenceBreakdownSchema(
            ioc_similarity=eb.ioc_similarity if eb else 0.0,
            cve_similarity=eb.cve_similarity if eb else 0.0,
            ttp_similarity=eb.ttp_similarity if eb else 0.0,
            semantic_similarity=eb.semantic_similarity if eb else 0.0,
        )
        # Attribution
        att = m.attribution
        attribution = AttributionSchema(
            matching_iocs=att.matching_iocs if att else [],
            matching_cves=att.matching_cves if att else [],
            shared_malware=att.shared_malware if att else [],
            matching_mitre_techniques=att.matching_mitre_techniques if att else [],
        )
        # Citations
        citations = []
        for c in (m.citations or []):
            citations.append(CitationSchema(
                doc_id=c.doc_id,
                doc_title=c.doc_title,
                source_org=c.source_org,
                published_date=str(c.published_date) if c.published_date else "",
                page_number=c.page_number,
                text_snippet=c.text_snippet[:500] if c.text_snippet else "",
            ))
        matches.append(Team3Match(
            rank=rank_idx,
            chunk_id=m.chunk_id,
            composite_score=m.composite_score,
            confidence_tier=m.confidence_tier,
            evidence_breakdown=breakdown,
            attribution=attribution,
            stix_relationships=m.stix_relationships or [],
            citations=citations,
        ))

    profile = pipeline.pipeline_profile
    pipeline_profile = PipelineProfileSchema(
        exact_match_ms=getattr(profile, "exact_match_ms", 0.0),
        vector_database_ms=getattr(profile, "vector_database_ms", profile.retrieval_ms),
        knowledge_graph_ms=getattr(profile, "knowledge_graph_ms", 0.0),
        scoring_ms=profile.scoring_ms,
        citation_ms=profile.citation_ms,
        total_ms=profile.total_ms,
    )

    return Team3Response(
        query_threat_id=pipeline.query_threat_id,
        top_matches=matches,
        pipeline_profile=pipeline_profile,
    )
