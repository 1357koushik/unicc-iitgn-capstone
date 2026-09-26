from fastapi import APIRouter
from src.services.pipeline import run_threat_match_pipeline
from src.schemas.api_schemas import Team3OutputRequest
from src.contracts.chunk_schema import ThreatMatchResponse

router = APIRouter()

@router.post("/team3/format", response_model=ThreatMatchResponse)
async def team3_format(request: Team3OutputRequest) -> ThreatMatchResponse:
    """
    Team 3 handoff: full threat-match pipeline -> standard ThreatMatchResponse.
    Returns the identical format as POST /threats/match.
    Uses existing retrieval, scoring, classification, attribution, citation.
    """
    return await run_threat_match_pipeline(
        query=request.query,
        top_k=request.top_k,
        alpha=request.alpha,
    )
