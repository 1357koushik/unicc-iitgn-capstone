from fastapi import APIRouter
from src.services.pipeline import run_threat_match_pipeline
from src.schemas.api_schemas import Team3OutputRequest, Team3Response
from src.adapters.team3_response_adapter import adapt_pipeline_to_team3

router = APIRouter()

@router.post("/team3/format", response_model=Team3Response)
async def team3_format(request: Team3OutputRequest) -> Team3Response:
    """
    Team 3 handoff: full threat-match pipeline -> Team 3 response format.
    Uses existing retrieval, scoring, classification, attribution, citation.
    """
    result = await run_threat_match_pipeline(query=request.query, top_k=request.top_k, alpha=request.alpha)
    return adapt_pipeline_to_team3(result)
