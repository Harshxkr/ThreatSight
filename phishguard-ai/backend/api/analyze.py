# API route placeholder.
# The main endpoint currently lives in backend/main.py.
from fastapi import APIRouter
from pydantic import BaseModel, Field
from backend.scoring.risk_engine import calculate_risk


router = APIRouter()


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1)
    text: str = ""


class AnalyzeResponse(BaseModel):
    score: int
    level: str
    verdict: str
    signals: dict
    reasons: list[str]


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    # Temporary mock detector scores.
    # These will later come from the NLP, URL, and brand detectors.
    nlp_score = 50
    url_score = 50
    brand_score = 50

    risk = calculate_risk(
        nlp_score,
        url_score,
        brand_score
    )

    return {
        "score": risk["score"],
        "level": risk["level"],
        "verdict": risk["verdict"],
        "signals": {
            "nlp": nlp_score,
            "url": url_score,
            "brand": brand_score
        },
        "reasons": [
            "Security analysis is currently using mock detectors"
        ]
    }