# API route placeholder.
# The main endpoint currently lives in backend/main.py.
from fastapi import APIRouter
from pydantic import BaseModel, Field


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
    # Temporary mock values.
    # These will later come from the NLP, URL, and brand detectors.

    nlp_score = 50
    url_score = 50
    brand_score = 50

    final_score = round(
        nlp_score * 0.35
        + url_score * 0.35
        + brand_score * 0.30
    )

    if final_score <= 30:
        level = "LOW"
        verdict = "LIKELY_SAFE"
    elif final_score <= 60:
        level = "SUSPICIOUS"
        verdict = "NEEDS_REVIEW"
    elif final_score <= 80:
        level = "HIGH"
        verdict = "LIKELY_PHISHING"
    else:
        level = "CRITICAL"
        verdict = "LIKELY_PHISHING"

    return {
        "score": final_score,
        "level": level,
        "verdict": verdict,
        "signals": {
            "nlp": nlp_score,
            "url": url_score,
            "brand": brand_score
        },
        "reasons": [
            "Security analysis is currently using mock detectors"
        ]
    }