from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.ml.predictor import analyze_text
from backend.detectors.url_detector import analyze_url
from backend.detectors.brand_detector import detect_brand
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

    # -----------------------------------------
    # 1. NLP phishing-message analysis
    # -----------------------------------------
    nlp_result = analyze_text(request.text)

    # -----------------------------------------
    # 2. URL security analysis
    # -----------------------------------------
    url_result = analyze_url(request.url)

    # -----------------------------------------
    # 3. Brand impersonation analysis
    # -----------------------------------------
    brand_result = detect_brand(request.url)

    # -----------------------------------------
    # 4. Combine all detector results
    # -----------------------------------------
    risk = calculate_risk(
        nlp_result,
        url_result,
        brand_result
    )

    return risk