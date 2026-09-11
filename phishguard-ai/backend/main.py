from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.detectors.url_detector import analyze_url
from backend.detectors.brand_detector import detect_brand
from backend.ml.predictor import analyze_text
from backend.scoring.risk_engine import calculate_risk


app = FastAPI(
    title="PhishGuard AI API",
    version="0.1.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str
    text: str = ""


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "phishguard-ai"
    }


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    nlp_result = analyze_text(request.text)

    url_result = analyze_url(request.url)

    brand_result = detect_brand(request.url)

    result = calculate_risk(
        nlp_result=nlp_result,
        url_result=url_result,
        brand_result=brand_result,
    )

    return result
