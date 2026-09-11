from fastapi import FastAPI
from backend.api.analyze import router as analyze_router

<<<<<<< HEAD
app = FastAPI(
    title="ThreatSight API",
    description="AI-powered phishing detection API",
    version="1.0.0"
=======
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
>>>>>>> feature/security
)

app.include_router(analyze_router)


@app.get("/")
def root():
    return {
        "name": "ThreatSight",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
<<<<<<< HEAD
        "status": "healthy"
    }
=======
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
>>>>>>> feature/security
