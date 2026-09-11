from fastapi import FastAPI
from backend.api.analyze import router as analyze_router

app = FastAPI(
    title="ThreatSight API",
    description="AI-powered phishing detection API",
    version="1.0.0"
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
        "status": "healthy"
    }