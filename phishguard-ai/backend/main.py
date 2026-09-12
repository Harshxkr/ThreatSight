from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.analyze import router as analyze_router


app = FastAPI(
    title="ThreatSight API",
    description="AI-powered phishing detection API",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


@app.get("/test")
def test_page():
    from fastapi.responses import HTMLResponse
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ThreatSight Chrome Extension Test Page</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; line-height: 1.6; background: #0f172a; color: #e2e8f0; }
        h1 { color: #38bdf8; }
        .card { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
        a { display: inline-block; color: #60a5fa; font-weight: bold; margin: 10px 0; text-decoration: none; padding: 8px 14px; background: #0f172a; border-radius: 6px; border: 1px solid #3b82f6; }
        a:hover { background: #1d4ed8; color: white; }
        .desc { color: #94a3b8; font-size: 14px; margin-bottom: 5px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-left: 8px; }
        .phish { background: #ef4444; color: white; }
        .safe { background: #10b981; color: white; }
    </style>
</head>
<body>
    <h1>🛡️ ThreatSight Extension Test Lab</h1>
    <p>Hover over the links below for ~400ms to test your AI-powered Chrome extension in real time!</p>

    <div class="card">
        <h3>1. Brand Impersonation Phishing Link <span class="badge phish">MALICIOUS</span></h3>
        <p class="desc">Simulates a spoofed Microsoft credential harvester with urgent text:</p>
        <p>URGENT! Your account will be suspended. <a href="http://microsoft-login-security.xyz/verify">Click here immediately to verify your Microsoft password</a></p>
    </div>

    <div class="card">
        <h3>2. PayPal Financial Phishing Link <span class="badge phish">MALICIOUS</span></h3>
        <p class="desc">Simulates urgent payment verification fraud:</p>
        <p>Your payment failed. <a href="http://paypal-security-login.com/update">Verify your credit card and update credentials now</a></p>
    </div>

    <div class="card">
        <h3>3. Suspicious IP Address Link <span class="badge phish">SUSPICIOUS</span></h3>
        <p class="desc">Link pointing directly to a raw IP address login form:</p>
        <p><a href="http://192.168.1.100/login">Access internal server login</a></p>
    </div>

    <div class="card">
        <h3>4. Legitimate Safe Link <span class="badge safe">SAFE</span></h3>
        <p class="desc">Official verified website:</p>
        <p><a href="https://www.google.com">Visit Official Google Search</a></p>
    </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)