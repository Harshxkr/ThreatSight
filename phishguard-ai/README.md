# 🛡️ PhishGuard AI

Real-time, explainable AI-powered phishing protection for the browser.

## Project Architecture

```text
User hovers over link
        ↓
Chrome Extension (frontend)
        ↓
POST /analyze
        ↓
FastAPI backend
        ↓
 ┌──────┼────────┐
 ↓      ↓        ↓
NLP    URL      Brand
 ↓      ↓        ↓
 └──────┼────────┘
        ↓
   Risk Engine
        ↓
  0–100 risk score
        ↓
Chrome Extension
        ↓
Explainable warning
```

## Team Modules

- `frontend/` — Chrome extension UI and browser interaction
- `backend/ml/` — NLP/AI model
- `backend/detectors/` — URL, brand and page security analysis
- `backend/scoring/` — final risk aggregation
- `docs/` — API and architecture documentation

## Quick Start

### Backend

```bash
cd backend
python -m venv .venv

# macOS/Linux
source .venv/bin/activate

# Windows
# .venv\Scripts\activate

pip install -r requirements.txt
uvicorn main:app --reload
```

Backend runs at `http://localhost:8000`.

Test:

```bash
curl -X POST http://localhost:8000/analyze   -H "Content-Type: application/json"   -d '{"url":"https://microsoft-login-security.xyz/verify","text":"URGENT! Your account will be suspended. Verify now."}'
```

### Chrome Extension

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `frontend` folder.
6. Open a webpage containing links and hover over a link.

The extension calls the local backend at `http://localhost:8000`.

## Team Workflow

Create feature branches:

```text
feature/frontend
feature/nlp
feature/security
feature/backend
```

Do not push directly to `main`. Merge tested work through Pull Requests.

## API Contract

`POST /analyze`

Request:

```json
{
  "url": "https://microsoft-login-security.xyz/verify",
  "text": "Your account will be suspended. Verify now."
}
```

Response:

```json
{
  "score": 91,
  "level": "CRITICAL",
  "verdict": "LIKELY_PHISHING",
  "signals": {
    "nlp": 94,
    "url": 88,
    "brand": 95,
    "page": 80
  },
  "reasons": [
    "Possible Microsoft impersonation",
    "Urgent language detected",
    "Credential request detected",
    "Suspicious domain"
  ]
}
```

## Hackathon Priority

### P0 — Must Have
- Hover detection
- URL extraction
- `/analyze` API
- URL analysis
- NLP phishing classifier
- Brand detection
- Risk score
- Explanation

### P1 — Should Have
- Website/DOM analysis
- Threat intelligence
- Better UI

### P2 — Bonus
- QR analysis
- Attachment analysis
- Dashboard
