# PhishGuard AI API Contract

## POST /analyze

### Request

```json
{
  "url": "https://example.com",
  "text": "Message or link text"
}
```

### Response

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
    "Urgent language detected"
  ]
}
```

Frontend should depend only on this contract, not on internal detector implementations.
