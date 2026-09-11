# Architecture

```text
Chrome Extension
      |
      | URL + text
      v
FastAPI
      |
      +--> NLP classifier
      |
      +--> URL analyzer
      |
      +--> Brand detector
      |
      +--> Page analyzer (deep scan, later)
      |
      v
Risk Engine
      |
      v
0-100 score + explanations
      |
      v
Chrome Extension
```

## Quick Scan

Runs on hover:
- URL
- link text
- URL heuristics
- brand impersonation
- NLP

## Deep Scan

Optional user action:
- DOM
- login/password fields
- iframes
- external form actions
- redirects
- reputation
