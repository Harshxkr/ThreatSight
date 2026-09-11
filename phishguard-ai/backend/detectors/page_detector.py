"""Future deep-scan module.

Teammate 3 can add DOM analysis here:
- password inputs
- email inputs
- login forms
- external form actions
- iframes
- visible brand/domain mismatch
"""


def analyze_page(page_data: dict) -> dict:
    return {
        "score": 0.0,
        "signals": []
    }
