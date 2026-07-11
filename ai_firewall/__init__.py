"""ai-firewall — prompt-injection detection library.

Public surface for library consumers (e.g. llm-honeypot Phase B, which pins
this package as a SHA-pinned git dependency — see that repo's DECISIONS.md
P1). The Flask app in this repo consumes the same surface; there is exactly
one implementation of the detection logic.
"""

from ai_firewall.detector import (
    HARD_MARKERS,
    analyse_prompt,
    api_scan,
    build_classification_request,
    calculate_risk,
    has_hard_marker,
    normalise_prompt,
    validate_api_result,
)

__version__ = "0.2.0"

__all__ = [
    "HARD_MARKERS",
    "analyse_prompt",
    "api_scan",
    "build_classification_request",
    "calculate_risk",
    "has_hard_marker",
    "normalise_prompt",
    "validate_api_result",
    "__version__",
]
