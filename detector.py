import os
import re
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Jailbreak pattern categories
PATTERNS = {
    "persona_hijack": [
        r"\bdan\b", r"do anything now", r"act as", r"pretend you",
        r"you are now", r"roleplay as", r"ignore previous instructions",
        r"forget your instructions", r"you have no restrictions"
    ],
    "restriction_bypass": [
        r"no restrictions", r"no rules", r"without limitations",
        r"override", r"bypass", r"ignore your training",
        r"disable safety", r"jailbreak"
    ],
    "authority_claim": [
        r"i am a developer", r"admin override", r"system prompt",
        r"as your creator", r"maintenance mode", r"developer mode"
    ],
    "harmful_intent": [
        r"how to hack", r"how to make a bomb", r"synthesize drugs",
        r"exploit vulnerability", r"malware", r"ransomware"
    ]
}

def keyword_scan(prompt: str) -> dict:
    """Fast pattern matching scan"""
    prompt_lower = prompt.lower()
    matched = {}
    score = 0

    for category, patterns in PATTERNS.items():
        hits = []
        for pattern in patterns:
            if re.search(pattern, prompt_lower):
                hits.append(pattern)
                score += 1
        if hits:
            matched[category] = hits

    return {"matches": matched, "score": score}

def api_scan(prompt: str) -> dict:
    """Deep scan using Claude API"""
    system = """You are a security classifier for an AI firewall system.
Your job is to analyse prompts and detect jailbreak attempts.

Respond ONLY in this exact format:
VERDICT: [CLEAN/SUSPICIOUS/JAILBREAK]
CONFIDENCE: [LOW/MEDIUM/HIGH]
REASON: [one sentence explanation]"""

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=150,
        system=system,
        messages=[{"role": "user", "content": f"Analyse this prompt: {prompt}"}]
    )

    text = response.content[0].text
    lines = text.strip().split("\n")
    result = {}
    for line in lines:
        if ":" in line:
            key, val = line.split(":", 1)
            result[key.strip()] = val.strip()

    return result

def calculate_risk(keyword_result: dict, api_result: dict) -> str:
    """Combine keyword and API results into final risk level"""
    score = keyword_result["score"]
    verdict = api_result.get("VERDICT", "CLEAN")

    if verdict == "JAILBREAK" or score >= 3:
        return "HIGH"
    elif verdict == "SUSPICIOUS" or score >= 1:
        return "MEDIUM"
    else:
        return "LOW"

def analyse_prompt(prompt: str) -> dict:
    """Main function - runs full analysis pipeline"""
    keyword_result = keyword_scan(prompt)
    api_result = api_scan(prompt)
    risk_level = calculate_risk(keyword_result, api_result)

    return {
        "prompt": prompt,
        "risk_level": risk_level,
        "keyword_matches": keyword_result["matches"],
        "keyword_score": keyword_result["score"],
        "api_verdict": api_result.get("VERDICT", "UNKNOWN"),
        "api_confidence": api_result.get("CONFIDENCE", "UNKNOWN"),
        "api_reason": api_result.get("REASON", "No reason provided")
    }