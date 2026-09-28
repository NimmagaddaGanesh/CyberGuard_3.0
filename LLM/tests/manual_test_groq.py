"""Manual test script to perform ONE real Groq API request using local .env credentials.

Usage:
    python tests/manual_test_groq.py
    or
    python -m tests.manual_test_groq
"""
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path when executed directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import os
from dotenv import load_dotenv
load_dotenv()
from llm_service import LLMService, llm_service


def run_manual_test():
    print("=== CyberGuard — Manual Groq Live Inference Test ===")
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("[ERROR] GROQ_API_KEY is not set in your .env file.")
        sys.exit(1)

    model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    print(f"Model configured: {model}")
    print("Initializing Groq client...")

    service = llm_service

    # Sample alert simulating an SSH credential attack
    alert_title = "Multiple SSH login failures detected from external subnet"
    raw_logs = (
        "Sep 28 09:40:01 auth-gateway sshd[44102]: Failed password for invalid user root from 198.51.100.24 port 51224\n"
        "Sep 28 09:40:02 auth-gateway sshd[44105]: Failed password for invalid user admin from 198.51.100.24 port 51226\n"
        "Sep 28 09:40:04 auth-gateway sshd[44109]: Failed password for invalid user ubuntu from 198.51.100.24 port 51230"
    )

    # Historical context showing a past resolution pattern
    historical_context = [
        {
            "incident_id": "INC-2026-0042",
            "incident_type": "Brute Force Attack",
            "root_cause": "Credential stuffing attack via leaked credential dump",
            "recommended_playbook": "PB-003",
            "resolutions_tried": [
                {
                    "action": "Enforce MFA and reset session keys",
                    "success": True,
                    "efficacy_score": 0.94
                },
                {
                    "action": "Temporary IP block on single subnet",
                    "success": False,
                    "efficacy_score": 0.20,
                    "analyst_notes": "Attacker switched to distributed residential proxies"
                }
            ],
            "lessons_learned": "Password-only endpoints represent critical technical debt; prioritize hardware key enrollment."
        }
    ]

    print("Sending request to Groq API...")
    try:
        response = service.investigate(
            alert_title=alert_title,
            raw_logs=raw_logs,
            affected_system="Internal Auth Gateway",
            historical_context=historical_context
        )
        print("\n[SUCCESS] Structured JSON response successfully validated against Pydantic schema:")
        print(json.dumps(response.model_dump(), indent=2))
    except Exception as e:
        print(f"\n[FAILURE] Error calling Groq API: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_manual_test()
