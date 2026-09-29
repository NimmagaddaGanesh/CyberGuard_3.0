"""Verification script to test the LLM pipeline and structured output generation.

Usage:
    python test_llm.py
"""
import json
import os
import sys
from pathlib import Path

# Add current directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from llm_service import investigate_incident, IncidentAlert


def main():
    print("=" * 60)
    print("CYBERGUARD — TESTING LLM END INVESTIGATION OUTPUT")
    print("=" * 60)

    sample_alert = {
        "alert_title": "Detected Distributed SSH Credential Stuffing on auth-cluster",
        "affected_system": "auth-cluster.prod.internal",
        "raw_logs": "Multiple failed SSH logins from proxy network. IPs: 198.51.100.24, 198.51.100.25. Repeated invalid user root."
    }

    print("\n[INPUT ALERT]")
    print(json.dumps(sample_alert, indent=2))

    print("\nRunning full pipeline (Retrieval -> Bayesian Confidence -> Groq LLM)...")
    try:
        response = investigate_incident(sample_alert)
        print("\n" + "=" * 60)
        print("[SUCCESS] STRUCTURED OUTPUT GENERATED:")
        print("=" * 60)
        print(json.dumps(response.model_dump(), indent=2))
        print("\n[OK] The LLM end is working and ready for integration!")
    except Exception as e:
        print(f"\n[ERROR] Pipeline test failed: {e}")


if __name__ == "__main__":
    main()
