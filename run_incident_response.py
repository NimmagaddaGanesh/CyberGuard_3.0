"""CyberGuard Terminal Incident Response Runner.

Demonstrates the service-oriented pipeline using:
    context_builder_service  (dataset, retrieval, Bayesian confidence)
            ↓
    llm_service              (prompt engineering, Groq LLM inference)
            ↓
    Structured Incident Response (Canonical JSON output)

Usage:
    python run_incident_response.py                 # Interactive mode
    python run_incident_response.py --random        # Random incident from dataset
    python run_incident_response.py --incident-id <ID> # Specific incident
    python run_incident_response.py --file <PATH>   # Custom alert JSON
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

# Load .env file automatically
from dotenv import load_dotenv
load_dotenv()

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Configure stdout for utf-8 on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from context_builder_service import context_builder_service, IncidentAlert, IncidentRecord
from llm_service import llm_service, investigate_incident


def run_pipeline(alert: IncidentAlert, incident_id_to_exclude: str = None, original_incident: IncidentRecord = None):
    """Executes the complete CyberGuard incident response workflow using the services."""
    banner = "=" * 60
    print(f"\n{banner}")
    print("[CYBERGUARD] NEW INCIDENT ALERT")
    print(banner)
    print(f"Title            : {alert.alert_title}")
    print(f"Affected System  : {alert.affected_system}")
    if original_incident:
        print(f"Category         : {original_incident.category}")
        print(f"Severity         : {original_incident.severity}")
        print(f"Known Root Cause : {original_incident.root_cause}")
    print(f"Raw Logs         : {alert.raw_logs[:120]}..." if len(alert.raw_logs or "") > 120 else f"Raw Logs         : {alert.raw_logs}")

    print("\n[STEP 1] ContextBuilderService: Retrieving historical evidence from 1,000 dataset...")
    t0 = time.time()
    matches = context_builder_service.retrieve(
        alert=alert,
        top_k=5,
        exclude_id=incident_id_to_exclude
    )
    t_retrieval = (time.time() - t0) * 1000

    print(f"-> Found {len(matches)} matching historical incidents in {t_retrieval:.1f}ms:")
    for i, m in enumerate(matches[:3], start=1):
        print(f"   [{i}] {m.incident_id} | Type: {m.incident_type} | Similarity: {m.similarity_score:.2f}")

    print("\n[STEP 2] ContextBuilderService: Calculating Bayesian confidence & synthesizing context...")
    context = context_builder_service.build_context(
        alert=alert,
        top_k=5,
        exclude_id=incident_id_to_exclude
    )
    if context.action_evaluations:
        print(f"-> Evaluated {len(context.action_evaluations)} candidate actions:")
        for ae in context.action_evaluations[:3]:
            print(f"   * {ae.action[:40]:<40} -> Bayesian Confidence: {ae.final_confidence:.1%} ({ae.successes}/{ae.trials} successes)")
    else:
        print("-> No prior action statistics available (cold start).")

    groq_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    print(f"\n[STEP 3] LLMService: Calling Groq LLM ({groq_model}) for Incident Response...")
    t0 = time.time()
    try:
        response = llm_service.investigate_with_context(context)
        t_llm = time.time() - t0
        print(f"-> LLM inference completed in {t_llm:.2f}s")
    except Exception as e:
        print(f"[!] Groq API Error: {e}")
        return

    print("\n" + "=" * 60)
    print("[CYBERGUARD INCIDENT RESPONSE - STRUCTURED OUTPUT]")
    print("=" * 60)
    print(json.dumps(response.model_dump(), indent=2))

    # Visible terminal alert summary
    print("\n" + "=" * 60)
    print("[!!! CYBERGUARD INCIDENT RESPONSE ALERT !!!]")
    print("=" * 60)
    print(f"Investigation ID      : {response.investigation_id}")
    print(f"Summary               : {response.summary}")
    primary_action = response.recommended_actions[0].action if response.recommended_actions else "Triage"
    print(f"Recommended Action    : {primary_action}")
    print(f"Historical Confidence : {response.confidence_score:.1%}")
    print(f"Playbook              : {response.recommended_playbook_id}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Incident Response Runner")
    parser.add_argument("--random", action="store_true", help="Pick a random incident from dataset")
    parser.add_argument("--incident-id", type=str, help="Specific incident ID from dataset")
    parser.add_argument("--file", type=str, help="Path to JSON file with custom alert")
    args = parser.parse_args()

    if args.random:
        inc = context_builder_service.get_random_incident()
        alert = context_builder_service.convert_to_alert(inc)
        run_pipeline(alert, incident_id_to_exclude=inc.incident_id, original_incident=inc)
    elif args.incident_id:
        inc = context_builder_service.get_incident_by_id(args.incident_id)
        if not inc:
            print(f"[!] Incident ID {args.incident_id} not found in dataset.")
            sys.exit(1)
        alert = context_builder_service.convert_to_alert(inc)
        run_pipeline(alert, incident_id_to_exclude=inc.incident_id, original_incident=inc)
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] File not found: {file_path}")
            sys.exit(1)
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        alert = IncidentAlert.model_validate(data)
        run_pipeline(alert)
    else:
        # Interactive mode
        print("\n" + "=" * 60)
        print("          CYBERGUARD INCIDENT RESPONSE SYSTEM")
        print("=" * 60)
        stats = context_builder_service.get_stats()
        print(f"Total Incidents Loaded : {stats['total_incidents']}")
        print(f"Traditional Cyber      : {stats['category_distribution'].get('Traditional Cyber', 0)}")
        print(f"AI Security            : {stats['category_distribution'].get('AI Security', 0)}")
        print("-" * 60)
        print("Select an option:")
        print("  1. Run response on a random incident")
        print("  2. Select an AI Security incident (Prompt Injection / Adversarial)")
        print("  3. Select a Traditional Cyber incident (Ransomware / Brute Force)")
        print("  4. Enter a custom incident ID")
        print("  5. Exit")
        print("-" * 60)

        choice = input("Enter choice [1-5]: ").strip()

        if choice == "1":
            inc = context_builder_service.get_random_incident()
            alert = context_builder_service.convert_to_alert(inc)
            run_pipeline(alert, incident_id_to_exclude=inc.incident_id, original_incident=inc)
        elif choice == "2":
            incidents = [i for i in context_builder_service.load_incidents() if i.category == "AI Security"]
            import random
            inc = random.choice(incidents)
            alert = context_builder_service.convert_to_alert(inc)
            run_pipeline(alert, incident_id_to_exclude=inc.incident_id, original_incident=inc)
        elif choice == "3":
            incidents = [i for i in context_builder_service.load_incidents() if i.category == "Traditional Cyber"]
            import random
            inc = random.choice(incidents)
            alert = context_builder_service.convert_to_alert(inc)
            run_pipeline(alert, incident_id_to_exclude=inc.incident_id, original_incident=inc)
        elif choice == "4":
            inc_id = input("Enter Incident ID (e.g. INC-2026-0001): ").strip()
            inc = context_builder_service.get_incident_by_id(inc_id)
            if not inc:
                print(f"[!] Incident ID {inc_id} not found.")
                return
            alert = context_builder_service.convert_to_alert(inc)
            run_pipeline(alert, incident_id_to_exclude=inc.incident_id, original_incident=inc)
        else:
            print("Exiting.")


if __name__ == "__main__":
    main()
