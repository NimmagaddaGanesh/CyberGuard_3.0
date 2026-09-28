"""CyberGuard Terminal Incident Response Runner.

Demonstrates the active incident response pipeline:
    1000 Incident Dataset
            ↓
    Select / receive an alert
            ↓
    Normalize incident
            ↓
    Find relevant historical evidence
            ↓
    Build context
            ↓
    Bayesian confidence
            ↓
    Groq LLM
            ↓
    Active Incident Response
            ↓
    Terminal Alert / Response

Usage:
    python backend/scripts/run_incident_response.py                 # Interactive mode
    python backend/scripts/run_incident_response.py --random        # Random incident
    python backend/scripts/run_incident_response.py --incident-id <ID> # Specific incident
    python backend/scripts/run_incident_response.py --file <PATH>   # Custom alert JSON
"""
import argparse
import json
import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Configure stdout for utf-8 on Windows
if sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from backend.config import settings
from backend.models.incident import IncidentAlert, IncidentRecord
from backend.services.context_synthesizer import context_synthesizer
from backend.services.dataset_service import dataset_service
from backend.services.groq_service import groq_service
from backend.services.notifier import terminal_notifier
from backend.services.retriever import local_retriever


def run_pipeline(alert: IncidentAlert, incident_id_to_exclude: str = None, original_incident: IncidentRecord = None):
    """Executes the complete CyberGuard incident response workflow."""
    banner = "=" * 60
    print(f"\n{banner}")
    print("[CYBERGUARD] NEW INCIDENT ALERT")
    print(banner)
    inc_display_id = alert.alert_id or (original_incident.incident_id if original_incident else "ALERT-EXTERNAL")
    category_disp = original_incident.category if original_incident else alert.extensions.get("category", "Cybersecurity")
    type_disp = original_incident.incident_type if original_incident else alert.alert_title
    severity_disp = original_incident.severity if original_incident else alert.extensions.get("severity", "High")
    system_disp = alert.affected_system or (original_incident.affected_system if original_incident else "Unknown")

    print(f"Incident ID      : {inc_display_id}")
    print(f"Category         : {category_disp}")
    print(f"Incident Type    : {type_disp}")
    print(f"Severity         : {severity_disp}")
    print(f"Affected System  : {system_disp}")
    print()

    # Step 1: Loading incident
    print("[1/5] Loading incident ................. OK")
    time.sleep(0.05)

    # Step 2: Searching historical evidence (excluding self ID if testing an existing incident)
    evidence_list = local_retriever.retrieve(
        alert=alert,
        top_k=5,
        exclude_id=incident_id_to_exclude
    )
    print(f"[2/5] Searching historical evidence ... OK (Found {len(evidence_list)} matches)")
    time.sleep(0.05)

    # Step 3: Building context
    synthesized = context_synthesizer.synthesize(alert=alert, evidence_list=evidence_list)
    print("[3/5] Building context ................ OK")
    time.sleep(0.05)

    # Step 4: Calculating Bayesian confidence
    print("[4/5] Calculating confidence .......... OK")
    time.sleep(0.05)

    # Display Historical Evidence Matches
    print(f"\n{banner}")
    print("HISTORICAL EVIDENCE")
    print("Memory Backend: LOCAL DATASET (TEMPORARY)")
    print(banner)

    if not evidence_list:
        print("No prior matching incidents found in memory.")
    else:
        for idx, ev in enumerate(evidence_list[:3], 1):
            print(f"Match #{idx}")
            print(f"Incident ID      : {ev.incident_id}")
            print(f"Type / Playbook  : {ev.incident_type} ({ev.recommended_playbook})")
            print(f"Similarity       : {ev.similarity_score:.4f}")
            print("Resolutions Tried:")
            for res in ev.resolutions_tried:
                outcome = "SUCCESS" if res.success else "FAILED"
                eff_str = f"{res.efficacy_score:.2f}" if res.efficacy_score is not None else "N/A"
                print(f"  • [{outcome}] Efficacy: {eff_str}")
                print(f"    Action : {res.action}")
                if res.analyst_notes:
                    print(f"    Notes  : {res.analyst_notes}")
            print()

    # Display Bayesian Historical Confidence
    print(banner)
    print("BAYESIAN HISTORICAL CONFIDENCE")
    print(banner)

    if synthesized.action_evaluations:
        primary = synthesized.action_evaluations[0]
        v_sim = primary.vector_similarity
        succ = primary.successes
        tri = primary.trials
        emp_comp = round((succ + 1) / (tri + 2), 4)
        print(f"Candidate Action:\n{primary.action}\n")
        print(f"Vector Similarity   : {v_sim:.4f}")
        print(f"Successes / Trials  : {succ} / {tri} (Empirical Rate: {primary.empirical_rate*100:.1f}%)")
        print(f"Empirical Component : ({succ} + 1) / ({tri} + 2) = {emp_comp:.4f}")
        print(f"Formula             : 0.40 * {v_sim:.4f} + 0.60 * {emp_comp:.4f}")
        print(f"Final Confidence    : {primary.final_confidence:.4f}")
        if primary.average_efficacy > 0:
            print(f"Average Efficacy    : {primary.average_efficacy:.2f}")
    else:
        print("No prior candidate actions evaluated (Cold Start baseline).")

    # Step 5: Querying Groq LLM
    print(f"\n[5/5] Querying Groq LLM ({settings.GROQ_MODEL}) ...")
    try:
        response = groq_service.investigate_with_context(synthesized)
        print("[5/5] Querying Groq LLM ............... OK")
    except Exception as e:
        print(f"[ERROR] Groq LLM inference failed: {e}", file=sys.stderr)
        return

    # Display Groq AI Response
    print(f"\n{banner}")
    print("CYBERGUARD AI RESPONSE (STRUCTURED JSON)")
    print(banner)
    print(json.dumps(response.model_dump(), indent=2))

    # Active Incident Response Alert
    print(f"\n{banner}")
    print("[CYBERGUARD ALERT]")
    print("ACTIVE INCIDENT RESPONSE GENERATED")
    print(banner)

    primary_rec = response.recommended_actions[0].action if response.recommended_actions else "Triage system"
    terminal_notifier.notify({
        "investigation_id": response.investigation_id,
        "summary": response.summary,
        "primary_action": primary_rec,
        "confidence_score": response.confidence_score,
        "recommended_playbook_id": response.recommended_playbook_id
    })


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Terminal Incident Response Runner")
    parser.add_argument("--random", action="store_true", help="Investigate a random incident from the 1000 dataset")
    parser.add_argument("--incident-id", type=str, help="Specific incident ID to investigate (e.g., INC-2026-0607)")
    parser.add_argument("--file", type=str, help="Path to external alert JSON file")
    args = parser.parse_args()

    # Pre-flight check: Dataset
    try:
        incidents = dataset_service.load_incidents()
    except Exception as e:
        print(f"[ERROR] Failed to load dataset: {e}", file=sys.stderr)
        sys.exit(1)

    # Pre-flight check: Groq API Key
    if not settings.GROQ_API_KEY:
        print("[ERROR] GROQ_API_KEY is missing from .env. Please configure it to run incident response.", file=sys.stderr)
        sys.exit(1)

    banner = "=" * 60

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[ERROR] Alert file not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        with open(file_path, "r", encoding="utf-8") as f:
            raw_alert = json.load(f)
        alert = IncidentAlert.model_validate(raw_alert)
        run_pipeline(alert)
        return

    if args.incident_id:
        target_id = args.incident_id.strip()
        incident = dataset_service.get_incident_by_id(target_id)
        if not incident:
            print(f"[ERROR] Incident '{target_id}' not found in dataset.", file=sys.stderr)
            sys.exit(1)
        alert = IncidentAlert(
            alert_id=incident.incident_id,
            alert_title=incident.incident_type,
            raw_logs="\n".join(incident.symptoms),
            affected_system=incident.affected_system,
            extensions=incident.extensions
        )
        run_pipeline(alert, incident_id_to_exclude=incident.incident_id, original_incident=incident)
        return

    if args.random:
        incident = dataset_service.get_random_incident()
        alert = IncidentAlert(
            alert_id=incident.incident_id,
            alert_title=incident.incident_type,
            raw_logs="\n".join(incident.symptoms),
            affected_system=incident.affected_system,
            extensions=incident.extensions
        )
        run_pipeline(alert, incident_id_to_exclude=incident.incident_id, original_incident=incident)
        return

    # Interactive Mode
    print(banner)
    print("CYBERGUARD — AI INCIDENT RESPONSE ENGINE")
    print(banner)
    print("Memory Backend: LOCAL DATASET (TEMPORARY)")
    print(f"Dataset: {dataset_service.dataset_path.name}")
    print(f"Incidents loaded: {len(incidents)}")
    print("System: READY\n")

    user_input = input("Enter an incident ID to investigate (or 'R' for random, 'Q' to quit):\n> ").strip()

    if user_input.upper() == "Q":
        print("Exiting.")
        return

    if user_input.upper() == "R":
        incident = dataset_service.get_random_incident()
    else:
        incident = dataset_service.get_incident_by_id(user_input)
        if not incident:
            print(f"[ERROR] Incident '{user_input}' not found in dataset.")
            return

    alert = IncidentAlert(
        alert_id=incident.incident_id,
        alert_title=incident.incident_type,
        raw_logs="\n".join(incident.symptoms),
        affected_system=incident.affected_system,
        extensions=incident.extensions
    )
    run_pipeline(alert, incident_id_to_exclude=incident.incident_id, original_incident=incident)


if __name__ == "__main__":
    main()
