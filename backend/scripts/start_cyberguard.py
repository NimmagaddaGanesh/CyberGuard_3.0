"""CyberGuard Primary Terminal Launcher.

Unified interactive interface for the CyberGuard AI Incident Response Engine.

Usage:
    python backend/scripts/start_cyberguard.py
"""
import sys
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
from backend.models.incident import IncidentAlert
from backend.scripts.run_incident_response import run_pipeline
from backend.services.dataset_service import dataset_service


def print_banner(stats: dict):
    """Displays the CyberGuard system status startup banner."""
    print("=" * 60)
    print("                 CYBERGUARD")
    print("        AI INCIDENT RESPONSE ENGINE")
    print("=" * 60)
    print()
    print(f"Environment        : READY")
    print(f"Dataset            : {stats['dataset_file']}")
    print(f"Incidents Loaded   : {stats['total_incidents']}")
    print(f"Groq Model         : {settings.GROQ_MODEL}")
    print(f"Memory Backend     : LOCAL DATASET (TEMPORARY)")
    print(f"Hindsight          : NOT CONNECTED")
    print()
    print(f"System Status      : READY")
    print()
    print("=" * 60)
    print()


def show_help():
    """Prints command help information."""
    print("\nSupported commands:")
    print("  1. incident <INCIDENT_ID>  - Investigate an incident (e.g., incident INC-2026-0607)")
    print("  2. random                  - Investigate a random incident from the 1000 dataset")
    print("  3. stats                   - Display dataset metrics and category breakdown")
    print("  4. help                    - Show this help message")
    print("  5. exit                    - Exit the CyberGuard engine\n")


def show_stats(stats: dict):
    """Displays dataset statistics."""
    print("\n" + "=" * 60)
    print("CYBERGUARD DATASET METRICS")
    print("=" * 60)
    print(f"Total Incidents       : {stats['total_incidents']}")
    print(f"Traditional Cyber     : {stats['traditional_cyber']} (70.0%)")
    print(f"AI Security           : {stats['ai_security']} (30.0%)")
    print("\nSeverity Distribution:")
    for sev, count in stats['severities'].items():
        print(f"  • {sev:<10}: {count}")
    print(f"\nDistinct Incident Types ({stats['unique_incident_types_count']}):")
    for itype, count in sorted(stats['incident_types'].items(), key=lambda x: x[1], reverse=True):
        print(f"  • {itype:<32}: {count}")
    print("=" * 60 + "\n")


def handle_incident_investigation(inc_id: str):
    """Processes an investigation request for a specific incident ID."""
    incident = dataset_service.get_incident_by_id(inc_id)
    if not incident:
        print(f"\n[ERROR] Incident '{inc_id}' not found in the 1000-incident dataset.")
        print("Tip: Use 'stats' to view distributions or 'random' to pick one automatically.\n")
        return

    alert = IncidentAlert(
        alert_id=incident.incident_id,
        alert_title=incident.incident_type,
        raw_logs="\n".join(incident.symptoms),
        affected_system=incident.affected_system,
        extensions=incident.extensions
    )
    run_pipeline(alert, incident_id_to_exclude=incident.incident_id, original_incident=incident)


def handle_random_investigation():
    """Selects a random incident and runs the investigation pipeline."""
    incident = dataset_service.get_random_incident()
    alert = IncidentAlert(
        alert_id=incident.incident_id,
        alert_title=incident.incident_type,
        raw_logs="\n".join(incident.symptoms),
        affected_system=incident.affected_system,
        extensions=incident.extensions
    )
    run_pipeline(alert, incident_id_to_exclude=incident.incident_id, original_incident=incident)


def main():
    # 1. Environment & configuration pre-flight check
    if not settings.GROQ_API_KEY:
        print("\n[CRITICAL ERROR] GROQ_API_KEY is not configured.", file=sys.stderr)
        print("Please ensure your .env file contains: GROQ_API_KEY=your_key", file=sys.stderr)
        sys.exit(1)

    # 2. Dataset pre-flight check
    try:
        incidents = dataset_service.load_incidents()
        stats = dataset_service.get_statistics()
    except Exception as e:
        print(f"\n[CRITICAL ERROR] Failed to load primary dataset: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Display startup banner
    print_banner(stats)

    # 4. Interactive command loop
    print("Type 'help' to see available commands, or 'exit' to quit.\n")

    while True:
        try:
            raw_command = input("Enter command:\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting CyberGuard. Stay secure.")
            break

        if not raw_command:
            continue

        parts = raw_command.split(maxsplit=1)
        action = parts[0].lower()

        if action in ("exit", "quit", "q"):
            print("\nExiting CyberGuard. Stay secure.")
            break
        elif action == "help":
            show_help()
        elif action == "stats":
            show_stats(stats)
        elif action == "random":
            handle_random_investigation()
        elif action == "incident":
            if len(parts) < 2 or not parts[1].strip():
                print("\n[ERROR] Missing incident ID. Example: incident INC-2026-0607\n")
            else:
                handle_incident_investigation(parts[1].strip())
        elif raw_command.upper().startswith("INC-"):
            # Convenience shortcut: user typed just the ID
            handle_incident_investigation(raw_command.strip())
        else:
            print(f"\n[ERROR] Unrecognized command '{raw_command}'. Type 'help' for instructions.\n")


if __name__ == "__main__":
    main()
