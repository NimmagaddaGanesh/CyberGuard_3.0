"""Active alert notification service.

Provides a clean notification abstraction allowing the current terminal notification
to be augmented or replaced later with Webhook, Slack, PagerDuty, or Email channels.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseNotifier(ABC):
    """Abstract base class for incident response alerts."""

    @abstractmethod
    def notify(self, alert_data: Dict[str, Any]) -> None:
        """Deliver the incident notification."""
        pass


class TerminalNotifier(BaseNotifier):
    """Outputs visible incident alerts directly to the terminal."""

    def notify(self, alert_data: Dict[str, Any]) -> None:
        inv_id = alert_data.get("investigation_id", "INV-2026-XXXX")
        summary = alert_data.get("summary", "Incident response generated.")
        primary_action = alert_data.get("primary_action", "Investigate")
        confidence = alert_data.get("confidence_score", "N/A")
        playbook = alert_data.get("recommended_playbook_id", "N/A")

        banner = "=" * 60
        print(f"\n{banner}")
        print("[!!! CYBERGUARD INCIDENT RESPONSE ALERT !!!]")
        print(f"{banner}")
        print(f"Investigation ID      : {inv_id}")
        print(f"Summary               : {summary}")
        print(f"Recommended Action    : {primary_action}")
        print(f"Historical Confidence : {confidence}")
        print(f"Playbook              : {playbook}")
        print(f"{banner}\n")


# Global default notifier
terminal_notifier = TerminalNotifier()
