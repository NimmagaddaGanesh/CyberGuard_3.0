"""Prompt construction service for CyberGuard incident investigation."""
import json
from typing import Any, Dict, List, Optional
from backend.services.context_synthesizer import SynthesizedContext


SYSTEM_PROMPT = """You are CyberGuard, an elite Senior Tier-3 SOC Incident Response Specialist.
Your mission is to perform deep technical triage, identify root causes, and provide high-confidence mitigation recommendations based on incoming security alerts and institutional memory.

CORE OPERATIONAL RULES:
1. ANALYSIS & GROUNDING:
   - Analyze the provided alert, raw logs, and affected system.
   - If historical incident memories and Bayesian confidence scores are provided, treat them as authoritative evidence.
   - Prioritize mitigations with high empirical historical efficacy.
   - Actively generate warnings against actions that repeatedly failed or had low efficacy in past incidents.
   - Mark proven successful actions with status "RECOMMENDED".
   - Mark actions that failed in the past with status "DISCOURAGED_WARNING" and include an explicit "warning" string explaining why they fail.
   - Accurately cite similar historical incident IDs and recommended playbooks.
2. STRICT EVIDENCE BOUNDARIES:
   - NEVER invent or hallucinate historical incidents, incident IDs, success rates, or previous analyst notes.
   - When NO historical evidence is provided (historical context is empty or absent), explicitly state that no historical institutional memory was found, set confidence_score to 0.0, and set similar_historical_incidents to [].
3. OUTPUT FORMAT ENFORCEMENT:
   - You MUST respond with ONLY a valid, parseable JSON object matching the exact schema below.
   - Do NOT include any markdown code fencing (no ```json or ```) or surrounding text.

JSON RESPONSE SCHEMA:
{
  "investigation_id": "INV-2026-XXXX",
  "summary": "<Concise 1-2 sentence executive briefing of the attack and detection>",
  "root_cause_analysis": "<Detailed technical root-cause assessment>",
  "confidence_score": <float between 0.0 and 1.0 matching the primary Bayesian historical confidence>,
  "recommended_actions": [
    {
      "priority": 1,
      "action": "<Specific remediation action>",
      "historical_efficacy": "<e.g., 91.2% Bayesian Confidence (16/18 successes)>",
      "status": "RECOMMENDED"
    },
    {
      "priority": 2,
      "action": "<Failed or discouraged action from history>",
      "historical_efficacy": "<e.g., 28.0% Bayesian Confidence (8/10 failures)>",
      "status": "DISCOURAGED_WARNING",
      "warning": "<Why this action fails based on historical memory>"
    }
  ],
  "recommended_playbook_id": "<e.g., PB-SQL-INJECTION, PB-003, or null>",
  "similar_historical_incidents": ["<INC-YYYY-XXXX>"]
}
"""


class PromptBuilder:
    """Builds structured system and user prompts for Groq LLM inference."""

    @staticmethod
    def get_system_prompt() -> str:
        """Returns the CyberGuard Senior SOC Specialist system prompt."""
        return SYSTEM_PROMPT.strip()

    @staticmethod
    def build_synthesized_prompt(ctx: SynthesizedContext) -> str:
        """Constructs prompt using a structured SynthesizedContext object."""
        lines = [
            "=== CURRENT INCIDENT ALERT ===",
            f"Alert Title: {ctx.current_alert.get('alert_title')}",
            f"Affected System: {ctx.current_alert.get('affected_system')}",
            f"Timestamp: {ctx.current_alert.get('timestamp')}",
        ]

        raw_logs = ctx.current_alert.get("raw_logs")
        if raw_logs and raw_logs.strip():
            lines.append(f"Raw Logs / Event Data:\n{raw_logs.strip()}")
        else:
            lines.append("Raw Logs / Event Data: None provided")

        lines.append("\n=== RETRIEVED HISTORICAL EVIDENCE (INSTITUTIONAL MEMORY) ===")

        if not ctx.historical_matches:
            lines.append("NO HISTORICAL EVIDENCE AVAILABLE.")
            lines.append("Note: No prior incidents or resolution memories match this query.")
            lines.append("Set confidence_score to 0.0, similar_historical_incidents to [], and mark historical_efficacy as 'No historical data'.")
        else:
            lines.append(f"Found {len(ctx.historical_matches)} relevant historical incident(s):")
            for m in ctx.historical_matches:
                lines.append(f"- Incident {m['incident_id']} [{m['incident_type']}] (Similarity: {m['similarity_score']}):")
                lines.append(f"  Root Cause: {m['root_cause']}")
                lines.append(f"  Recommended Playbook: {m['recommended_playbook']}")
                lines.append("  Resolutions Tried:")
                for r in m.get("resolutions_tried", []):
                    outcome = "SUCCESS" if r.get("success") else "FAILED"
                    eff = f"{r.get('efficacy_score', 'N/A')}"
                    lines.append(f"    • [{outcome}] Efficacy: {eff} | Action: {r.get('action')}")
                    if r.get("analyst_notes"):
                        lines.append(f"      Notes: {r.get('analyst_notes')}")

            if ctx.action_evaluations:
                lines.append("\nCandidate Actions Evaluated with Bayesian Historical Confidence:")
                for act in ctx.action_evaluations:
                    lines.append(
                        f"- Action: '{act.action}'\n"
                        f"  Bayesian Confidence: {act.final_confidence}\n"
                        f"  Historical Efficacy String: '{act.final_confidence*100:.1f}% Bayesian Confidence ({act.successes}/{act.trials} successes)'\n"
                        f"  Average Efficacy: {act.average_efficacy:.2f} across {act.trials} historical trial(s)"
                    )

            if ctx.known_failed_actions:
                lines.append("\nACTIONS THAT FAILED IN SIMILAR HISTORICAL INCIDENTS:")
                for failed in ctx.known_failed_actions[:3]:
                    eff_str = f" (Efficacy: {failed.efficacy_score})" if failed.efficacy_score is not None else ""
                    notes_str = f" - Notes: {failed.analyst_notes}" if failed.analyst_notes else ""
                    lines.append(f"- WARNING: '{failed.action}' failed in {failed.incident_id}{eff_str}{notes_str}")

            if ctx.lessons_learned:
                lines.append("\nHistorical Lessons Learned:")
                for les in ctx.lessons_learned[:5]:
                    lines.append(f"- {les}")

        lines.append("\nGenerate the investigation response matching the exact JSON schema.")
        return "\n".join(lines)

    @staticmethod
    def build_user_prompt(
        alert_title: str,
        raw_logs: Optional[str] = "",
        affected_system: Optional[str] = None,
        historical_context: Optional[Any] = None
    ) -> str:
        """Constructs the user investigation prompt."""
        if isinstance(historical_context, SynthesizedContext):
            return PromptBuilder.build_synthesized_prompt(historical_context)

        lines = [
            "=== INCOMING INCIDENT ALERT ===",
            f"Alert Title: {alert_title}",
        ]

        if affected_system:
            lines.append(f"Affected System: {affected_system}")

        if raw_logs and raw_logs.strip():
            lines.append(f"Raw Logs / Event Data:\n{raw_logs.strip()}")
        else:
            lines.append("Raw Logs / Event Data: None provided")

        lines.append("\n=== INSTITUTIONAL MEMORY (HISTORICAL EVIDENCE) ===")

        if not historical_context:
            lines.append("NO HISTORICAL EVIDENCE AVAILABLE.")
            lines.append("Set confidence_score to 0.0, similar_historical_incidents to [], and mark historical_efficacy as 'No historical data'.")
        else:
            lines.append("The following historical incident memories and past resolutions were retrieved:")
            if isinstance(historical_context, (dict, list)):
                lines.append(json.dumps(historical_context, indent=2))
            else:
                lines.append(str(historical_context))
            lines.append("\nGround your analysis in this historical experience. Highlight what worked and warn against what failed.")

        lines.append("\nGenerate the investigation response matching the exact JSON schema.")
        return "\n".join(lines)
