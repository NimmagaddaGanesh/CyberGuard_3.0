"""Prompt construction service for CyberGuard incident investigation."""
import json
from typing import Any, Dict, List, Optional
from cyberguard.services.context_synthesizer import SynthesizedContext


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
    def build_user_prompt(
        alert_title: str,
        raw_logs: Optional[str] = "",
        affected_system: Optional[str] = None,
        historical_context: Optional[Any] = None
    ) -> str:
        """Constructs the user prompt strictly separating the current alert from historical memory."""
        sections = [
            "### INCOMING SECURITY ALERT TO INVESTIGATE ###",
            f"Alert Title     : {alert_title}",
            f"Affected System : {affected_system or 'Unknown / Unspecified'}",
            f"Raw Telemetry / Logs:\n{raw_logs or 'No raw log telemetry provided.'}",
            "",
            "### INSTITUTIONAL HISTORICAL MEMORY & EVIDENCE ###"
        ]

        if not historical_context:
            sections.append(
                "STATUS: No historical institutional memory or prior incidents were found matching this alert pattern.\n"
                "INSTRUCTION: Base your triage solely on standard security first principles. Set confidence_score to 0.0, recommended_playbook_id to null, and similar_historical_incidents to []."
            )
            return "\n".join(sections)

        # Handle SynthesizedContext or dictionary representation
        if isinstance(historical_context, SynthesizedContext):
            context_dict = historical_context.model_dump()
        elif isinstance(historical_context, dict):
            context_dict = historical_context
        else:
            context_dict = {}

        action_evals = context_dict.get("action_evaluations", [])
        proven_actions = context_dict.get("proven_effective_actions", [])
        failed_actions = context_dict.get("known_failed_actions", [])
        playbooks = context_dict.get("recommended_playbooks", [])
        lessons = context_dict.get("lessons_learned", [])
        matches = context_dict.get("historical_matches", [])

        if not matches:
            sections.append(
                "STATUS: Historical search executed, but zero matching prior incidents were identified.\n"
                "INSTRUCTION: Set confidence_score to 0.0 and similar_historical_incidents to []."
            )
            return "\n".join(sections)

        sections.append(f"Matching Historical Incidents Found: {len(matches)}")
        for i, match in enumerate(matches[:3], start=1):
            inc_id = match.get("incident_id")
            sim = match.get("similarity_score", 0.0)
            itype = match.get("incident_type", "Unknown")
            rc = match.get("root_cause", "Unknown")
            sections.append(
                f"  [{i}] ID: {inc_id} | Similarity: {sim:.2f} | Type: {itype} | Root Cause: {rc}"
            )

        if playbooks:
            sections.append(f"\nHistorical Recommended Playbooks: {', '.join(playbooks)}")

        if action_evals:
            sections.append("\nBayesian Historical Action Evaluations:")
            for ae in action_evals[:5]:
                action = ae.get("action")
                conf = ae.get("final_confidence", 0.0)
                succ = ae.get("successes", 0)
                trials = ae.get("trials", 0)
                avg_eff = ae.get("average_efficacy", 0.0)
                sections.append(
                    f"  * Action: \"{action}\"\n"
                    f"    - Bayesian Confidence: {conf:.1%} ({conf:.3f})\n"
                    f"    - Historical Record: {succ}/{trials} successful attempts\n"
                    f"    - Avg Historical Efficacy: {avg_eff:.1%}"
                )

        if failed_actions:
            sections.append("\nWARNING - Actions that FAILED in Prior Similar Incidents:")
            for fa in failed_actions[:3]:
                action = fa.get("action")
                notes = fa.get("analyst_notes") or "No analyst notes recorded."
                sections.append(f"  * FAILED ACTION: \"{action}\" (From {fa.get('incident_id')}): {notes}")

        if lessons:
            sections.append("\nLessons Learned from Previous Incidents:")
            for l in lessons[:3]:
                sections.append(f"  - {l}")

        sections.append(
            "\nINSTRUCTION: Synthesize the root cause, determine the primary recommended actions and discouraged warnings, and output the required JSON format."
        )

        return "\n".join(sections)
