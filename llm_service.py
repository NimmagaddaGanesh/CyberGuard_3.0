"""LLM Service for CyberGuard.

Service-oriented module responsible for:
1. Canonical Investigation models (InvestigationResponse, ActionItem, InvestigationRequest)
2. SOC prompt construction with strict evidence boundaries and JSON schema enforcement
3. Groq LLM integration (openai/gpt-oss-120b)
4. High-level end-to-end investigation pipeline (investigate_incident)

Usage:
    from llm_service import investigate_incident, IncidentAlert

    # Simple dict or IncidentAlert:
    result = investigate_incident({
        "alert_title": "Detected SQL Injection attempt on web-portal",
        "affected_system": "prod-db-cluster",
        "raw_logs": "UNION SELECT username, password_hash FROM users --"
    })
    print(result.model_dump())
"""
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from groq import Groq
from pydantic import BaseModel, Field

# Import context builder capabilities
from context_builder_service import (
    ContextBuilderService,
    IncidentAlert,
    IncidentRecord,
    ResolutionRecord,
    SynthesizedContext,
    context_builder_service,
)

logger = logging.getLogger(__name__)


# =====================================================================
# Canonical Output Data Models
# =====================================================================

class ActionItem(BaseModel):
    """Specific remediation or discouraged action with historical efficacy and status."""
    priority: int
    action: str
    historical_efficacy: str
    status: str  # e.g., "RECOMMENDED" | "DISCOURAGED_WARNING"
    warning: Optional[str] = None


class InvestigationResponse(BaseModel):
    """Structured incident investigation response matching CyberGuard canonical format."""
    investigation_id: str
    summary: str
    root_cause_analysis: str
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_actions: List[ActionItem] = Field(default_factory=list)
    recommended_playbook_id: Optional[str] = None
    similar_historical_incidents: List[str] = Field(default_factory=list)


class InvestigationRequest(BaseModel):
    """Request payload for initiating an incident investigation."""
    alert_title: str
    raw_logs: Optional[str] = ""
    affected_system: Optional[str] = None
    bypass_memory: bool = False


# =====================================================================
# SOC Specialist Prompt Engineering
# =====================================================================

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


def build_user_prompt(
    alert_title: str,
    raw_logs: Optional[str] = "",
    affected_system: Optional[str] = None,
    historical_context: Optional[Any] = None
) -> str:
    """Constructs the user prompt strictly separating current alert from historical memory."""
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

    if isinstance(historical_context, SynthesizedContext):
        context_dict = historical_context.model_dump()
    elif isinstance(historical_context, dict):
        context_dict = historical_context
    else:
        context_dict = {}

    action_evals = context_dict.get("action_evaluations", [])
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


# =====================================================================
# LLM Service Implementation
# =====================================================================

class LLMService:
    """Service handling interactions with the Groq API for incident analysis and triage."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, client: Optional[Groq] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = model or os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        self._client = client

    def get_client(self) -> Groq:
        """Lazily initialize and return the Groq client."""
        if self._client is None:
            if not self.api_key:
                raise ValueError("GROQ_API_KEY is not configured in the environment.")
            self._client = Groq(api_key=self.api_key)
        return self._client

    def investigate(
        self,
        alert_title: str,
        raw_logs: Optional[str] = "",
        affected_system: Optional[str] = None,
        historical_context: Optional[Any] = None,
        temperature: float = 0.1
    ) -> InvestigationResponse:
        """Invokes Groq LLM with structured JSON output to analyze an alert."""
        client = self.get_client()
        user_prompt = build_user_prompt(
            alert_title=alert_title,
            raw_logs=raw_logs,
            affected_system=affected_system,
            historical_context=historical_context
        )

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT.strip()},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=temperature
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("Groq returned an empty response.")

        parsed_data = json.loads(content)
        return InvestigationResponse.model_validate(parsed_data)

    def investigate_with_context(
        self,
        context: SynthesizedContext,
        temperature: float = 0.1
    ) -> InvestigationResponse:
        """Convenience method accepting a SynthesizedContext directly."""
        alert_data = context.current_alert
        return self.investigate(
            alert_title=alert_data.get("alert_title", "Unknown Alert"),
            raw_logs=alert_data.get("raw_logs", ""),
            affected_system=alert_data.get("affected_system"),
            historical_context=context,
            temperature=temperature
        )


# Global singleton instance
llm_service = LLMService()


# =====================================================================
# High-Level Investigation Pipeline Entrypoint
# =====================================================================

def investigate_incident(
    alert: Union[IncidentAlert, Dict[str, Any]],
    bypass_memory: bool = False,
    exclude_id: Optional[str] = None,
    top_k: int = 5,
    context_service: Optional[ContextBuilderService] = None,
    inference_service: Optional[LLMService] = None
) -> InvestigationResponse:
    """High-level one-line function to investigate any incident alert.
    
    Coordinates context building (retrieval + Bayesian confidence) and LLM inference.
    
    Args:
        alert: IncidentAlert instance or dictionary representing the incoming alert.
        bypass_memory: If True, skips historical memory lookup.
        exclude_id: Optional incident ID to exclude from historical retrieval.
        top_k: Number of historical matches to retrieve.
        context_service: Optional custom ContextBuilderService.
        inference_service: Optional custom LLMService.
        
    Returns:
        InvestigationResponse matching canonical schema.
    """
    c_service = context_service or context_builder_service
    l_service = inference_service or llm_service

    # 1. Build Synthesized Context (Retrieval + Bayesian Confidence)
    context = c_service.build_context(
        alert=alert,
        top_k=top_k,
        exclude_id=exclude_id,
        bypass_memory=bypass_memory
    )

    # 2. Invoke Groq LLM for Structured SOC Investigation
    return l_service.investigate_with_context(context=context)
