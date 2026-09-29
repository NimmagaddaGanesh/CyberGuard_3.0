"""
Segment 4: Groq LLM Copilot Engine
Calls Groq LLM API to format investigation rationale and synthesize deep DFIR crisis dossiers.
"""
from typing import Dict, Any, List, Tuple
from app.config import settings
from app.models.schemas import InvestigationResult, Recommendation, HistoricalMatch

class CopilotEngine:
    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.model = settings.GROQ_MODEL

    async def generate_investigation(
        self,
        raw_input: Any,
        source: str,
        synthesized_context: Dict[str, Any]
    ) -> InvestigationResult:
        """
        Synthesizes final InvestigationResult payload for Segment 6 Frontend.
        """
        rec_dict = synthesized_context["recommendation"]
        hist_matches = [
            HistoricalMatch(**m) for m in synthesized_context.get("historical_matches", [])
        ]
        
        recommendation_obj = Recommendation(**rec_dict)
        preview = str(raw_input)[:200] if isinstance(raw_input, str) else str(raw_input)

        # If Groq API key is present, optionally refine rationale using Groq LLM
        if self.api_key:
            try:
                import groq
                client = groq.AsyncGroq(api_key=self.api_key)
                prompt = (
                    f"You are CyberGuard Security Copilot. Summarize rationale for alert: {preview}\n"
                    f"Recommended Action: {recommendation_obj.resolution}\n"
                    f"Historical success rate: {recommendation_obj.success_rate * 100}%"
                )
                chat_completion = await client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=self.model,
                    max_tokens=150
                )
                llm_rationale = chat_completion.choices[0].message.content
                if llm_rationale:
                    recommendation_obj.rationale = llm_rationale.strip()
            except Exception as e:
                print(f"[Groq Copilot Warning] LLM call skipped, using memory template rationale: {e}")

        return InvestigationResult(
            is_cold_start=synthesized_context.get("is_cold_start", False),
            historical_matches=hist_matches,
            recommendation=recommendation_obj,
            source=source,
            user_input_preview=preview
        )

    async def generate_deep_investigation_dossier(
        self,
        incident_id: str,
        resolution_id: str,
        primary_action: str,
        alternate_action: str
    ) -> Tuple[str, List[str]]:
        """
        Invokes Groq LLM when automated playbooks hit the escalation ceiling (Level 2).
        Returns (memo, emergency_actions).
        """
        default_memo = (
            f"CRITICAL SEV-0 CRISIS: Automated Tier-1 ({primary_action[:60]}...) and Tier-2 "
            f"({alternate_action[:60]}...) playbooks failed to neutralize incident {incident_id}. "
            "Adversary exhibits active defense evasion. Automated script execution has been halted. "
            "Incident transitioned to Tier-3 DFIR Incident Commander War Room."
        )
        default_actions = [
            "Sever public ingress & cross-VPC network routes for affected host to enforce immediate air-gap.",
            "Acquire live volatile RAM image (LiME/WinPmem) and disk snapshot before reboot.",
            "Invalidate all domain Kerberos/OAuth tokens and enforce out-of-band communication bridge.",
            "Convene SEV-0 War Room with CISO, Lead Forensics Investigator, and Infrastructure Architect."
        ]

        if not self.api_key:
            return default_memo, default_actions

        try:
            import groq
            client = groq.AsyncGroq(api_key=self.api_key)
            prompt = (
                f"You are the CyberGuard Principal DFIR Incident Commander.\n"
                f"An active security incident has EXHAUSTED all automated mitigation playbooks without resolution.\n"
                f"Incident ID: {incident_id} | Resolution ID: {resolution_id}\n"
                f"Failed Playbook 1 (Tier-1): {primary_action}\n"
                f"Failed Playbook 2 (Tier-2 Alternate): {alternate_action}\n\n"
                f"Write a concise, authoritative SEV-0 Executive Diagnosis (under 90 words) explaining why rule-based "
                f"playbooks failed (e.g. active APT evasion, living-off-the-land techniques, or zero-day persistence) "
                f"and directing human responders to immediate manual intervention."
            )
            chat_completion = await client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=self.model,
                max_tokens=200,
                temperature=0.2
            )
            llm_text = chat_completion.choices[0].message.content
            if llm_text:
                return llm_text.strip(), default_actions
        except Exception as e:
            print(f"[Groq Deep Investigation Warning] Groq API call error: {e}")

        return default_memo, default_actions

copilot_service = CopilotEngine()
