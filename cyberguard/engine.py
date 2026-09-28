"""CyberGuard Investigation Engine.

High-level interface for incident investigation, reasoning, and memory-backed triage.
Can be directly imported into any backend (FastAPI, Flask, Django, etc.):

    from cyberguard import investigate_incident, IncidentAlert

    # Simple dictionary or IncidentAlert input:
    result = investigate_incident({
        "alert_title": "Detected SQL Injection attempt on web-portal",
        "affected_system": "prod-db-cluster",
        "raw_logs": "UNION SELECT username, password_hash FROM users --"
    })
    print(result.model_dump())
"""
from typing import Any, Dict, Optional, Union

from cyberguard.models.incident import IncidentAlert, IncidentRecord
from cyberguard.models.investigation import InvestigationResponse
from cyberguard.services.context_synthesizer import ContextSynthesizer, SynthesizedContext, context_synthesizer
from cyberguard.services.dataset_service import DatasetService, dataset_service
from cyberguard.services.groq_service import GroqService, groq_service
from cyberguard.services.notifier import TerminalNotifier, terminal_notifier
from cyberguard.services.retriever import HistoricalEvidence, LocalDatasetRetriever, local_retriever


class CyberGuardEngine:
    """Core investigation engine coordinating retrieval, Bayesian analysis, and LLM inference."""

    def __init__(
        self,
        retriever: Optional[LocalDatasetRetriever] = None,
        synthesizer: Optional[ContextSynthesizer] = None,
        llm_service: Optional[GroqService] = None,
        notifier: Optional[TerminalNotifier] = None
    ):
        self.retriever = retriever or local_retriever
        self.synthesizer = synthesizer or context_synthesizer
        self.llm = llm_service or groq_service
        self.notifier = notifier or terminal_notifier

    def investigate(
        self,
        alert: Union[IncidentAlert, Dict[str, Any]],
        bypass_memory: bool = False,
        exclude_id: Optional[str] = None,
        top_k: int = 5,
        notify: bool = False
    ) -> InvestigationResponse:
        """Executes full incident investigation pipeline.
        
        Args:
            alert: IncidentAlert instance or raw dictionary.
            bypass_memory: If True, bypasses historical memory lookup.
            exclude_id: Optional incident ID to exclude from historical search (useful when testing dataset items).
            top_k: Number of historical matches to retrieve.
            notify: If True, fires the configured alert notifier.
            
        Returns:
            InvestigationResponse matching canonical schema.
        """
        if isinstance(alert, dict):
            alert_obj = IncidentAlert.model_validate(alert)
        else:
            alert_obj = alert

        # 1. Retrieve historical incident memories
        if bypass_memory:
            matches: list[HistoricalEvidence] = []
        else:
            matches = self.retriever.retrieve(
                alert=alert_obj,
                top_k=top_k,
                exclude_id=exclude_id
            )

        # 2. Synthesize context & calculate Bayesian confidence
        synthesized_context: SynthesizedContext = self.synthesizer.synthesize(
            alert=alert_obj,
            historical_matches=matches
        )

        # 3. LLM Reasoning via Groq
        response: InvestigationResponse = self.llm.investigate_with_context(
            context=synthesized_context
        )

        # 4. Optional notification dispatch
        if notify and self.notifier:
            primary_action = (
                response.recommended_actions[0].action
                if response.recommended_actions else "Triage"
            )
            self.notifier.notify({
                "investigation_id": response.investigation_id,
                "summary": response.summary,
                "primary_action": primary_action,
                "confidence_score": f"{response.confidence_score:.1%}",
                "recommended_playbook_id": response.recommended_playbook_id
            })

        return response


# Default singleton instance
cyberguard_engine = CyberGuardEngine()


def investigate_incident(
    alert: Union[IncidentAlert, Dict[str, Any]],
    bypass_memory: bool = False,
    exclude_id: Optional[str] = None,
    top_k: int = 5,
    notify: bool = False
) -> InvestigationResponse:
    """One-line convenience entrypoint for incident investigation."""
    return cyberguard_engine.investigate(
        alert=alert,
        bypass_memory=bypass_memory,
        exclude_id=exclude_id,
        top_k=top_k,
        notify=notify
    )
