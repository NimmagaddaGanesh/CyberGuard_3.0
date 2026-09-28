"""Investigation and dataset statistics router for CyberGuard."""
from typing import Any, Dict, Optional, Union
from fastapi import APIRouter, HTTPException

from backend.models.incident import IncidentAlert
from backend.models.investigation import InvestigationRequest, InvestigationResponse
from backend.services.context_synthesizer import context_synthesizer
from backend.services.dataset_service import dataset_service
from backend.services.groq_service import groq_service
from backend.services.notifier import terminal_notifier
from backend.services.retriever import local_retriever

router = APIRouter(prefix="/api", tags=["Investigation"])


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate_alert(payload: Union[IncidentAlert, InvestigationRequest]):
    """Analyzes an incident alert using historical evidence, Bayesian confidence, and Groq."""
    try:
        # Normalize incoming payload to IncidentAlert
        if isinstance(payload, IncidentAlert):
            alert = payload
        else:
            alert = IncidentAlert(
                alert_title=payload.alert_title,
                raw_logs=payload.raw_logs or "",
                affected_system=payload.affected_system
            )

        # 1. Retrieve historical evidence
        if hasattr(payload, "bypass_memory") and payload.bypass_memory:
            evidence_list = []
        else:
            evidence_list = local_retriever.retrieve(alert=alert, top_k=5)

        # 2. Synthesize context with Bayesian confidence
        synthesized = context_synthesizer.synthesize(alert=alert, evidence_list=evidence_list)

        # 3. Groq LLM inference
        response = groq_service.investigate_with_context(synthesized)

        # 4. Trigger active terminal alert
        primary_act = response.recommended_actions[0].action if response.recommended_actions else "Triage"
        terminal_notifier.notify({
            "investigation_id": response.investigation_id,
            "summary": response.summary,
            "primary_action": primary_act,
            "confidence_score": response.confidence_score,
            "recommended_playbook_id": response.recommended_playbook_id
        })

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.get("/dataset/stats")
async def get_dataset_statistics() -> Dict[str, Any]:
    """Returns dataset metrics including total counts, categories, and severities."""
    try:
        return dataset_service.get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load dataset stats: {str(e)}")
