"""
Segment 5: Analyst Feedback & Memory Update Worker
Receives analyst feedback, updates empirical counts, recalculates rates, commits to Hindsight,
and triggers Groq LLM Deep Security Dossier when escalation limit is reached.
"""
from typing import Dict, Any
from app.models.schemas import FeedbackSubmission, FeedbackResponse, FeedbackResponseMetrics, HistoricalMatch
from app.segment_2_hindsight_memory.hindsight_client import hindsight_service
from app.segment_4_copilot_llm.copilot_engine import copilot_service

class MemoryUpdateWorker:
    @staticmethod
    async def process_feedback(submission: FeedbackSubmission) -> FeedbackResponse:
        """
        Applies analyst feedback, updates memory state, and returns updated metrics with alternate playbook
        or Groq LLM deep investigation dossier if escalation limit is reached.
        """
        updated_data = hindsight_service.update_local_memory(
            resolution_id=submission.resolution_id,
            outcome=submission.feedback_outcome,
            incident_id=submission.incident_id
        )

        metrics = FeedbackResponseMetrics(
            times_used=updated_data["times_used"],
            successful_resolutions=updated_data["successful_resolutions"],
            success_rate=updated_data["success_rate"]
        )

        hist_matches = [
            HistoricalMatch(**m) for m in updated_data.get("historical_matches", [])
        ]

        # Check if escalation limit (Level 2+) has been hit
        is_exhausted = (
            submission.feedback_outcome == "failed" 
            and (submission.escalation_count or 1) >= 2
        )

        deep_memo = None
        emergency_actions = []

        if is_exhausted:
            primary_action = updated_data.get("resolution", "Tier-1 Automated Playbook")
            alternate_action = updated_data.get("alternate_playbook", "Tier-2 Containment Playbook")
            deep_memo, emergency_actions = await copilot_service.generate_deep_investigation_dossier(
                incident_id=submission.incident_id,
                resolution_id=submission.resolution_id,
                primary_action=primary_action,
                alternate_action=alternate_action
            )

        return FeedbackResponse(
            memory_updated=True,
            metrics=metrics,
            historical_matches=hist_matches,
            alternate_playbook=updated_data.get("alternate_playbook"),
            alternate_steps=updated_data.get("alternate_steps", []),
            escalation_tier=updated_data.get("escalation_tier"),
            is_exhausted=is_exhausted,
            deep_investigation_memo=deep_memo,
            emergency_actions=emergency_actions,
            received=submission.model_dump()
        )

memory_updater_service = MemoryUpdateWorker()
