"""Analyst feedback request and response models."""
from pydantic import BaseModel
from typing import Optional


class FeedbackRequest(BaseModel):
    incident_id: str
    action_taken: str
    status: str  # "worked" | "failed" | "partially_useful"
    analyst_notes: Optional[str] = None
    playbook_id: Optional[str] = None


class FeedbackResponse(BaseModel):
    message: str = "Feedback endpoint placeholder (Phase 6)"
