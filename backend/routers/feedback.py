"""Feedback router (To be implemented in Phase 6)."""
from fastapi import APIRouter
from backend.models.feedback import FeedbackRequest, FeedbackResponse

router = APIRouter(prefix="/api", tags=["Feedback"])


@router.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(request: FeedbackRequest):
    """Endpoint for submitting analyst feedback into Hindsight memory (Phase 6)."""
    return FeedbackResponse(message="Feedback endpoint will be implemented in Phase 6")
