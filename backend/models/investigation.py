"""Investigation request and response models matching CyberGuard canonical format."""
from typing import List, Optional
from pydantic import BaseModel, Field


class ActionItem(BaseModel):
    """Specific remediation or discouraged action with historical efficacy and status."""
    priority: int
    action: str
    historical_efficacy: str
    status: str  # e.g., "RECOMMENDED" | "DISCOURAGED_WARNING"
    warning: Optional[str] = None


class InvestigationResponse(BaseModel):
    """Structured incident investigation response."""
    investigation_id: str
    summary: str
    root_cause_analysis: str
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_actions: List[ActionItem] = Field(default_factory=list)
    recommended_playbook_id: Optional[str] = None
    similar_historical_incidents: List[str] = Field(default_factory=list)


class InvestigationRequest(BaseModel):
    alert_title: str
    raw_logs: Optional[str] = ""
    affected_system: Optional[str] = None
    bypass_memory: bool = False
