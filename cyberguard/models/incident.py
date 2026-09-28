"""Canonical incident and memory data schemas for CyberGuard.

Combines the hybrid operational contract with the master ingestion schema:
- Fixed operational fields for SOC workflows
- Optional extensions dictionary for domain-specific telemetry
"""
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ResolutionRecord(BaseModel):
    """Specific remediation attempt with outcome and empirical efficacy."""
    action: str
    success: bool
    efficacy_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    analyst_notes: Optional[str] = None


class IncidentAlert(BaseModel):
    """Incoming alert payload from SIEM / logging pipelines."""
    alert_id: Optional[str] = None
    alert_title: str
    raw_logs: Optional[str] = ""
    affected_system: Optional[str] = None
    timestamp: Optional[str] = None
    extensions: Dict[str, Any] = Field(default_factory=dict)


class IncidentRecord(BaseModel):
    """Canonical CyberGuard incident record schema."""
    incident_id: str
    category: Literal["Traditional Cyber", "AI Security"]
    incident_type: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    affected_system: str
    symptoms: List[str] = Field(default_factory=list)
    indicators_of_compromise: List[str] = Field(default_factory=list)
    root_cause: str
    recommended_playbook: str
    resolutions_tried: List[ResolutionRecord] = Field(default_factory=list)
    lessons_learned: Optional[str] = None
    extensions: Dict[str, Any] = Field(default_factory=dict)


class MemoryObject(BaseModel):
    """Schema for individual memories stored in or recalled from Hindsight."""
    memory_id: Optional[str] = None
    memory_type: Literal["incident", "resolution", "root_cause", "playbook", "lessons_learned"]
    content: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnalystFeedback(BaseModel):
    """Structured analyst feedback schema."""
    incident_id: str
    action_taken: str
    status: Literal["worked", "failed", "partially_useful"]
    analyst_notes: Optional[str] = None
    playbook_id: Optional[str] = None
