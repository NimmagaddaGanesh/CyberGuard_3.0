"""Historical memory retrieval service.

Provides the HistoricalMemoryRetriever abstraction and the LocalDatasetRetriever
implementation for searching historical incidents deterministically.
Designed to be replaced by Hindsight Cloud in Phase 14 without altering Groq or API layers.
"""
from abc import ABC, abstractmethod
import re
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from backend.models.incident import IncidentAlert, IncidentRecord, ResolutionRecord
from backend.services.dataset_service import dataset_service


class HistoricalEvidence(BaseModel):
    """Structured evidence returned from historical incident retrieval."""
    incident_id: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    category: str
    incident_type: str
    severity: str
    affected_system: str
    symptoms: List[str] = Field(default_factory=list)
    root_cause: str
    recommended_playbook: str
    resolutions_tried: List[ResolutionRecord] = Field(default_factory=list)
    lessons_learned: Optional[str] = None


class HistoricalMemoryRetriever(ABC):
    """Abstract interface for historical incident memory retrieval."""

    @abstractmethod
    def retrieve(
        self,
        alert: IncidentAlert,
        top_k: int = 5,
        exclude_id: Optional[str] = None
    ) -> List[HistoricalEvidence]:
        """Retrieve top_k matching historical incident memories."""
        pass


def _tokenize(text: str) -> Set[str]:
    """Extract lowercase alphanumeric tokens from text."""
    if not text:
        return set()
    return set(re.findall(r"\b[a-zA-Z0-9_\-\.]{3,}\b", text.lower()))


class LocalDatasetRetriever(HistoricalMemoryRetriever):
    """Deterministic local retriever operating over the 1000-incident dataset.
    
    Acts as the temporary memory backend prior to Hindsight Cloud setup.
    """

    def __init__(self, ds_service=None):
        self.ds_service = ds_service or dataset_service

    def _compute_similarity(self, alert_tokens: Set[str], candidate: IncidentRecord, alert: IncidentAlert) -> float:
        """Computes deterministic similarity score between alert and historical candidate."""
        candidate_text = f"{candidate.incident_type} {candidate.category} {candidate.affected_system} {candidate.root_cause} " + \
                         " ".join(candidate.symptoms) + " " + " ".join(candidate.indicators_of_compromise) + " " + \
                         candidate.recommended_playbook
        candidate_tokens = _tokenize(candidate_text)

        if not alert_tokens or not candidate_tokens:
            return 0.0

        # Jaccard similarity on tokens
        intersection = alert_tokens.intersection(candidate_tokens)
        union = alert_tokens.union(candidate_tokens)
        jaccard = len(intersection) / len(union) if union else 0.0

        # Incident type exact/partial match bonus
        type_bonus = 0.0
        alert_title_lower = alert.alert_title.lower()
        if candidate.incident_type.lower() in alert_title_lower or alert_title_lower in candidate.incident_type.lower():
            type_bonus = 0.35
        elif any(t in alert_title_lower for t in _tokenize(candidate.incident_type)):
            type_bonus = 0.20

        # System match bonus
        system_bonus = 0.0
        if alert.affected_system and candidate.affected_system:
            if alert.affected_system.lower() == candidate.affected_system.lower():
                system_bonus = 0.15

        # Weighted composite score normalized to [0.0, 1.0]
        score = (jaccard * 0.50) + type_bonus + system_bonus
        return min(max(round(score, 4), 0.0), 1.0)

    def retrieve(
        self,
        alert: IncidentAlert,
        top_k: int = 5,
        exclude_id: Optional[str] = None
    ) -> List[HistoricalEvidence]:
        """Search the 1000-incident dataset and return ranked historical evidence."""
        incidents = self.ds_service.load_incidents()

        alert_text = f"{alert.alert_title} {alert.affected_system or ''} {alert.raw_logs or ''}"
        alert_tokens = _tokenize(alert_text)

        scored_candidates = []
        for inc in incidents:
            # Exclude self ID to prevent data leakage during self-testing
            if exclude_id and inc.incident_id == exclude_id:
                continue

            similarity = self._compute_similarity(alert_tokens, inc, alert)
            scored_candidates.append((similarity, inc))

        # Sort descending by similarity
        scored_candidates.sort(key=lambda x: x[0], reverse=True)

        results: List[HistoricalEvidence] = []
        for sim, inc in scored_candidates[:top_k]:
            evidence = HistoricalEvidence(
                incident_id=inc.incident_id,
                similarity_score=sim,
                category=inc.category,
                incident_type=inc.incident_type,
                severity=inc.severity,
                affected_system=inc.affected_system,
                symptoms=inc.symptoms,
                root_cause=inc.root_cause,
                recommended_playbook=inc.recommended_playbook,
                resolutions_tried=inc.resolutions_tried,
                lessons_learned=inc.lessons_learned
            )
            results.append(evidence)

        return results


# Default retriever instance
local_retriever = LocalDatasetRetriever()
