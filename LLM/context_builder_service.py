"""Context Builder Service for CyberGuard.

Service-oriented module responsible for:
1. Canonical incident schemas (IncidentAlert, IncidentRecord, ResolutionRecord)
2. Primary dataset operations (loading, querying 1,000 incidents)
3. Historical memory retrieval & heuristic similarity matching
4. Bayesian confidence calculation:
       Confidence = 0.40 * Similarity + 0.60 * ((Successes + 1) / (Trials + 2))
5. Synthesizing validated evidence into structured context for LLM triage.
"""
from abc import ABC, abstractmethod
from collections import Counter
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Literal, Optional, Set, Union
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

# Default dataset path resolution
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DATASET_PATH = PROJECT_ROOT / "cyberguard_incidents_1000.json"


# =====================================================================
# Canonical Data Models
# =====================================================================

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
    """Schema for individual memories stored in or recalled from persistent store."""
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


class ActionEvaluation(BaseModel):
    """Bayesian statistical evaluation of a candidate remediation action."""
    action: str
    vector_similarity: float = Field(ge=0.0, le=1.0)
    successes: int = Field(ge=0)
    trials: int = Field(ge=0)
    empirical_rate: float = Field(ge=0.0, le=1.0)
    smoothed_rate: float = Field(ge=0.0, le=1.0)
    average_efficacy: float = Field(default=0.0, ge=0.0, le=1.0)
    final_confidence: float = Field(ge=0.0, le=1.0)
    source_incident_ids: List[str] = Field(default_factory=list)


class ResolutionSummary(BaseModel):
    """Atomic paired resolution detail from a historical incident."""
    incident_id: str
    action: str
    success: bool
    efficacy_score: Optional[float] = None
    analyst_notes: Optional[str] = None


class SynthesizedContext(BaseModel):
    """Unified context object cleanly separating current alert from retrieved historical memory."""
    current_alert: Dict[str, Any]
    historical_matches: List[Dict[str, Any]] = Field(default_factory=list)
    action_evaluations: List[ActionEvaluation] = Field(default_factory=list)
    proven_effective_actions: List[ResolutionSummary] = Field(default_factory=list)
    known_failed_actions: List[ResolutionSummary] = Field(default_factory=list)
    recommended_playbooks: List[str] = Field(default_factory=list)
    lessons_learned: List[str] = Field(default_factory=list)
    primary_candidate_action: Optional[ActionEvaluation] = None


# =====================================================================
# Tokenizer & Retrieval Heuristics
# =====================================================================

def _tokenize(text: str) -> Set[str]:
    """Extract lowercase alphanumeric tokens from text."""
    if not text:
        return set()
    return set(re.findall(r"\b[a-zA-Z0-9_\-\.]{3,}\b", text.lower()))


# =====================================================================
# Context Builder Service Implementation
# =====================================================================

class ContextBuilderService:
    """Service-oriented manager for incident dataset loading, retrieval, and Bayesian context synthesis."""

    def __init__(self, dataset_path: Optional[Path] = None):
        env_path = os.getenv("CYBERGUARD_DATASET_PATH")
        self.dataset_path = Path(dataset_path or env_path or DEFAULT_DATASET_PATH)
        self._incidents: Optional[List[IncidentRecord]] = None
        self._incidents_by_id: Optional[Dict[str, IncidentRecord]] = None

    def load_incidents(self) -> List[IncidentRecord]:
        """Loads and validates all incidents from the primary dataset file."""
        if self._incidents is not None:
            return self._incidents

        if not self.dataset_path.exists():
            alt_path = PROJECT_ROOT / "cyberguard_incidents_1000.json"
            if alt_path.exists():
                self.dataset_path = alt_path
            else:
                raise FileNotFoundError(f"Primary dataset not found at: {self.dataset_path}")

        logger.info(f"Loading incidents from {self.dataset_path}")
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            raise ValueError(f"Dataset root must be a JSON array, got {type(raw_data).__name__}")

        validated_incidents: List[IncidentRecord] = []
        by_id: Dict[str, IncidentRecord] = {}

        for record in raw_data:
            incident = IncidentRecord.model_validate(record)
            validated_incidents.append(incident)
            by_id[incident.incident_id] = incident

        self._incidents = validated_incidents
        self._incidents_by_id = by_id
        return self._incidents

    def get_incident_by_id(self, incident_id: str) -> Optional[IncidentRecord]:
        """Retrieves a specific incident by its unique ID."""
        if self._incidents_by_id is None:
            self.load_incidents()
        return self._incidents_by_id.get(incident_id)

    def get_random_incident(self) -> IncidentRecord:
        """Picks a random incident from the dataset."""
        import random
        incidents = self.load_incidents()
        return random.choice(incidents)

    def get_stats(self) -> Dict[str, Any]:
        """Returns distribution statistics of categories, severities, and top incident types."""
        incidents = self.load_incidents()
        categories = Counter(i.category for i in incidents)
        severities = Counter(i.severity for i in incidents)
        types = Counter(i.incident_type for i in incidents)

        return {
            "total_incidents": len(incidents),
            "category_distribution": dict(categories),
            "severity_distribution": dict(severities),
            "top_incident_types": dict(types.most_common(10)),
        }

    def convert_to_alert(self, incident: IncidentRecord) -> IncidentAlert:
        """Converts an existing incident record into an incoming IncidentAlert simulation."""
        raw_logs = f"Alert trigger on system: {incident.affected_system}. Symptoms: {', '.join(incident.symptoms)}. IOCs: {', '.join(incident.indicators_of_compromise)}."
        return IncidentAlert(
            alert_id=f"ALT-{incident.incident_id}",
            alert_title=f"Detected {incident.incident_type} on {incident.affected_system}",
            raw_logs=raw_logs,
            affected_system=incident.affected_system,
            extensions=incident.extensions
        )

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
        """Search the 1000-incident dataset and return top_k ranked historical evidence records."""
        incidents = self.load_incidents()

        alert_text = f"{alert.alert_title} {alert.affected_system or ''} {alert.raw_logs or ''}"
        alert_tokens = _tokenize(alert_text)

        scored_candidates = []
        for inc in incidents:
            if exclude_id and inc.incident_id == exclude_id:
                continue

            similarity = self._compute_similarity(alert_tokens, inc, alert)
            scored_candidates.append((similarity, inc))

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

    @staticmethod
    def calculate_bayesian_confidence(vector_similarity: float, successes: int, trials: int) -> float:
        """Computes: Confidence = 0.40 * VectorSimilarity + 0.60 * ((Successes + 1) / (Trials + 2))
        
        Uses Laplace smoothing prior (+1 / +2) to handle small sample sizes and zero trials safely.
        """
        smoothed_rate = (successes + 1) / (trials + 2)
        score = (0.40 * vector_similarity) + (0.60 * smoothed_rate)
        return round(min(1.0, max(0.0, score)), 4)

    def build_context(
        self,
        alert: Union[IncidentAlert, Dict[str, Any]],
        top_k: int = 5,
        exclude_id: Optional[str] = None,
        bypass_memory: bool = False
    ) -> SynthesizedContext:
        """Builds a fully synthesized context for an alert by retrieving history and computing Bayesian confidence."""
        if isinstance(alert, dict):
            alert_obj = IncidentAlert.model_validate(alert)
        else:
            alert_obj = alert

        current_alert_dict = {
            "alert_id": alert_obj.alert_id,
            "alert_title": alert_obj.alert_title,
            "raw_logs": alert_obj.raw_logs,
            "affected_system": alert_obj.affected_system,
            "timestamp": alert_obj.timestamp,
            "extensions": alert_obj.extensions
        }

        if bypass_memory:
            return SynthesizedContext(
                current_alert=current_alert_dict,
                historical_matches=[],
                action_evaluations=[],
                proven_effective_actions=[],
                known_failed_actions=[],
                recommended_playbooks=[],
                lessons_learned=[],
                primary_candidate_action=None
            )

        historical_matches = self.retrieve(alert=alert_obj, top_k=top_k, exclude_id=exclude_id)
        if not historical_matches:
            return SynthesizedContext(
                current_alert=current_alert_dict,
                historical_matches=[],
                action_evaluations=[],
                proven_effective_actions=[],
                known_failed_actions=[],
                recommended_playbooks=[],
                lessons_learned=[],
                primary_candidate_action=None
            )

        # Aggregate resolution actions across historical evidence
        action_stats: Dict[str, Dict[str, Any]] = {}
        proven_effective: List[ResolutionSummary] = []
        known_failed: List[ResolutionSummary] = []
        playbooks: List[str] = []
        lessons: List[str] = []
        matches_serialized: List[Dict[str, Any]] = []

        for match in historical_matches:
            matches_serialized.append(match.model_dump())
            if match.recommended_playbook and match.recommended_playbook not in playbooks:
                playbooks.append(match.recommended_playbook)
            if match.lessons_learned and match.lessons_learned not in lessons:
                lessons.append(match.lessons_learned)

            for res in match.resolutions_tried:
                action_clean = res.action.strip()
                summary_item = ResolutionSummary(
                    incident_id=match.incident_id,
                    action=action_clean,
                    success=res.success,
                    efficacy_score=res.efficacy_score,
                    analyst_notes=res.analyst_notes
                )

                if res.success:
                    proven_effective.append(summary_item)
                else:
                    known_failed.append(summary_item)

                if action_clean not in action_stats:
                    action_stats[action_clean] = {
                        "action": action_clean,
                        "successes": 0,
                        "trials": 0,
                        "efficacy_scores": [],
                        "max_similarity": match.similarity_score,
                        "incident_ids": []
                    }

                entry = action_stats[action_clean]
                entry["trials"] += 1
                if res.success:
                    entry["successes"] += 1
                if res.efficacy_score is not None:
                    entry["efficacy_scores"].append(res.efficacy_score)
                entry["max_similarity"] = max(entry["max_similarity"], match.similarity_score)
                if match.incident_id not in entry["incident_ids"]:
                    entry["incident_ids"].append(match.incident_id)

        action_evaluations: List[ActionEvaluation] = []
        for action_name, stats in action_stats.items():
            successes = stats["successes"]
            trials = stats["trials"]
            sim = stats["max_similarity"]
            empirical_rate = successes / trials if trials > 0 else 0.0
            smoothed_rate = (successes + 1) / (trials + 2)
            avg_eff = (
                sum(stats["efficacy_scores"]) / len(stats["efficacy_scores"])
                if stats["efficacy_scores"] else empirical_rate
            )
            confidence = self.calculate_bayesian_confidence(sim, successes, trials)

            action_evaluations.append(
                ActionEvaluation(
                    action=action_name,
                    vector_similarity=round(sim, 4),
                    successes=successes,
                    trials=trials,
                    empirical_rate=round(empirical_rate, 4),
                    smoothed_rate=round(smoothed_rate, 4),
                    average_efficacy=round(avg_eff, 4),
                    final_confidence=confidence,
                    source_incident_ids=stats["incident_ids"]
                )
            )

        # Sort candidate actions by final Bayesian confidence descending
        action_evaluations.sort(key=lambda x: (x.final_confidence, x.trials), reverse=True)
        primary_action = action_evaluations[0] if action_evaluations else None

        return SynthesizedContext(
            current_alert=current_alert_dict,
            historical_matches=matches_serialized,
            action_evaluations=action_evaluations,
            proven_effective_actions=proven_effective,
            known_failed_actions=known_failed,
            recommended_playbooks=playbooks,
            lessons_learned=lessons,
            primary_candidate_action=primary_action
        )


# Global singleton instance
context_builder_service = ContextBuilderService()
