"""Context Synthesizer and Bayesian Confidence Calculation.

Calculates Bayesian Historical Confidence using the formula:
    Confidence = 0.40 * VectorSimilarity + 0.60 * ((Successes + 1) / (Trials + 2))

Strictly separates CURRENT ALERT from HISTORICAL EVIDENCE so LLM reasoning remains grounded.
Preserves atomic pairing of action, outcome, efficacy score, and analyst notes.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from cyberguard.models.incident import IncidentAlert
from cyberguard.services.retriever import HistoricalEvidence


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


class ContextSynthesizer:
    """Synthesizes historical evidence and calculates Bayesian confidence."""

    @staticmethod
    def calculate_bayesian_confidence(vector_similarity: float, successes: int, trials: int) -> float:
        """Computes: Confidence = 0.40 * VectorSimilarity + 0.60 * ((Successes + 1) / (Trials + 2))
        
        Uses Laplace smoothing prior (+1 / +2) to handle small sample sizes and zero trials safely.
        Result is clamped strictly to [0.0, 1.0].
        """
        smoothed_rate = (successes + 1) / (trials + 2)
        score = (0.40 * vector_similarity) + (0.60 * smoothed_rate)
        return round(min(1.0, max(0.0, score)), 4)

    def synthesize(self, alert: IncidentAlert, historical_matches: List[HistoricalEvidence]) -> SynthesizedContext:
        """Combines an alert and retrieved historical matches into a structured, validated context."""
        current_alert_dict = {
            "alert_id": alert.alert_id,
            "alert_title": alert.alert_title,
            "raw_logs": alert.raw_logs,
            "affected_system": alert.affected_system,
            "timestamp": alert.timestamp,
            "extensions": alert.extensions
        }

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
context_synthesizer = ContextSynthesizer()
