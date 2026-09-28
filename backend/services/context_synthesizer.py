"""Context Synthesizer and Bayesian Confidence Calculation.

Calculates Bayesian Historical Confidence using the architecture-defined formula:
    Confidence = 0.40 * VectorSimilarity + 0.60 * ((Successes + 1) / (Trials + 2))

Strictly separates CURRENT ALERT from HISTORICAL EVIDENCE so LLM reasoning remains grounded.
Preserves atomic pairing of action, outcome, efficacy score, and analyst notes.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.models.incident import IncidentAlert
from backend.services.retriever import HistoricalEvidence


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
        # Laplace-smoothed empirical rate: (Successes + 1) / (Trials + 2)
        smoothed_rate = (successes + 1) / (trials + 2)

        # Weighted composite score
        score = (0.40 * vector_similarity) + (0.60 * smoothed_rate)
        return min(max(round(score, 4), 0.0), 1.0)

    def synthesize(self, alert: IncidentAlert, evidence_list: List[HistoricalEvidence]) -> SynthesizedContext:
        """Transforms retrieved historical memories into a clean, separated context structure."""
        current_alert_dict = {
            "alert_id": alert.alert_id or "ALERT-INCOMING",
            "alert_title": alert.alert_title,
            "affected_system": alert.affected_system or "Not specified",
            "raw_logs": alert.raw_logs or "",
            "timestamp": alert.timestamp or "Real-time"
        }

        # action_name -> aggregated stats
        action_stats: Dict[str, Dict[str, Any]] = {}
        proven_effective: List[ResolutionSummary] = []
        known_failed: List[ResolutionSummary] = []
        playbooks = set()
        lessons = []
        matches_summary = []

        for ev in evidence_list:
            matches_summary.append({
                "incident_id": ev.incident_id,
                "similarity_score": ev.similarity_score,
                "incident_type": ev.incident_type,
                "severity": ev.severity,
                "affected_system": ev.affected_system,
                "root_cause": ev.root_cause,
                "recommended_playbook": ev.recommended_playbook,
                "resolutions_tried": [
                    {
                        "action": r.action,
                        "success": r.success,
                        "efficacy_score": r.efficacy_score,
                        "analyst_notes": r.analyst_notes
                    }
                    for r in ev.resolutions_tried
                ]
            })

            if ev.recommended_playbook:
                playbooks.add(ev.recommended_playbook)
            if ev.lessons_learned:
                lessons.append(f"[{ev.incident_id}] {ev.lessons_learned}")

            for res in ev.resolutions_tried:
                act = res.action.strip()
                if not act:
                    continue

                if act not in action_stats:
                    action_stats[act] = {
                        "successes": 0,
                        "trials": 0,
                        "max_sim": ev.similarity_score,
                        "inc_ids": [],
                        "efficacy_scores": []
                    }

                action_stats[act]["trials"] += 1
                if res.success:
                    action_stats[act]["successes"] += 1
                    proven_effective.append(ResolutionSummary(
                        incident_id=ev.incident_id,
                        action=res.action,
                        success=True,
                        efficacy_score=res.efficacy_score,
                        analyst_notes=res.analyst_notes
                    ))
                else:
                    known_failed.append(ResolutionSummary(
                        incident_id=ev.incident_id,
                        action=res.action,
                        success=False,
                        efficacy_score=res.efficacy_score,
                        analyst_notes=res.analyst_notes
                    ))

                if res.efficacy_score is not None:
                    action_stats[act]["efficacy_scores"].append(res.efficacy_score)

                action_stats[act]["max_sim"] = max(action_stats[act]["max_sim"], ev.similarity_score)
                if ev.incident_id not in action_stats[act]["inc_ids"]:
                    action_stats[act]["inc_ids"].append(ev.incident_id)

        # Compute Bayesian Historical Confidence for each candidate action
        evaluations: List[ActionEvaluation] = []
        for act, stats in action_stats.items():
            successes = stats["successes"]
            trials = stats["trials"]
            max_sim = stats["max_sim"]
            empirical_rate = round(successes / trials, 4) if trials > 0 else 0.0
            smoothed_rate = round((successes + 1) / (trials + 2), 4)

            eff_scores = stats["efficacy_scores"]
            avg_eff = round(sum(eff_scores) / len(eff_scores), 4) if eff_scores else 0.0

            conf = self.calculate_bayesian_confidence(max_sim, successes, trials)

            evaluations.append(ActionEvaluation(
                action=act,
                vector_similarity=max_sim,
                successes=successes,
                trials=trials,
                empirical_rate=empirical_rate,
                smoothed_rate=smoothed_rate,
                average_efficacy=avg_eff,
                final_confidence=conf,
                source_incident_ids=stats["inc_ids"]
            ))

        # Sort candidate actions descending by final confidence
        evaluations.sort(key=lambda x: x.final_confidence, reverse=True)

        primary_action = evaluations[0] if evaluations else None

        return SynthesizedContext(
            current_alert=current_alert_dict,
            historical_matches=matches_summary,
            action_evaluations=evaluations,
            proven_effective_actions=proven_effective,
            known_failed_actions=known_failed,
            recommended_playbooks=sorted(list(playbooks)),
            lessons_learned=lessons,
            primary_candidate_action=primary_action
        )


# Global default instance
context_synthesizer = ContextSynthesizer()
