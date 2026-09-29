"""
Segment 3: Bayesian Scorer & Context Synthesizer
Calculates Laplace-smoothed confidence score and builds context payload for LLM Copilot.
"""
from typing import Dict, Any
from app.config import settings

class BayesianScorer:
    @staticmethod
    def calculate_confidence(
        semantic_similarity: float,
        successful_resolutions: int,
        times_used: int,
        w_sem: float = settings.WEIGHT_SEMANTIC,
        w_emp: float = settings.WEIGHT_EMPIRICAL
    ) -> float:
        """
        Calculates Laplace-smoothed Bayesian confidence score.
        Confidence = (w_sem * Similarity) + (w_emp * ((Successes + 1) / (Trials + 2)))
        """
        # Laplace Smoothing: (Successes + 1) / (Trials + 2)
        empirical_score = (successful_resolutions + 1) / (times_used + 2) if times_used >= 0 else 0.5
        raw_confidence = (w_sem * semantic_similarity) + (w_emp * empirical_score)
        
        # Clamp confidence between 0.50 and 0.98 for realistic reporting
        return round(min(max(raw_confidence, 0.50), 0.98), 2)

    @classmethod
    def synthesize_context(cls, scenario: str, memory_profile: Dict[str, Any], severity: str) -> Dict[str, Any]:
        """
        Merges memory matches and computes dynamic confidence score for recommendation.
        """
        times_used = memory_profile.get('times_used', 0)
        successful = memory_profile.get('successful_resolutions', 0)
        
        # Calculate primary match similarity from top historical match
        matches = memory_profile.get('historical_matches', [])
        top_sim = matches[0]['similarity'] if matches else 0.85

        calculated_confidence = cls.calculate_confidence(
            semantic_similarity=top_sim,
            successful_resolutions=successful,
            times_used=times_used
        )

        success_rate = successful / times_used if times_used > 0 else 0.0

        recommendation_data = {
            "resolution_id": memory_profile['resolution_id'],
            "resolution": memory_profile['resolution'],
            "response_domain": memory_profile.get('response_domain', 'Incident Containment'),
            "priority": "Critical" if severity.lower() == "critical" else memory_profile.get('priority', 'High'),
            "rationale": memory_profile.get('rationale', f"Historical incident data shows this response action succeeded in {successful} of {times_used} similar cases."),
            "response_steps": memory_profile.get('response_steps', []),
            "confidence": calculated_confidence,
            "times_used": times_used,
            "successful_resolutions": successful,
            "success_rate": round(success_rate, 4),
            "alternate_resolution_id": memory_profile.get('alternate_resolution_id'),
            "alternate_playbook": memory_profile.get('alternate_playbook'),
            "alternate_steps": memory_profile.get('alternate_steps', []),
            "escalation_tier": memory_profile.get('escalation_tier', 'Tier-2 DFIR & Threat Specialist')
        }

        return {
            "recommendation": recommendation_data,
            "historical_matches": matches,
            "is_cold_start": len(matches) == 0
        }
