"""Tests for CyberGuard canonical incident schemas, 1000-incident dataset, and retrieval logic."""
import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from backend.models.incident import (
    IncidentRecord,
    ResolutionRecord,
    IncidentAlert,
    MemoryObject,
    AnalystFeedback
)
from backend.services.dataset_service import dataset_service
from backend.services.retriever import local_retriever
from backend.services.context_synthesizer import context_synthesizer, ContextSynthesizer
from backend.scripts.validate_dataset import validate_dataset

DATASET_PATH = Path(__file__).resolve().parent.parent / "cyberguard_incidents_1000.json"


@pytest.fixture
def sample_valid_incident():
    return {
        "incident_id": "INC-2026-TEST",
        "category": "Traditional Cyber",
        "incident_type": "SSH Brute Force",
        "severity": "High",
        "affected_system": "bastion.corp.internal",
        "symptoms": ["Multiple failed SSH attempts"],
        "indicators_of_compromise": ["198.51.100.24"],
        "root_cause": "Weak password auth exposed",
        "recommended_playbook": "PB-SSH-BRUTE-FORCE",
        "resolutions_tried": [
            {
                "action": "Enforce MFA and disable passwords",
                "success": True,
                "efficacy_score": 0.95,
                "analyst_notes": "Worked smoothly"
            }
        ],
        "lessons_learned": "Enforce MFA everywhere",
        "extensions": {"port": 22, "protocol": "SSH-2"}
    }


def test_valid_incident_record(sample_valid_incident):
    """Verify that a valid incident dictionary creates an IncidentRecord."""
    record = IncidentRecord.model_validate(sample_valid_incident)
    assert record.incident_id == "INC-2026-TEST"
    assert record.category == "Traditional Cyber"
    assert record.severity == "High"
    assert record.resolutions_tried[0].efficacy_score == 0.95
    assert record.extensions["port"] == 22


def test_invalid_severity(sample_valid_incident):
    """Verify that an invalid severity string raises a ValidationError."""
    data = sample_valid_incident.copy()
    data["severity"] = "UltraCritical"
    with pytest.raises(ValidationError) as exc:
        IncidentRecord.model_validate(data)
    assert "severity" in str(exc.value)


def test_invalid_category(sample_valid_incident):
    """Verify that an invalid category raises a ValidationError."""
    data = sample_valid_incident.copy()
    data["category"] = "Physical Security"
    with pytest.raises(ValidationError) as exc:
        IncidentRecord.model_validate(data)
    assert "category" in str(exc.value)


@pytest.mark.parametrize("invalid_score", [-0.2, 1.3])
def test_invalid_efficacy_score(sample_valid_incident, invalid_score):
    """Verify that efficacy_score outside 0.0 - 1.0 raises ValidationError."""
    data = sample_valid_incident.copy()
    data["resolutions_tried"] = [
        {"action": "Block IP", "success": False, "efficacy_score": invalid_score}
    ]
    with pytest.raises(ValidationError) as exc:
        IncidentRecord.model_validate(data)
    assert "efficacy_score" in str(exc.value)


def test_extensions_support(sample_valid_incident):
    """Verify that the hybrid schema supports arbitrary extensions telemetry."""
    data = sample_valid_incident.copy()
    data["extensions"] = {
        "telemetry_source": "syslog",
        "blast_radius_score": 0.85,
        "custom_tags": ["pci-dss", "tier-1"]
    }
    record = IncidentRecord.model_validate(data)
    assert record.extensions["blast_radius_score"] == 0.85
    assert "pci-dss" in record.extensions["custom_tags"]


def test_primary_dataset_count_and_distribution():
    """Verify that cyberguard_incidents_1000.json contains exactly 1000 records (700 Traditional / 300 AI)."""
    results = validate_dataset(DATASET_PATH)
    assert results["total_incidents"] == 1000
    assert results["traditional_cyber_count"] == 700
    assert results["ai_security_count"] == 300
    assert results["unique_ids_count"] == 1000


def test_dataset_service_load_and_queries():
    """Verify dataset_service loads and indexes records correctly."""
    incidents = dataset_service.load_incidents()
    assert len(incidents) == 1000

    target = dataset_service.get_incident_by_id("INC-2026-0607")
    assert target is not None
    assert target.incident_type == "SQL Injection"
    assert target.severity == "Critical"

    stats = dataset_service.get_statistics()
    assert stats["total_incidents"] == 1000
    assert stats["traditional_cyber"] == 700
    assert stats["ai_security"] == 300


def test_retriever_excludes_self_id():
    """Verify historical retriever does not return the queried incident itself as evidence."""
    target_inc = dataset_service.get_incident_by_id("INC-2026-0607")
    alert = IncidentAlert(
        alert_id=target_inc.incident_id,
        alert_title=target_inc.incident_type,
        raw_logs="\n".join(target_inc.symptoms),
        affected_system=target_inc.affected_system
    )
    evidence = local_retriever.retrieve(alert=alert, top_k=5, exclude_id="INC-2026-0607")
    retrieved_ids = [e.incident_id for e in evidence]
    assert "INC-2026-0607" not in retrieved_ids
    assert len(evidence) > 0


def test_bayesian_confidence_calculation():
    """Verify Bayesian confidence formula: 0.40 * Sim + 0.60 * ((Successes + 1)/(Trials + 2))."""
    calc = ContextSynthesizer.calculate_bayesian_confidence

    # Sim = 1.0, 5 successes out of 5 trials:
    # 0.40 * 1.0 + 0.60 * (6/7) = 0.40 + 0.5143 = 0.9143
    conf1 = calc(vector_similarity=1.0, successes=5, trials=5)
    assert conf1 == pytest.approx(0.9143, abs=0.001)

    # Zero trials (prior is 1/2 = 0.5):
    # 0.40 * 0.8 + 0.60 * 0.5 = 0.32 + 0.30 = 0.62
    conf_zero = calc(vector_similarity=0.8, successes=0, trials=0)
    assert conf_zero == pytest.approx(0.62, abs=0.001)

    # 0 successes out of 5 trials (failed action):
    # 0.40 * 0.8 + 0.60 * (1/7) = 0.32 + 0.0857 = 0.4057
    conf_failed = calc(vector_similarity=0.8, successes=0, trials=5)
    assert conf_failed == pytest.approx(0.4057, abs=0.001)

    # Bounds check
    assert 0.0 <= conf1 <= 1.0
    assert 0.0 <= conf_zero <= 1.0
    assert 0.0 <= conf_failed <= 1.0


def test_context_synthesizer_clean_separation():
    """Verify ContextSynthesizer cleanly isolates current alert from historical memory."""
    target_inc = dataset_service.get_incident_by_id("INC-2026-0607")
    alert = IncidentAlert(
        alert_id=target_inc.incident_id,
        alert_title=target_inc.incident_type,
        raw_logs="Test raw log lines",
        affected_system=target_inc.affected_system
    )
    evidence = local_retriever.retrieve(alert=alert, top_k=5, exclude_id="INC-2026-0607")
    synthesized = context_synthesizer.synthesize(alert=alert, evidence_list=evidence)

    # Check separation
    assert synthesized.current_alert["alert_id"] == "INC-2026-0607"
    assert synthesized.current_alert["alert_title"] == "SQL Injection"
    assert len(synthesized.historical_matches) > 0
    assert len(synthesized.action_evaluations) > 0
    assert synthesized.primary_candidate_action is not None
    assert 0.0 <= synthesized.primary_candidate_action.final_confidence <= 1.0


def test_resolution_record_atomic_pairing_for_sql_injection():
    """Verify action, success, and efficacy_score strictly come from the same resolution object."""
    target_inc = dataset_service.get_incident_by_id("INC-2026-0607")
    alert = IncidentAlert(
        alert_id=target_inc.incident_id,
        alert_title=target_inc.incident_type,
        raw_logs="\n".join(target_inc.symptoms),
        affected_system=target_inc.affected_system
    )
    evidence = local_retriever.retrieve(alert=alert, top_k=5, exclude_id="INC-2026-0607")

    # Match #1 should be INC-2026-0413
    match1 = evidence[0]
    assert match1.incident_id == "INC-2026-0413"

    # Verify each resolution object in match1 has aligned fields
    res0 = match1.resolutions_tried[0]
    assert res0.action == "Blocked the detected request pattern"
    assert res0.success is False
    assert res0.efficacy_score == 0.48

    res1 = match1.resolutions_tried[1]
    assert res1.action == "Applied parameterized queries and corrected input validation"
    assert res1.success is True
    assert res1.efficacy_score == 0.97
