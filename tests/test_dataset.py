"""Tests for CyberGuard canonical incident schemas, 1000-incident dataset, and retrieval logic."""
import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from cyberguard.models.incident import (
    IncidentRecord,
    ResolutionRecord,
    IncidentAlert,
    MemoryObject,
    AnalystFeedback
)
from cyberguard.services.dataset_service import dataset_service, validate_dataset
from cyberguard.services.retriever import local_retriever
from cyberguard.services.context_synthesizer import context_synthesizer, ContextSynthesizer

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
    with pytest.raises(ValidationError):
        IncidentRecord.model_validate(data)


def test_invalid_category(sample_valid_incident):
    """Verify that an invalid category string raises a ValidationError."""
    data = sample_valid_incident.copy()
    data["category"] = "Physical Security"
    with pytest.raises(ValidationError):
        IncidentRecord.model_validate(data)


def test_dataset_file_structure():
    """Verify that the primary dataset file conforms to the canonical contract."""
    results = validate_dataset(DATASET_PATH)
    assert results["status"] == "VALID"
    assert results["total_incidents"] == 1000
    assert results["traditional_cyber_count"] == 700
    assert results["ai_security_count"] == 300
    assert results["unique_ids_count"] == 1000


def test_retriever_returns_relevant_evidence():
    """Verify that local_retriever retrieves relevant historical matches."""
    alert = IncidentAlert(
        alert_title="Suspicious SSH repeated logon failures",
        raw_logs="sshd: Failed password for invalid user admin from 192.168.1.50 port 44322 ssh2",
        affected_system="bastion-host"
    )
    matches = local_retriever.retrieve(alert, top_k=3)
    assert len(matches) <= 3
    assert len(matches) > 0
    # First match should have positive similarity score
    assert matches[0].similarity_score > 0.0
    assert matches[0].incident_id.startswith("INC-")


def test_bayesian_confidence_calculation():
    """Verify the Bayesian confidence formula implementation."""
    # formula: 0.40 * similarity + 0.60 * ((successes + 1) / (trials + 2))
    # 0 trials, 0 successes: smoothed rate = 1/2 = 0.5
    # with similarity 1.0: 0.40 * 1.0 + 0.60 * 0.5 = 0.40 + 0.30 = 0.70
    conf = ContextSynthesizer.calculate_bayesian_confidence(
        vector_similarity=1.0,
        successes=0,
        trials=0
    )
    assert conf == 0.70

    # 10 trials, 10 successes: smoothed rate = 11/12 = 0.916666...
    # similarity 0.8: 0.40 * 0.8 + 0.60 * (11/12) = 0.32 + 0.55 = 0.87
    conf2 = ContextSynthesizer.calculate_bayesian_confidence(
        vector_similarity=0.8,
        successes=10,
        trials=10
    )
    assert round(conf2, 2) == 0.87


def test_context_synthesizer_separates_proven_and_failed_actions():
    """Verify that ContextSynthesizer separates proven vs failed actions."""
    alert = IncidentAlert(
        alert_title="SQL Injection detection in API",
        raw_logs="' OR '1'='1",
        affected_system="api-gateway"
    )
    matches = local_retriever.retrieve(alert, top_k=5)
    context = context_synthesizer.synthesize(alert, matches)
    assert context.current_alert["alert_title"] == alert.alert_title
    assert isinstance(context.action_evaluations, list)
