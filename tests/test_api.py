import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app
from backend.models.investigation import InvestigationResponse

client = TestClient(app)


def test_health_check():
    """Verify that the GET /api/health endpoint returns 200 and healthy status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CyberGuard"
    assert "running" in data["message"].lower()


def test_dataset_stats_endpoint():
    """Verify GET /api/dataset/stats returns correct metrics for 1000 incidents."""
    response = client.get("/api/dataset/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_incidents"] == 1000
    assert data["traditional_cyber"] == 700
    assert data["ai_security"] == 300
    assert "SQL Injection" in data["incident_types"]


def test_investigate_endpoint_mocked():
    """Verify POST /api/investigate processes an alert and returns structured response."""
    mock_response_data = {
        "investigation_id": "INV-2026-8812",
        "summary": "High-confidence distributed SQL injection attack detected.",
        "root_cause_analysis": "Unvalidated parameters in payment request.",
        "confidence_score": 0.8597,
        "recommended_actions": [
            {
                "priority": 1,
                "action": "Applied parameterized queries and corrected input validation",
                "historical_efficacy": "85.97% Bayesian Confidence (5/5 successes)",
                "status": "RECOMMENDED"
            },
            {
                "priority": 2,
                "action": "Blocked the detected request pattern",
                "historical_efficacy": "40.57% Bayesian Confidence (0/5 successes)",
                "status": "DISCOURAGED_WARNING",
                "warning": "Historical memory shows attackers easily bypass pattern blocking."
            }
        ],
        "recommended_playbook_id": "PB-SQL-INJECTION",
        "similar_historical_incidents": ["INC-2026-0413", "INC-2026-0079"]
    }

    with patch("backend.services.groq_service.groq_service.investigate_with_context") as mock_investigate:
        mock_investigate.return_value = InvestigationResponse.model_validate(mock_response_data)

        payload = {
            "alert_title": "SQL Injection alert on payment gateway",
            "raw_logs": "SELECT * FROM payments WHERE id='1' OR 1=1",
            "affected_system": "Payment Gateway"
        }

        response = client.post("/api/investigate", json=payload)
        assert response.status_code == 200
        result = response.json()
        assert result["investigation_id"] == "INV-2026-8812"
        assert result["confidence_score"] == 0.8597
        assert result["recommended_playbook_id"] == "PB-SQL-INJECTION"
        assert len(result["recommended_actions"]) == 2
        assert result["recommended_actions"][0]["status"] == "RECOMMENDED"
