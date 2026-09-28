"""Tests for Groq response structure, Pydantic schemas, and PromptBuilder.

These tests execute without making real API calls, ensuring no API credits are consumed.
"""
import json
import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock
from backend.models.investigation import (
    InvestigationResponse,
    ActionItem
)
from backend.services.prompt_builder import PromptBuilder
from backend.services.groq_service import GroqService


@pytest.fixture
def valid_response_data():
    return {
        "investigation_id": "INV-2026-8812",
        "summary": "High-confidence distributed SSH credential stuffing attack detected.",
        "root_cause_analysis": "Credential stuffing via leaked authentication dumps.",
        "confidence_score": 0.912,
        "recommended_actions": [
            {
                "priority": 1,
                "action": "Enforce MFA and rotate session keys",
                "historical_efficacy": "91.2% Bayesian Confidence (16/18 successes)",
                "status": "RECOMMENDED"
            },
            {
                "priority": 2,
                "action": "Single IP blocking",
                "historical_efficacy": "28.0% Bayesian Confidence (8/10 failures)",
                "status": "DISCOURAGED_WARNING",
                "warning": "Historical memory shows attackers easily bypass single IP blocks using residential proxy rotation."
            }
        ],
        "recommended_playbook_id": "PB-003",
        "similar_historical_incidents": ["INC-2026-0042", "INC-2026-0108"]
    }


def test_investigation_response_valid_schema(valid_response_data):
    """Verify that a compliant dictionary validates successfully into InvestigationResponse."""
    resp = InvestigationResponse.model_validate(valid_response_data)
    assert resp.investigation_id == "INV-2026-8812"
    assert resp.summary.startswith("High-confidence")
    assert resp.confidence_score == 0.912
    assert len(resp.recommended_actions) == 2
    assert resp.recommended_actions[0].status == "RECOMMENDED"
    assert resp.recommended_actions[1].warning is not None
    assert resp.recommended_playbook_id == "PB-003"
    assert len(resp.similar_historical_incidents) == 2


@pytest.mark.parametrize("invalid_score", [-0.1, 1.5, 2.0])
def test_confidence_score_range_validation(valid_response_data, invalid_score):
    """Verify confidence_score is bounded between 0.0 and 1.0."""
    invalid_data = valid_response_data.copy()
    invalid_data["confidence_score"] = invalid_score
    with pytest.raises(ValidationError) as exc_info:
        InvestigationResponse.model_validate(invalid_data)
    assert "confidence_score" in str(exc_info.value)


def test_required_fields_missing(valid_response_data):
    """Verify that missing critical fields raises ValidationError."""
    incomplete_data = valid_response_data.copy()
    del incomplete_data["root_cause_analysis"]

    with pytest.raises(ValidationError) as exc_info:
        InvestigationResponse.model_validate(incomplete_data)
    assert "root_cause_analysis" in str(exc_info.value)


def test_prompt_builder_no_memory():
    """Verify that PromptBuilder explicitly notes absence of memory for cold start."""
    prompt = PromptBuilder.build_user_prompt(
        alert_title="Unrecognized token usage",
        raw_logs="HTTP 401 Unauthorized bursts",
        historical_context=None
    )
    assert "NO HISTORICAL EVIDENCE AVAILABLE" in prompt
    assert "Unrecognized token usage" in prompt


def test_prompt_builder_with_memory():
    """Verify that PromptBuilder embeds historical incident context when provided."""
    memories = [
        {"incident_id": "INC-001", "root_cause": "Leaked bearer token"}
    ]
    prompt = PromptBuilder.build_user_prompt(
        alert_title="Token anomaly",
        raw_logs="HTTP 403 Forbidden",
        historical_context=memories
    )
    assert "INC-001" in prompt
    assert "Leaked bearer token" in prompt
    assert "Ground your analysis in this historical experience" in prompt


def test_groq_service_investigate_mocked(valid_response_data):
    """Verify GroqService.investigate parses LLM output into InvestigationResponse without network calls."""
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(valid_response_data)
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_response

    service = GroqService(api_key="mock_key", client=mock_client)
    result = service.investigate(
        alert_title="Suspicious SSH connections",
        raw_logs="Failed password for invalid user admin",
        historical_context=[{"incident_id": "INC-2026-0042"}]
    )

    assert isinstance(result, InvestigationResponse)
    assert result.investigation_id == "INV-2026-8812"
    assert result.confidence_score == 0.912
    assert result.recommended_actions[0].action == "Enforce MFA and rotate session keys"
    assert mock_client.chat.completions.create.called
