"""Tests for Groq response structure, Pydantic schemas, and LLMService.

These tests execute without making real API calls, ensuring no API credits are consumed.
"""
import json
import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock
from llm_service import (
    InvestigationResponse,
    ActionItem,
    LLMService,
    SYSTEM_PROMPT,
    build_user_prompt,
)


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
    with pytest.raises(ValidationError):
        InvestigationResponse.model_validate(invalid_data)


def test_action_item_structure(valid_response_data):
    """Verify ActionItem fields."""
    item_data = valid_response_data["recommended_actions"][0]
    action = ActionItem.model_validate(item_data)
    assert action.priority == 1
    assert action.action == "Enforce MFA and rotate session keys"
    assert action.status == "RECOMMENDED"
    assert action.warning is None


def test_action_item_with_warning(valid_response_data):
    """Verify ActionItem with warning."""
    item_data = valid_response_data["recommended_actions"][1]
    action = ActionItem.model_validate(item_data)
    assert action.priority == 2
    assert action.status == "DISCOURAGED_WARNING"
    assert action.warning is not None


def test_system_prompt_contains_json_rules():
    """Verify system prompt contains critical SOC persona and JSON schema requirements."""
    prompt = SYSTEM_PROMPT
    assert "CyberGuard" in prompt
    assert "Senior Tier-3 SOC Incident Response Specialist" in prompt
    assert "JSON RESPONSE SCHEMA" in prompt
    assert "RECOMMENDED" in prompt
    assert "DISCOURAGED_WARNING" in prompt
    assert "investigation_id" in prompt


def test_prompt_builder_handles_empty_context():
    """Verify prompt builder handles empty/None context safely."""
    user_prompt = build_user_prompt(
        alert_title="Test Alert",
        raw_logs="sample logs",
        affected_system="test-sys",
        historical_context=None
    )
    assert "Test Alert" in user_prompt
    assert "No historical institutional memory" in user_prompt


def test_llm_service_mock_call(valid_response_data):
    """Verify LLMService parses valid JSON response into InvestigationResponse."""
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(valid_response_data)
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    mock_client.chat.completions.create.return_value = mock_response

    svc = LLMService(api_key="gsk_dummy", model="test-model", client=mock_client)
    res = svc.investigate(
        alert_title="Test Alert",
        raw_logs="test logs",
        affected_system="host1"
    )

    assert isinstance(res, InvestigationResponse)
    assert res.investigation_id == "INV-2026-8812"
    assert len(res.recommended_actions) == 2
