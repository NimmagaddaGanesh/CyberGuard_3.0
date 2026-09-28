"""Groq LLM Service for fast inference and structured investigation responses."""
import json
import logging
from typing import Any, Dict, List, Optional
from groq import Groq

from cyberguard.config import settings
from cyberguard.models.investigation import InvestigationResponse
from cyberguard.services.context_synthesizer import SynthesizedContext
from cyberguard.services.prompt_builder import PromptBuilder

logger = logging.getLogger(__name__)


class GroqService:
    """Service handling interactions with the Groq API for incident analysis."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, client: Optional[Groq] = None):
        self.api_key = api_key or settings.GROQ_API_KEY
        self.model = model or settings.GROQ_MODEL
        self._client = client

    def get_client(self) -> Groq:
        """Lazily initialize and return the Groq client."""
        if self._client is None:
            if not self.api_key:
                raise ValueError("GROQ_API_KEY is not configured in the environment.")
            self._client = Groq(api_key=self.api_key)
        return self._client

    def investigate(
        self,
        alert_title: str,
        raw_logs: Optional[str] = "",
        affected_system: Optional[str] = None,
        historical_context: Optional[Any] = None,
        temperature: float = 0.1
    ) -> InvestigationResponse:
        """Invokes Groq LLM with structured JSON output to analyze an alert."""
        client = self.get_client()
        system_prompt = PromptBuilder.get_system_prompt()
        user_prompt = PromptBuilder.build_user_prompt(
            alert_title=alert_title,
            raw_logs=raw_logs,
            affected_system=affected_system,
            historical_context=historical_context
        )

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=temperature
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("Groq returned an empty response.")

        parsed_data = json.loads(content)
        return InvestigationResponse.model_validate(parsed_data)

    def investigate_with_context(
        self,
        context: SynthesizedContext,
        temperature: float = 0.1
    ) -> InvestigationResponse:
        """Convenience method accepting a SynthesizedContext directly."""
        alert_data = context.current_alert
        return self.investigate(
            alert_title=alert_data.get("alert_title", "Unknown Alert"),
            raw_logs=alert_data.get("raw_logs", ""),
            affected_system=alert_data.get("affected_system"),
            historical_context=context,
            temperature=temperature
        )


# Global singleton instance
groq_service = GroqService()
