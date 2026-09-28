"""Groq LLM Service for fast inference and structured investigation responses."""
import json
import logging
from typing import Any, Dict, List, Optional
from groq import Groq
from backend.config import settings
from backend.models.investigation import InvestigationResponse
from backend.services.context_synthesizer import SynthesizedContext
from backend.services.prompt_builder import PromptBuilder

logger = logging.getLogger(__name__)


class GroqService:
    """Service handling interactions with the Groq API for incident analysis.
    
    Does NOT interact with Hindsight or any memory platform directly.
    Accepts historical context supplied by the caller.
    """

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
        ctx: SynthesizedContext,
        temperature: float = 0.1
    ) -> InvestigationResponse:
        """Convenience method to investigate directly from a SynthesizedContext."""
        return self.investigate(
            alert_title=ctx.current_alert.get("alert_title", "Unknown Alert"),
            raw_logs=ctx.current_alert.get("raw_logs", ""),
            affected_system=ctx.current_alert.get("affected_system"),
            historical_context=ctx,
            temperature=temperature
        )


# Global default instance
groq_service = GroqService()
