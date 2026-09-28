"""Hindsight Memory Service.

To be connected in Phase 4 when teammate provides Hindsight Cloud details.
No alternative vector databases or fake memory implementations are allowed.
"""


class HindsightService:
    """Interface for Hindsight Cloud Memory operations."""

    def __init__(self):
        pass

    async def recall(self, query: str):
        """Recall historical memories from Hindsight Cloud (Phase 4)."""
        raise NotImplementedError("Hindsight integration will be implemented in Phase 4.")

    async def retain(self, memory_type: str, content: dict):
        """Retain feedback/lessons into Hindsight Cloud (Phase 4)."""
        raise NotImplementedError("Hindsight integration will be implemented in Phase 4.")


hindsight_service = HindsightService()
