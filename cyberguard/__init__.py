"""CyberGuard - Memory-Powered AI Incident Response Engine.

Provides institutional memory retrieval, Bayesian confidence estimation,
and structured incident response synthesis via Groq LLM.
"""

from cyberguard.models.incident import (
    IncidentAlert,
    IncidentRecord,
    ResolutionRecord,
    MemoryObject,
    AnalystFeedback
)
from cyberguard.models.investigation import (
    InvestigationResponse,
    ActionItem,
    InvestigationRequest
)
from cyberguard.services.dataset_service import DatasetService, dataset_service
from cyberguard.services.retriever import HistoricalEvidence, LocalDatasetRetriever, local_retriever
from cyberguard.services.context_synthesizer import (
    ContextSynthesizer,
    context_synthesizer,
    SynthesizedContext,
    ActionEvaluation,
    ResolutionSummary
)
from cyberguard.services.prompt_builder import PromptBuilder
from cyberguard.services.groq_service import GroqService, groq_service
from cyberguard.services.notifier import TerminalNotifier, terminal_notifier
from cyberguard.engine import CyberGuardEngine, cyberguard_engine, investigate_incident

__all__ = [
    # Canonical Schemas
    "IncidentAlert",
    "IncidentRecord",
    "ResolutionRecord",
    "MemoryObject",
    "AnalystFeedback",
    "InvestigationResponse",
    "ActionItem",
    "InvestigationRequest",
    # Services
    "DatasetService",
    "dataset_service",
    "HistoricalEvidence",
    "LocalDatasetRetriever",
    "local_retriever",
    "ContextSynthesizer",
    "context_synthesizer",
    "SynthesizedContext",
    "ActionEvaluation",
    "ResolutionSummary",
    "PromptBuilder",
    "GroqService",
    "groq_service",
    "TerminalNotifier",
    "terminal_notifier",
    # Core Engine & Entrypoint
    "CyberGuardEngine",
    "cyberguard_engine",
    "investigate_incident",
]
