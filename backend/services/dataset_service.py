"""Dataset Service for loading, querying, and managing the 1000-incident dataset."""
import json
import logging
import random
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.models.incident import IncidentAlert, IncidentRecord

logger = logging.getLogger(__name__)

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent.parent.parent / "cyberguard_incidents_1000.json"


class DatasetService:
    """Service to load and query the primary CyberGuard 1000-incident dataset."""

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = dataset_path or DEFAULT_DATASET_PATH
        self._incidents: Optional[List[IncidentRecord]] = None
        self._incidents_by_id: Optional[Dict[str, IncidentRecord]] = None

    def load_incidents(self) -> List[IncidentRecord]:
        """Loads and validates all incidents from the primary dataset file."""
        if self._incidents is not None:
            return self._incidents

        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Primary dataset not found at: {self.dataset_path}")

        logger.info(f"Loading incidents from {self.dataset_path}")
        with open(self.dataset_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            raise ValueError(f"Dataset root must be a JSON array, got {type(raw_data).__name__}")

        validated_incidents: List[IncidentRecord] = []
        by_id: Dict[str, IncidentRecord] = {}

        for record in raw_data:
            incident = IncidentRecord.model_validate(record)
            validated_incidents.append(incident)
            by_id[incident.incident_id] = incident

        self._incidents = validated_incidents
        self._incidents_by_id = by_id
        return self._incidents

    def get_incident_by_id(self, incident_id: str) -> Optional[IncidentRecord]:
        """Retrieves a specific incident by its ID."""
        if self._incidents_by_id is None:
            self.load_incidents()
        return self._incidents_by_id.get(incident_id)

    def get_random_incident(self) -> IncidentRecord:
        """Picks a random incident from the dataset."""
        incidents = self.load_incidents()
        return random.choice(incidents)

    def get_statistics(self) -> Dict[str, Any]:
        """Returns statistical overview of the dataset."""
        incidents = self.load_incidents()
        total = len(incidents)
        categories = dict(Counter(inc.category for inc in incidents))
        severities = dict(Counter(inc.severity for inc in incidents))
        incident_types = dict(Counter(inc.incident_type for inc in incidents))
        playbooks = dict(Counter(inc.recommended_playbook for inc in incidents))

        return {
            "dataset_file": self.dataset_path.name,
            "total_incidents": total,
            "categories": categories,
            "traditional_cyber": categories.get("Traditional Cyber", 0),
            "ai_security": categories.get("AI Security", 0),
            "severities": severities,
            "unique_incident_types_count": len(incident_types),
            "incident_types": incident_types,
            "playbooks_count": len(playbooks),
            "playbooks": playbooks
        }


# Global default instance
dataset_service = DatasetService()
