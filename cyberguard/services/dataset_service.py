"""Dataset Service for loading, querying, and managing the 1000-incident dataset."""
import json
import logging
import random
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import ValidationError

from cyberguard.config import settings
from cyberguard.models.incident import IncidentAlert, IncidentRecord

logger = logging.getLogger(__name__)

DEFAULT_DATASET_PATH = Path(settings.CYBERGUARD_DATASET_PATH)


def validate_dataset(dataset_path: Path) -> dict:
    """Validates:
    - Exactly 1,000 incidents
    - Exactly 700 Traditional Cyber (70%)
    - Exactly 300 AI Security (30%)
    - 1,000 unique incident IDs
    - Severity in Low | Medium | High | Critical
    - Efficacy scores in 0.0 - 1.0
    - Valid structural Pydantic validation for all records
    """
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Dataset root must be a JSON array, got {type(data).__name__}")

    total_count = len(data)
    if total_count != 1000:
        raise ValueError(f"Expected exactly 1000 incidents, found {total_count}")

    traditional_count = 0
    ai_security_count = 0
    seen_ids = set()

    for idx, raw_record in enumerate(data):
        # 1. Pydantic validation
        try:
            record = IncidentRecord.model_validate(raw_record)
        except ValidationError as e:
            raise ValueError(f"Record at index {idx} failed Pydantic validation: {e}") from e

        # 2. Unique ID check
        if record.incident_id in seen_ids:
            raise ValueError(f"Duplicate incident_id found: {record.incident_id} at index {idx}")
        seen_ids.add(record.incident_id)

        # 3. Category count
        if record.category == "Traditional Cyber":
            traditional_count += 1
        elif record.category == "AI Security":
            ai_security_count += 1

        # 4. Resolution records validation
        if not record.resolutions_tried:
            raise ValueError(f"Incident {record.incident_id} must have at least one resolution attempt")

        for res in record.resolutions_tried:
            if res.efficacy_score is not None:
                if not (0.0 <= res.efficacy_score <= 1.0):
                    raise ValueError(f"Invalid efficacy_score {res.efficacy_score} in incident {record.incident_id}")

    # 5. Distribution checks
    if traditional_count != 700:
        raise ValueError(f"Expected exactly 700 Traditional Cyber incidents, got {traditional_count}")
    if ai_security_count != 300:
        raise ValueError(f"Expected exactly 300 AI Security incidents, got {ai_security_count}")

    return {
        "status": "VALID",
        "total_incidents": total_count,
        "traditional_cyber_count": traditional_count,
        "ai_security_count": ai_security_count,
        "unique_ids_count": len(seen_ids)
    }


class DatasetService:
    """Service to load and query the primary CyberGuard 1000-incident dataset."""

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = Path(dataset_path) if dataset_path else DEFAULT_DATASET_PATH
        self._incidents: Optional[List[IncidentRecord]] = None
        self._incidents_by_id: Optional[Dict[str, IncidentRecord]] = None

    def load_incidents(self) -> List[IncidentRecord]:
        """Loads and validates all incidents from the primary dataset file."""
        if self._incidents is not None:
            return self._incidents

        if not self.dataset_path.exists():
            # Fallback check relative to package parent
            alt_path = Path(__file__).resolve().parent.parent.parent / "cyberguard_incidents_1000.json"
            if alt_path.exists():
                self.dataset_path = alt_path
            else:
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

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistical distribution of categories and severities."""
        incidents = self.load_incidents()
        categories = Counter(i.category for i in incidents)
        severities = Counter(i.severity for i in incidents)
        types = Counter(i.incident_type for i in incidents)

        return {
            "total_incidents": len(incidents),
            "category_distribution": dict(categories),
            "severity_distribution": dict(severities),
            "top_incident_types": dict(types.most_common(10)),
        }

    def convert_to_alert(self, incident: IncidentRecord) -> IncidentAlert:
        """Converts an existing incident record into an incoming IncidentAlert simulation."""
        raw_logs = f"Alert trigger on system: {incident.affected_system}. Symptoms: {', '.join(incident.symptoms)}. IOCs: {', '.join(incident.indicators_of_compromise)}."
        return IncidentAlert(
            alert_id=f"ALT-{incident.incident_id}",
            alert_title=f"Detected {incident.incident_type} on {incident.affected_system}",
            raw_logs=raw_logs,
            affected_system=incident.affected_system,
            extensions=incident.extensions
        )


# Global singleton instance
dataset_service = DatasetService()
