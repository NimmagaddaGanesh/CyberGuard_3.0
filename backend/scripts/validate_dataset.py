"""Dataset validator for the primary CyberGuard 1000-incident dataset.

Validates:
- Exactly 1,000 incidents
- Exactly 700 Traditional Cyber (70%)
- Exactly 300 AI Security (30%)
- 1,000 unique incident IDs
- Severity in Low | Medium | High | Critical
- Efficacy scores in 0.0 - 1.0
- Valid structural Pydantic validation for all records
"""
import json
import sys
from pathlib import Path
from pydantic import ValidationError

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.models.incident import IncidentRecord


def validate_dataset(dataset_path: Path) -> dict:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    with open(dataset_path, "r", encoding="utf-8") as f:
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


def main():
    dataset_file = PROJECT_ROOT / "cyberguard_incidents_1000.json"

    print("=== CyberGuard 1000-Incident Dataset Validation ===")
    print(f"Dataset path: {dataset_file}")

    try:
        results = validate_dataset(dataset_file)
        print("\n[SUCCESS] Dataset is 100% valid and verified:")
        for k, v in results.items():
            print(f"  - {k}: {v}")
    except Exception as e:
        print(f"\n[FAILURE] Dataset validation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
