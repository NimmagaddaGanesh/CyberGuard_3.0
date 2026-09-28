# CyberGuard — AI Incident Response & Memory Reasoning Engine

CyberGuard is a memory-powered AI incident response engine for Security Operations Centers (SOCs). It couples 1,000 empirical historical incidents with Bayesian confidence scoring and Groq high-speed LLM inference to generate structured, actionable incident response triage.

---

## 📦 What's in this Repository (Your AI Role Files)

This repository contains the standalone AI reasoning engine and dataset, structured for seamless integration into any backend:

- **`cyberguard/`** — Core AI & Bayesian reasoning package:
  - `engine.py` — High-level investigation pipeline (`investigate_incident`).
  - `models/` — Canonical Pydantic schemas (`IncidentAlert`, `InvestigationResponse`, etc.).
  - `services/` — Dataset service, historical retriever, Bayesian confidence synthesizer, prompt builder, Groq client.
- **`cyberguard_incidents_1000.json`** — Primary validated dataset: 1,000 incidents (700 Traditional Cyber, 300 AI Security).
- **`data/playbooks/`** — Playbooks (PB-001 to PB-005) for automated remediation guidance.
- **`run_incident_response.py`** — Interactive CLI runner to test and simulate incident investigations directly.
- **`tests/`** — Automated test suite verifying schema compliance, Bayesian mathematics, and dataset integrity.

---

## 🔌 How to Integrate into the Backend

Your teammate can import and run investigations in **2 lines of code**:

```python
from cyberguard import investigate_incident, IncidentAlert

# Call with a dictionary or IncidentAlert:
response = investigate_incident({
    "alert_title": "Detected SQL Injection attempt on web-portal",
    "affected_system": "prod-db-cluster",
    "raw_logs": "UNION SELECT username, password_hash FROM users --"
})

# Access structured fields directly:
print(response.investigation_id)
print(response.summary)
print(response.confidence_score)
print(response.recommended_actions)
print(response.model_dump()) # Clean JSON dictionary for API responses
```

---

## 📋 Standard Response Format

Every investigation produces structured JSON matching this exact schema:

```json
{
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
```

---

## 🚀 Quickstart & Testing

### 1. Install Requirements
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Create a `.env` file from `.env.example`:
```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
```

### 3. Run the Terminal Agent
```bash
# Random incident from the 1,000 dataset:
python run_incident_response.py --random

# Interactive menu:
python run_incident_response.py
```

### 4. Run Automated Tests
```bash
pytest
```
