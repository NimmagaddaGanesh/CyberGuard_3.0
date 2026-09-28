# CyberGuard — AI Incident Response & Memory Reasoning Engine

CyberGuard is a service-oriented AI incident response engine for Security Operations Centers (SOCs). It couples 1,000 empirical historical incidents with Bayesian confidence scoring and Groq high-speed LLM inference to generate structured, actionable incident response triage.

---

## 📦 Service-Oriented Architecture (Your Role Files)

All AI reasoning, retrieval, and LLM inference are cleanly encapsulated into two service-oriented modules:

- **`context_builder_service.py`** — Context Builder Service:
  - Canonical data models (`IncidentAlert`, `IncidentRecord`, `ResolutionRecord`, `SynthesizedContext`).
  - 1,000 incident dataset loading, querying, and validation.
  - Heuristic & semantic similarity retrieval across institutional memory.
  - Bayesian confidence formula:
    $$\text{Confidence} = 0.40 \times \text{Similarity} + 0.60 \times \frac{\text{Successes} + 1}{\text{Trials} + 2}$$
  - Context synthesis separating current alert from historical evidence.

- **`llm_service.py`** — LLM Inference Service:
  - Canonical investigation schemas (`InvestigationResponse`, `ActionItem`).
  - Tier-3 SOC Specialist prompt engineering with strict evidence grounding rules.
  - Groq LLM integration (`openai/gpt-oss-120b`).
  - High-level investigation pipeline (`investigate_incident`).

- **`cyberguard_incidents_1000.json`** — Primary validated dataset (700 Traditional Cyber, 300 AI Security).
- **`data/playbooks/`** — Playbooks (PB-001 to PB-005) for automated remediation guidance.
- **`run_incident_response.py`** — Terminal agent runner to test and simulate incident response.
- **`tests/`** — Automated unit test suite verifying schema validation, Bayesian calculation, and response formats.

---

## 🔌 How Your Teammate Integrates into the Backend

Your teammate can import and run investigations in **2 lines of code**:

```python
from llm_service import investigate_incident, IncidentAlert

# Inside any backend API route / controller:
@app.post("/api/investigate")
def investigate(alert: IncidentAlert):
    response = investigate_incident(alert)
    return response.model_dump()
```

Or access the services individually:
```python
from context_builder_service import context_builder_service
from llm_service import llm_service

# Build memory-backed Bayesian context:
context = context_builder_service.build_context(alert_data)

# Run LLM inference:
response = llm_service.investigate_with_context(context)
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
