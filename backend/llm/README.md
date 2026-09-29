# CyberGuard LLM & Bayesian Investigation Module

This module provides the complete AI incident response pipeline:
1. **Memory Retrieval:** Finds relevant historical incidents from institutional memory.
2. **Bayesian Confidence:** Computes empirical efficacy and Bayesian confidence scores.
3. **Groq LLM Reasoning:** Synthesizes root cause analysis and produces structured action recommendations with failure warnings.

---

## 🚀 How to Integrate into Your Backend Route (2 Lines)

In your backend API controller (e.g. `main.py` or router):

```python
from backend.llm import investigate_incident, IncidentAlert

@app.post("/api/investigate")
def investigate(alert: IncidentAlert):
    # Runs the entire investigation pipeline and returns structured output:
    result = investigate_incident(alert)
    return result.model_dump()
```

---

## 📋 Exact Output Format Generated

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

## 🧪 Testing

Run directly from this directory:
```bash
python test_llm.py
```
