# CyberGuard — Memory-Powered AI Incident Response Agent

CyberGuard is a memory-powered AI incident response assistant for modern Security Operations Centers (SOCs). It leverages Hindsight Cloud persistent memory and Groq fast LLM inference to transform historical incidents, resolutions, and postmortems into actionable real-time guidance.

## Architecture

```
Incident / Alert
    ↓
Hindsight Memory Recall
    ↓
Historical incidents / resolutions / playbooks / lessons learned
    ↓
Groq LLM
    ↓
Incident Response Recommendation
    ↓
Analyst Feedback
    ↓
Hindsight Memory Retain
    ↓
Future Recall
```

## Tech Stack
- **Backend:** FastAPI (Python 3.11+)
- **LLM Inference:** Groq SDK
- **Long-Term Memory:** Hindsight Cloud
- **Dashboard:** Streamlit
