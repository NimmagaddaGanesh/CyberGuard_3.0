# Segment 4: LLM Copilot & Reasoning Engine
> **Owner:** AI / Prompt Engineer

## Responsibilities
This segment is responsible for calling Groq LLM API (`openai/gpt-oss-120b` or `qwen/qwen3-32b`) to refine recommendations, output rationale, and structure responses.

### Key Capabilities:
* Integration with Groq fast-inference LLM backend.
* JSON mode validation for structured output.
* Fallback prompt reasoning when API key is pending.

### Files:
* `copilot_engine.py`: Interacts with Groq client or fallback synthesizer to produce final `InvestigationResult` payload.
