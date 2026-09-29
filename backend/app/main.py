"""
CyberGuard FastAPI Engine Main Entrypoint
Exposes POST /api/investigate and POST /api/feedback endpoints matching the React Frontend.
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.models.schemas import (
    AlertInputPayload,
    InvestigationResult,
    FeedbackSubmission,
    FeedbackResponse
)
from app.segment_1_ingestion.ingestor import AlertIngestor
from app.segment_2_hindsight_memory.hindsight_client import hindsight_service
from app.segment_3_bayesian_scorer.bayesian_scorer import BayesianScorer
from app.segment_4_copilot_llm.copilot_engine import copilot_service
from app.segment_5_memory_updater.memory_updater import memory_updater_service

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Memory-Powered AI Incident Response Agent Backend"
)

# Enable CORS for Frontend Next.js integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows Next.js frontend (http://localhost:3000)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": settings.APP_NAME,
        "hindsight_configured": bool(settings.HINDSIGHT_API_KEY),
        "groq_configured": bool(settings.GROQ_API_KEY)
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/api/investigate", response_model=InvestigationResult)
async def investigate_alert(payload: AlertInputPayload):
    """
    Main Investigation Endpoint:
    Segment 1 (Ingest) -> Segment 2 (Memory Recall) -> Segment 3 (Bayesian Scoring) -> Segment 4 (Copilot JSON Output)
    """
    try:
        # Segment 1: Ingestion & Normalization
        scenario, severity, metadata = AlertIngestor.parse_raw_input(payload.raw_input)

        # Segment 2: Hindsight Memory Retrieval
        memory_profile = await hindsight_service.query_memory(scenario, payload.raw_input)

        # Segment 3: Bayesian Scoring & Context Synthesis
        synthesized = BayesianScorer.synthesize_context(scenario, memory_profile, severity)

        # Segment 4: LLM Copilot Final Formatting
        result = await copilot_service.generate_investigation(
            raw_input=payload.raw_input,
            source=payload.source or "RAW_SYSLOG_WEBHOOK",
            synthesized_context=synthesized
        )

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")

@app.post("/api/feedback", response_model=FeedbackResponse)
async def submit_feedback(submission: FeedbackSubmission):
    """
    Analyst Feedback Endpoint:
    Segment 5 (Memory Update Worker) -> Recalculate Bayesian Weights & Commit to Hindsight
    """
    try:
        if submission.feedback_outcome not in ["success", "failed"]:
            raise HTTPException(status_code=400, detail="feedback_outcome must be 'success' or 'failed'")

        result = await memory_updater_service.process_feedback(submission)
        return result
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feedback writeback failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
