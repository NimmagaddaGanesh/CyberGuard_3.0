"""
Direct Async Python Unit Test Runner for CyberGuard Backend
"""
import sys
import os
import asyncio

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import httpx
from app.main import app

async def run_all_tests_async():
    print("Executing CyberGuard Backend Unit Tests...")
    
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Test 1: Root endpoint
        res1 = await client.get("/")
        assert res1.status_code == 200, f"Root endpoint failed: {res1.text}"
        assert res1.json()["status"] == "online"
        print("PASS: Root endpoint test passed.")

        # Test 2: Investigation endpoint
        payload = {
            "raw_input": "2026-09-28T09:12:00Z auth.fail 198.51.100.24 user=root count=120 ssh brute force",
            "source": "RAW_SYSLOG_WEBHOOK"
        }
        res2 = await client.post("/api/investigate", json=payload)
        assert res2.status_code == 200, f"Investigation endpoint failed: {res2.text}"
        data = res2.json()
        assert "recommendation" in data
        assert data["recommendation"]["resolution_id"] == "RES-SSH-001"
        assert data["recommendation"]["confidence"] >= 0.50
        print(f"PASS: Investigation endpoint test passed (Resolution: {data['recommendation']['resolution_id']}, Confidence: {data['recommendation']['confidence']}).")

        # Test 3: Feedback submission endpoint
        fb_payload = {
            "resolution_id": "RES-SSH-001",
            "incident_id": "INC-2026-0042",
            "feedback_outcome": "success"
        }
        res3 = await client.post("/api/feedback", json=fb_payload)
        assert res3.status_code == 200, f"Feedback endpoint failed: {res3.text}"
        fb_data = res3.json()
        assert fb_data["memory_updated"] is True
        assert fb_data["metrics"]["times_used"] > 0
        print(f"PASS: Feedback submission endpoint test passed (Times Used: {fb_data['metrics']['times_used']}, Success Rate: {fb_data['metrics']['success_rate']}).")

    print("\nALL BACKEND UNIT TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    asyncio.run(run_all_tests_async())
