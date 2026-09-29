"""
Seed Hindsight Cloud Database
Reads synthetic incidents JSON and loads them into Hindsight Cloud collections.
"""
import os
import json
import httpx

HINDSIGHT_API_KEY = os.getenv("HINDSIGHT_API_KEY", "")
HINDSIGHT_BASE_URL = os.getenv("HINDSIGHT_BASE_URL", "https://ui.hindsight.vectorize.io/api/v1")

def seed():
    if not HINDSIGHT_API_KEY:
        print("[Seed] HINDSIGHT_API_KEY is not set. Skipping cloud seeding.")
        return

    with open("backend/seeds/synthetic_incidents.json") as f:
        incidents = json.load(f)

    print(f"[Seed] Ingesting {len(incidents)} incidents into Hindsight Cloud...")
    headers = {"Authorization": f"Bearer {HINDSIGHT_API_KEY}"}
    
    with httpx.Client(timeout=10.0) as client:
        response = client.post(f"{HINDSIGHT_BASE_URL}/ingest", headers=headers, json={"documents": incidents})
        if response.status_code == 200:
            print("[Seed] Successfully seeded Hindsight Cloud memory!")
        else:
            print(f"[Seed Error] Status {response.status_code}: {response.text}")

if __name__ == "__main__":
    seed()
