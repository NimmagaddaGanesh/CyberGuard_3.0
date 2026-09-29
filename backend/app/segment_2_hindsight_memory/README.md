# Segment 2: Hindsight Memory Store Integration
> **Owner:** Memory Engineer / Backend Lead

## Responsibilities
This folder contains the Hindsight Cloud SDK integration and multi-collection vector memory query logic.

### Memory Collections in Hindsight:
1. **Incident Memory:** Historical IOC fingerprints and alert symptoms.
2. **Resolution Effectiveness:** Historical resolution actions, times used, successful outcomes.
3. **Root Cause Clusters:** Symptom-to-vulnerability statistical mappings.
4. **Playbook Memory:** Standard Operating Procedures.

### Files:
* `hindsight_client.py`: Implements async multi-query lookup against Hindsight API (`https://ui.hindsight.vectorize.io`). Fallbacks to built-in resolution profiles if Hindsight Cloud API key is not configured.
