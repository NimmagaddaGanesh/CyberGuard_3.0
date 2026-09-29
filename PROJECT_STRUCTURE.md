# CyberGuard Project Architecture & Structural Layout

This document details the refined, clean structural layout of the CyberGuard platform. All legacy duplicate and orphaned folders (such as `cyberguard-memory/backend`) have been removed.

---

## 📁 Repository Root Layout

```text
CyberGuard/
├── backend/                  # FastAPI Core Engine & LLM Playbook Service
│   ├── app/                  # Modular 5-Segment CyberGuard SOC Pipeline
│   │   ├── models/           # Pydantic Schemas for Ingestion, Recall & Feedback
│   │   ├── segment_1_ingestion/          # Syslog & Telemetry Ingestion / Normalization
│   │   ├── segment_2_hindsight_memory/   # Hindsight Cloud Client & 18 Resolution Profiles
│   │   ├── segment_3_bayesian_scorer/    # Laplace-Smoothed Bayesian Confidence Engine
│   │   ├── segment_4_copilot_llm/        # Groq LLM Rationale Synthesis
│   │   ├── segment_5_memory_updater/     # Analyst Feedback & Escalation Writeback Worker
│   │   ├── config.py         # App Environment Configuration (Hindsight, Groq, Ports)
│   │   └── main.py           # FastAPI Application Entrypoint & CORS Middleware
│   ├── llm/                  # LLM Service & Structured Playbook Repository
│   │   ├── data/
│   │   │   └── playbooks/    # All 18 Markdown Operational Playbooks (PB-001 to PB-018)
│   │   ├── context_builder_service.py   # Historical Context Builder & Heuristic Matcher
│   │   ├── cyberguard_incidents_1000.json # 1,000 Verified Incident Records
│   │   ├── llm_service.py    # Standalone LLM Investigation Service
│   │   └── test_llm.py       # LLM Service Unit Tests
│   ├── seeds/                # Initial Seeding Scripts for Hindsight Memory Banks
│   │   ├── seed_hindsight.py
│   │   └── synthetic_incidents.json
│   ├── tests/                # Automated End-to-End API Integration Tests
│   │   ├── run_tests.py      # Automated Recall, Scorer, and Retain Test Suite
│   │   └── test_api.py
│   ├── requirements.txt      # Python Dependencies (fastapi, uvicorn, hindsight-client, groq)
│   └── .env                  # Live Credentials (Hindsight Cloud & Groq API)
│
├── frontend/                 # Next.js 16 (Turbopack) Interactive SOC Dashboard
│   ├── app/
│   │   ├── globals.css       # Tailwind CSS & Dark/Light Theme Styles
│   │   ├── layout.tsx        # Dashboard Layout & Font Provider
│   │   └── page.tsx          # Real-time Investigation, Playbook & Escalation Interface
│   ├── lib/
│   │   ├── api.ts            # REST Client (/api/investigate & /api/feedback)
│   │   └── mockData.ts       # 18 Threat Scenario Categories & Dropdown Presets
│   ├── types/
│   │   └── cyberguard.ts     # TypeScript Interfaces for Incidents, Feedback & Metrics
│   ├── package.json          # Node.js Dependencies (Next.js 16, React 19, Tailwind)
│   └── .env.local            # Frontend API Base URL (http://localhost:8000/api)
│
└── PROJECT_STRUCTURE.md      # Platform Architecture & Layout Specification
```

---

## 🛡️ Playbook Repository (`backend/llm/data/playbooks/`)

All 18 threat scenarios are documented in full operational markdown format:

| Playbook File | Threat Scenario | Containment Domain | Alternate Escalation Route |
|---|---|---|---|
| `PB-001.md` | **SSH Brute Force** | Identity & Access Defense | Zero-Trust Bastion Lockdown |
| `PB-002.md` | **Ransomware** | Endpoint & Storage Containment | Enterprise Blast-Radius Quarantine |
| `PB-003.md` | **Credential Stuffing** | Authentication & Fraud Prevention | Mass Credential Reset & TLS Fingerprinting |
| `PB-004.md` | **Prompt Injection** | AI System Defense | Dual-LLM Guardrail & Sandboxed Agent |
| `PB-005.md` | **Agent Tool Abuse** | AI API Rate & Resource Defense | Fraud Circuit Breaker & Behavioral Blacklisting |
| `PB-006.md` | **SQL Injection** | Application & Database Security | Database Exfiltration Lockdown |
| `PB-007.md` | **Phishing** | Email & Identity Defense | Adversary-in-the-Middle (AiTM) Token Defense |
| `PB-008.md` | **Malware Detection** | Endpoint Threat Mitigation | Living-off-the-Land (LotL) Deep Threat Hunt |
| `PB-009.md` | **Port Scanning** | Perimeter Network Defense | Perimeter Reconnaissance Evasion |
| `PB-010.md` | **DDoS Attack** | Network & Edge Resilience | Origin Shielding & Carrier Blackholing |
| `PB-011.md` | **Unauthorized Access** | Identity & Session Defense | Privilege Escalation & Lateral Movement Quarantine |
| `PB-012.md` | **Cloud IAM Misconfig** | Cloud Governance & Access Control | Infrastructure-as-Code (IaC) Drift Rollback |
| `PB-013.md` | **Agent Goal Hijacking** | Autonomous Agent Safety | Deterministic Execution Fallback & Human Gateway |
| `PB-014.md` | **Unsafe Tool Invocation**| AI Tool Runtime Protection | Ephemeral Micro-VM Sandboxing |
| `PB-015.md` | **Excessive Agent Perms** | Agent Privilege Governance | Just-In-Time (JIT) Permission Brokerage |
| `PB-016.md` | **Sensitive Data Leakage**| Data Loss Prevention & Privacy | Vector Store / RAG Poisoning Quarantine |
| `PB-017.md` | **Model Manipulation** | Model Integrity & Robustness | Model Checkpoint Rollback & Attestation |
| `PB-018.md` | **Generic Security Event**| General Incident Containment | Zero-Trust Triage & Threat Surface Quarantine |

---

## ⚡ Execution Pipeline

1. **Ingestion (`segment_1_ingestion`)**: Normalizes raw syslog streams or preset dropdown selections into canonical threat scenarios.
2. **Memory Retrieval (`segment_2_hindsight_memory`)**: Performs semantic vector recall against Hindsight Cloud (`cyberguard-soc`) to retrieve historical resolutions and match similarity.
3. **Bayesian Scoring (`segment_3_bayesian_scorer`)**: Computes Laplace-smoothed confidence score combining semantic similarity and historical resolution counts:
   $$\text{Confidence} = w_{\text{sem}} \cdot \text{Similarity} + w_{\text{emp}} \cdot \frac{\text{Successes} + 1}{\text{Trials} + 2}$$
4. **Copilot Rationale (`segment_4_copilot_llm`)**: Synthesizes structured context using Groq LLM (`openai/gpt-oss-120b`).
5. **Human-in-the-Loop Feedback (`segment_5_memory_updater`)**:
   - `[✓ RESOLVED]`: Commits positive resolution into Hindsight Cloud and increments success metrics.
   - `[✗ ESCALATE]`: Penalizes Bayesian weight, commits failure case to Hindsight Cloud, and deploys the **Tier-2 Alternate Escalation Playbook**.
