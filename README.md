# CyberGuard 3.0: Memory-Augmented AI Incident Response Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2016-black.svg?logo=next.js)](https://nextjs.org)
[![Hindsight Cloud](https://img.shields.io/badge/Memory-Hindsight%20Cloud-6366F1.svg)](https://hindsight.vectorize.io)
[![Groq LLM](https://img.shields.io/badge/Inference-Groq%20Cloud-F55036.svg)](https://groq.com)

**CyberGuard 3.0** is an enterprise-grade autonomous Security Operations Center (SOC) agent. It integrates long-term vector memory recall via **Vectorize Hindsight Cloud**, mathematical **Laplace-smoothed Bayesian confidence scoring**, high-speed LLM inference via **Groq**, and a **multi-tier adaptive escalation engine** across 18 enterprise and AI infrastructure threat scenarios.

---

## 🚀 Key Features

- **🧠 Long-Term Episodic Memory (Hindsight Cloud):** Recalls historical security incident resolutions and continuously writes back validated analyst feedback into dedicated memory banks (`cyberguard-soc`).
- **📊 Bayesian Confidence Engine:** Combines semantic vector similarity with historical success rates using Laplace smoothing to eliminate cold-start bias:
  $$\text{Confidence} = w_{\text{sem}} \cdot \text{Similarity} + w_{\text{emp}} \cdot \left(\frac{\text{Successes} + 1}{\text{Trials} + 2}\right)$$
- **🛡️ 18 Enterprise & AI Threat Playbooks:** Covers traditional enterprise attacks (Ransomware, SSH Brute Force, SQL Injection, DDoS) and emerging AI/LLM infrastructure threats (Prompt Injection, Agent Goal Hijacking, Tool Abuse).
- **⚡ Multi-Tier Escalation Architecture:**
  - **Tier-1:** Automated operational containment playbook.
  - **Tier-2:** Alternate containment playbook deployed upon first escalation.
  - **Tier-3 (Escalation Ceiling):** Automated scripts freeze; **Groq LLM** synthesizes an emergency SEV-0 Incident Commander crisis dossier with live RAM/air-gap directives.
- **🔒 Resolution Lockout:** Automatically disables escalation buttons once a playbook solution has been verified as successful by an analyst.
- **💻 Interactive SOC Dashboard:** Responsive dark/light theme web interface built with **Next.js 16** (Turbopack) and Tailwind CSS.

---

## 🏗️ System Architecture

```text
                                  ┌──────────────────────────────┐
                                  │   Raw Syslog / Threat Alert  │
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ SEGMENT 1: ALERT INGESTION & NORMALIZATION                                                     │
│ Parses raw syslog lines, JSON payloads, or dropdown presets into canonical threat signatures    │
└────────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ SEGMENT 2: HINDSIGHT MEMORY RETRIEVAL                                                          │
│ Queries Hindsight Cloud bank ('cyberguard-soc') via arecall() to fetch historical resolutions  │
└────────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ SEGMENT 3: BAYESIAN SCORER & CONTEXT SYNTHESIS                                                 │
│ Computes Laplace-smoothed empirical confidence score & selects optimal mitigation playbook     │
└────────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                                 │
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ SEGMENT 4: GROQ COPILOT LLM ENGINE                                                             │
│ Generates triage rationales & JSON responses using openai/gpt-oss-120b on Groq Cloud          │
└────────────────────────────────────────────────┬───────────────────────────────────────────────┘
                                                 │
                         ┌───────────────────────┴───────────────────────┐
                         ▼                                               ▼
               [ ✓ Mark Resolved ]                              [ ✕ ESCALATE ]
                         │                                               │
                         ▼                                               ▼
          Increment Success Metrics                    ⚠️ Level 1: Tier-2 Alternate Playbook
          Commit 'success' to Hindsight                                  │
          🔒 Lock Escalation Controls                                     ▼ (Escalated Again)
                                                       🚨 Level 2: Groq SEV-0 Crisis Dossier
                                                       Freeze automation & dispatch War Room
```

---

## 📋 Comprehensive Playbook Catalog (18 Scenarios)

All playbooks are structured with primary tactical steps and alternate escalation procedures in `backend/llm/data/playbooks/`:

| Playbook | Scenario | Primary Action | Alternate Escalation Action | Specialist Tier |
|---|---|---|---|---|
| `PB-001.md` | **SSH Brute Force** | Rate-limit auth attempts & firewall IP drop | Zero-Trust Bastion Lockdown | Tier-2 Linux Security |
| `PB-002.md` | **Ransomware** | Host network isolation & terminate encryptor | Enterprise Blast-Radius Quarantine | Tier-3 DFIR & Disaster Recovery |
| `PB-003.md` | **Credential Stuffing** | Progressive login delay & IP challenge | Mass Reset & TLS JA3/JA4 Fingerprinting | Tier-2 Fraud Prevention |
| `PB-004.md` | **Prompt Injection** | Sanitize inputs & strip override tags | Dual-LLM Guardrail & Sandbox Agent | AI Red Team Safety Officer |
| `PB-005.md` | **Agent Tool Abuse** | Token bucket rate limiting on APIs | Fraud Circuit Breaker & Behavioral Blacklist | FinSecOps & API Security |
| `PB-006.md` | **SQL Injection** | Deploy Cloud WAF virtual patch | Database Exfiltration Lockdown & Read-Only | Tier-2 AppSec & Database Forensics |
| `PB-007.md` | **Phishing** | Search & purge campaign emails across inboxes | Adversary-in-the-Middle (AiTM) Token Defense | Tier-2 Identity & Endpoint Hunting |
| `PB-008.md` | **Malware Detection** | EDR host isolation & kill process tree | Living-off-the-Land (LotL) Deep Hunt | Tier-2 Reverse Engineering |
| `PB-009.md` | **Port Scanning** | Perimeter firewall drop rules | Perimeter Reconnaissance Evasion & Honeynet | Tier-2 Perimeter Security |
| `PB-010.md` | **DDoS Attack** | BGP Anycast scrubbing & L7 challenge | Origin Shielding & Carrier RTBH Blackholing | Tier-3 Cloud Reliability |
| `PB-011.md` | **Unauthorized Access**| Terminate active user web & API sessions | Privilege Escalation Quarantine & STS Reset | Tier-2 Cloud IAM Response |
| `PB-012.md` | **Cloud IAM Misconfig** | Detach wildcard policies (`*:*`) | Infrastructure-as-Code (IaC) Drift Rollback | Tier-2 Cloud DevSecOps |
| `PB-013.md` | **Agent Goal Hijack** | Terminate divergent agent execution loop | Deterministic Execution & Human Gateway | Autonomous Systems SecOps |
| `PB-014.md` | **Unsafe Tool Invocation**| Reject dangerous system calls (`rm`, `exec`)| Ephemeral Micro-VM Sandboxing | AI Infrastructure Security |
| `PB-015.md` | **Excessive Agent Perms**| Apply Least-Privilege Agent Scope (LPAS) | Just-In-Time (JIT) 5-Min Token Brokerage | AI Governance & Cloud IAM |
| `PB-016.md` | **Sensitive Data Leak** | Redact PII/secrets with regex & Presidio | Vector Store / RAG Poisoning Quarantine | Data Privacy & Cryptography |
| `PB-017.md` | **Model Manipulation** | Adversarial input perturbation filtering | Model Checkpoint Rollback & Attestation | MLOps Security Integrity |
| `PB-018.md` | **Generic Security** | Isolate affected host & collect volatile logs | Zero-Trust Triage & Threat Surface Quarantine | Senior SOC Lead & Threat Intel |

---

## 🛠️ Getting Started

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** & npm
- Valid **Hindsight Cloud** API Key & Bank ID
- Valid **Groq Cloud** API Key

---

### 1. Backend Setup

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Configure environment variables (.env)
cp .env.example .env
```

Ensure your `backend/.env` file contains:
```env
APP_NAME="CyberGuard API Engine"
HOST=0.0.0.0
PORT=8000

# Hindsight Cloud Credentials
HINDSIGHT_API_KEY=your_hindsight_api_key
HINDSIGHT_BASE_URL=https://api.hindsight.vectorize.io
HINDSIGHT_BANK_ID=cyberguard-soc

# Groq Cloud Credentials
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=openai/gpt-oss-120b

# Bayesian Scorer Weights
WEIGHT_SEMANTIC=0.40
WEIGHT_EMPIRICAL=0.60
```

Start the FastAPI server:
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be available at: **`http://localhost:8000/docs`**

---

### 2. Frontend Setup

```bash
cd frontend

# Install Node dependencies
npm install

# Start development server
npm run dev
```
Open **`http://localhost:3000`** in your browser.

---

## 🧪 Automated Testing

Run the full end-to-end integration test suite (validates live Hindsight recall, Bayesian scoring, Groq copilot formatting, and feedback retain writeback):

```bash
python backend/tests/run_tests.py
```

---

## 📁 Repository Structure

```text
CyberGuard/
├── backend/
│   ├── app/                      # 5-Segment Modular Architecture
│   │   ├── segment_1_ingestion/  # Alert Ingestion & Parsing
│   │   ├── segment_2_hindsight_memory/ # Hindsight Client & 18 Resolution Profiles
│   │   ├── segment_3_bayesian_scorer/  # Laplace-Smoothed Bayesian Engine
│   │   ├── segment_4_copilot_llm/      # Groq LLM Rationale & Deep Dossiers
│   │   ├── segment_5_memory_updater/   # Analyst Feedback & Escalation Worker
│   │   ├── models/schemas.py     # Pydantic Schemas
│   │   ├── config.py             # Settings & Environment Parser
│   │   └── main.py               # FastAPI App & Endpoints
│   ├── llm/
│   │   └── data/playbooks/       # 18 Markdown Operational Playbooks (PB-001 - PB-018)
│   ├── tests/                    # End-to-End Test Suite
│   └── requirements.txt
├── frontend/
│   ├── app/page.tsx              # Interactive SOC Dashboard (Next.js 16)
│   ├── lib/                      # API Client & Threat Presets
│   └── types/                    # TypeScript Interfaces
├── PROJECT_STRUCTURE.md          # Architectural Layout Details
└── README.md                     # Platform Documentation
```

---

## 📄 License
This project is licensed under the MIT License.
