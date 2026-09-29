"""
CyberGuard Comprehensive Playbook Profiles
Covers all 18 Traditional Cybersecurity and AI/LLM Security scenarios.
Each profile defines:
- Primary Tier-1 Automated Playbook with tactical response steps
- Alternate Tier-2 Escalation Playbook with advanced containment steps
- Dynamic empirical metrics and historical match templates
"""
from typing import Dict, Any

RESOLUTION_PROFILES: Dict[str, Dict[str, Any]] = {
    'SSH Brute Force': {
        'resolution_id': 'PB-SSH-001',
        'resolution': 'Throttle SSH authentication attempts, block attacking IPs via firewall, and enforce MFA for impacted accounts.',
        'response_domain': 'Identity & Access Defense',
        'priority': 'High',
        'rationale': 'Rapid failed SSH logins indicate automated credential guessing against privileged remote access paths.',
        'response_steps': [
            'Rate-limit SSH authentication attempts and inject firewall drop rules for offending source IPs.',
            'Require MFA and trigger automated credential rotation for accounts experiencing repeated failures.',
            'Audit /var/log/auth.log for successful logins and verify authorized public keys.'
        ],
        'confidence': 0.95,
        'times_used': 24,
        'successful_resolutions': 22,
        'alternate_resolution_id': 'PB-SSH-ALT-001',
        'alternate_playbook': 'Zero-Trust Bastion Lockdown: Disable password authentication, restrict SSH to VPN/Bastion hosts, and trigger PAM credential audit.',
        'alternate_steps': [
            'Enforce SSH public-key only authentication and disable PAM password auth on target servers.',
            'Restrict inbound port 22 access exclusively to internal bastion host VPN subnets.',
            'Dispatch Tier-2 Linux Security ticket to inspect system binaries for backdoor SSH keys.'
        ],
        'escalation_tier': 'Tier-2 Linux Security & Identity Specialist',
        'historical_matches': [
            {'incident_id': 'INC-2026-0156', 'similarity': 0.97, 'resolution': 'Throttle login attempts and enforce MFA for impacted SSH accounts.', 'outcome': 'success'},
            {'incident_id': 'INC-2026-0042', 'similarity': 0.91, 'resolution': 'Rate-limit authentication attempts and rotate impacted credentials.', 'outcome': 'success'}
        ]
    },
    'Ransomware': {
        'resolution_id': 'PB-RANSOM-002',
        'resolution': 'Immediately sever network connectivity for affected endpoints, freeze suspicious encrypting processes, and lock shared storage mounts.',
        'response_domain': 'Endpoint & Storage Containment',
        'priority': 'Critical',
        'rationale': 'High-volume file modifications and ransom note drops signal active ransomware encryption requiring instant blast-radius containment.',
        'response_steps': [
            'Trigger automated EDR host network isolation across all identified affected endpoints.',
            'Terminate unsigned processes exhibiting anomalous disk I/O and rapid entropy changes.',
            'Temporarily revoke SMB and NFS network share permissions to prevent lateral file encryption.'
        ],
        'confidence': 0.96,
        'times_used': 15,
        'successful_resolutions': 14,
        'alternate_resolution_id': 'PB-RANSOM-ALT-002',
        'alternate_playbook': 'Enterprise Blast-Radius Quarantine: Invalidate Kerberos tokens, isolate hypervisor cluster, and mount immutable air-gapped backups.',
        'alternate_steps': [
            'Execute domain-wide Kerberos KRBTGT account password reset to halt lateral movement.',
            'Isolate targeted hypervisor cluster and capture volatile RAM snapshots for cryptographic key recovery.',
            'Mount read-only immutable WORM backup volumes and initiate clean disaster recovery pipeline.'
        ],
        'escalation_tier': 'Tier-3 DFIR & Disaster Recovery Incident Commander',
        'historical_matches': [
            {'incident_id': 'INC-2026-0446', 'similarity': 0.96, 'resolution': 'Isolated infected file server and restored volume from snapshot.', 'outcome': 'success'},
            {'incident_id': 'INC-2026-0391', 'similarity': 0.89, 'resolution': 'Terminated encrypter process and blocked C2 IP range.', 'outcome': 'success'}
        ]
    },
    'SQL Injection': {
        'resolution_id': 'PB-SQLI-003',
        'resolution': 'Deploy WAF virtual patch for identified SQL injection signatures, terminate malicious database sessions, and block source IP.',
        'response_domain': 'Application & Database Security',
        'priority': 'Critical',
        'rationale': 'Malicious SQL syntax patterns in HTTP parameters indicate an attempt to bypass auth or exfiltrate database records.',
        'response_steps': [
            'Deploy Cloud WAF virtual patch filtering out SQL injection signatures on vulnerable API routes.',
            'Terminate active database connection sessions originating from the attacking IP address.',
            'Quarantine input field on reverse proxy and alert engineering team for parameterization.'
        ],
        'confidence': 0.94,
        'times_used': 31,
        'successful_resolutions': 29,
        'alternate_resolution_id': 'PB-SQLI-ALT-003',
        'alternate_playbook': 'Database Exfiltration Lockdown: Restrict database service account to read-only, audit query transaction logs, and emergency patch application code.',
        'alternate_steps': [
            'Demote database service account permissions to read-only mode to prevent table drops/modifications.',
            'Audit binary transaction logs for mass exfiltration or UNION SELECT queries against sensitive tables.',
            'Engage AppSec team for an emergency code hotfix deploying prepared statements and parameterized queries.'
        ],
        'escalation_tier': 'Tier-2 AppSec & Database Forensics Engineer',
        'historical_matches': [
            {'incident_id': 'INC-2026-0607', 'similarity': 0.97, 'resolution': 'Applied WAF rule and sanitized SQL query parameters.', 'outcome': 'success'},
            {'incident_id': 'INC-2026-0511', 'similarity': 0.90, 'resolution': 'Terminated active database session and blocked attacker IP.', 'outcome': 'success'}
        ]
    },
    'Phishing': {
        'resolution_id': 'PB-PHISH-004',
        'resolution': 'Purge malicious email across all tenant mailboxes, block sender domain at Secure Email Gateway, and revoke credentials for clicked users.',
        'response_domain': 'Email & Identity Defense',
        'priority': 'High',
        'rationale': 'Deceptive email campaigns attempt credential harvesting or malware staging; rapid purge prevents organizational compromise.',
        'response_steps': [
            'Execute automated search-and-purge command across all employee mailboxes matching the campaign message ID.',
            'Block sender domain, originating IP, and embedded URLs at the Secure Email Gateway.',
            'Force sign-out and session revocation for users identified as having opened the phishing link.'
        ],
        'confidence': 0.93,
        'times_used': 42,
        'successful_resolutions': 39,
        'alternate_resolution_id': 'PB-PHISH-ALT-004',
        'alternate_playbook': 'Adversary-in-the-Middle (AiTM) Token Defense: Invalidate OAuth refresh tokens, enforce FIDO2 hardware keys, and scan endpoints for infostealers.',
        'alternate_steps': [
            'Invalidate all active Entra ID / Okta session and OAuth refresh tokens for targeted user groups.',
            'Enforce phishing-resistant FIDO2 hardware token challenge for all external sign-in requests.',
            'Dispatch EDR full-disk threat scans on recipient workstations to detect second-stage infostealer payloads.'
        ],
        'escalation_tier': 'Tier-2 Identity & Endpoint Threat Hunting Team',
        'historical_matches': [
            {'incident_id': 'INC-2026-0317', 'similarity': 0.95, 'resolution': 'Purged phishing emails and revoked clicked user sessions.', 'outcome': 'success'},
            {'incident_id': 'INC-2026-0284', 'similarity': 0.91, 'resolution': 'Blocked spoofed domain and reset compromised passwords.', 'outcome': 'success'}
        ]
    },
    'Malware Detection': {
        'resolution_id': 'PB-MALW-005',
        'resolution': 'Quarantine suspicious binary via EDR, terminate execution tree, and isolate endpoint from internal corporate subnet.',
        'response_domain': 'Endpoint Threat Mitigation',
        'priority': 'Critical',
        'rationale': 'Known malware signatures or anomalous behavioral heuristics detected on host require immediate containment to stop propagation.',
        'response_steps': [
            'Issue instantaneous EDR host isolation command to cut network lateral communication.',
            'Kill malicious process and all associated spawned child subshells.',
            'Quarantine binary hash, collect sample to secure vault, and query SIEM for matching hashes.'
        ],
        'confidence': 0.94,
        'times_used': 28,
        'successful_resolutions': 26,
        'alternate_resolution_id': 'PB-MALW-ALT-005',
        'alternate_playbook': 'Living-off-the-Land (LotL) Deep Threat Hunt: Inspect scheduled tasks, WMI persistence, and memory injection across lateral network subnet.',
        'alternate_steps': [
            'Scan local registry, systemd/cron services, and WMI subscriptions for persistent hooks.',
            'Capture volatile memory dump using Volatility framework to detect process hollowing or DLL injection.',
            'Trigger enterprise-wide IoC threat hunt across SIEM to locate dormant lateral infections.'
        ],
        'escalation_tier': 'Tier-2 Reverse Engineering & Malware Forensics',
        'historical_matches': [
            {'incident_id': 'INC-2026-0492', 'similarity': 0.94, 'resolution': 'Quarantined Trojan binary and removed registry persistence run keys.', 'outcome': 'success'}
        ]
    },
    'Port Scanning': {
        'resolution_id': 'PB-SCAN-006',
        'resolution': 'Rate-limit external SYN packets, inject dynamic edge firewall drop rules, and inspect honeypot sensor telemetry.',
        'response_domain': 'Perimeter Network Defense',
        'priority': 'Medium',
        'rationale': 'Systematic probing of network ports indicates adversarial reconnaissance targeting unpatched edge services.',
        'response_steps': [
            'Inject temporary perimeter firewall drop rules for the scanning CIDR IP range.',
            'Enable TCP SYN flood protection and connection rate-limiting on edge routers.',
            'Audit internal service exposure on targeted subnet ports.'
        ],
        'confidence': 0.91,
        'times_used': 19,
        'successful_resolutions': 18,
        'alternate_resolution_id': 'PB-SCAN-ALT-006',
        'alternate_playbook': 'Perimeter Reconnaissance Evasion: Rotate public IP interfaces, drop ICMP/SYN discovery packets, and deploy honeynet deception tokens.',
        'alternate_steps': [
            'Deploy defensive honeynet deception services on probed ports to capture attacker TTPs.',
            'Tighten public cloud security groups to strict IP allowlists for administrative ports.',
            'Initiate External Attack Surface Management (ASM) scan to identify accidental port exposures.'
        ],
        'escalation_tier': 'Tier-2 Perimeter & Network Infrastructure Security',
        'historical_matches': [
            {'incident_id': 'INC-2026-0093', 'similarity': 0.92, 'resolution': 'Blocked scanning subnet and tightened border ACLs.', 'outcome': 'success'}
        ]
    },
    'DDoS Attack': {
        'resolution_id': 'PB-DDOS-007',
        'resolution': 'Divert traffic through BGP Anycast scrubbing center, activate L7 rate limiting, and challenge suspicious requests.',
        'response_domain': 'Network & Edge Resilience',
        'priority': 'Critical',
        'rationale': 'Volumetric or application-layer floods threaten availability of public APIs and user-facing endpoints.',
        'response_steps': [
            'Route ingress traffic through upstream Anycast DDoS scrubbing network.',
            'Activate Managed Challenge (CAPTCHA/JS) and Layer-7 rate limiting on HTTP endpoints.',
            'Drop spoofed UDP and TCP SYN flood packets at perimeter upstream border routers.'
        ],
        'confidence': 0.96,
        'times_used': 22,
        'successful_resolutions': 21,
        'alternate_resolution_id': 'PB-DDOS-ALT-007',
        'alternate_playbook': 'Origin Shielding & Carrier Blackholing: Rotate origin IP addresses, restrict origin access strictly to CDN, and trigger carrier RTBH.',
        'alternate_steps': [
            'Re-bind origin IP addresses and enforce strict Security Group rules accepting traffic only from CDN proxies.',
            'Trigger upstream ISP Remotely Triggered Black Hole (RTBH) routing for targeted destination IPs.',
            'Enable circuit breakers and graceful degradation for resource-heavy backend database queries.'
        ],
        'escalation_tier': 'Tier-3 Cloud Reliability & SecOps Lead',
        'historical_matches': [
            {'incident_id': 'INC-2026-0597', 'similarity': 0.96, 'resolution': 'Enabled CDN scrubbing and blocked layer-7 botnet traffic.', 'outcome': 'success'}
        ]
    },
    'Credential Stuffing': {
        'resolution_id': 'PB-CRED-008',
        'resolution': 'Throttle login endpoints with progressive delay, challenge suspicious user-agents, and block botnet IPs.',
        'response_domain': 'Authentication & Fraud Prevention',
        'priority': 'Critical',
        'rationale': 'Credential stuffing spreads automated password spray traffic across customer accounts and can lead to mass account takeover.',
        'response_steps': [
            'Block abusive IP ranges and enforce progressive delay for repeated login failures.',
            'Prompt risk-based step-up verification for suspicious users and require password resets for targeted accounts.',
            'Inspect authentication telemetry for successful takeover patterns.'
        ],
        'confidence': 0.93,
        'times_used': 20,
        'successful_resolutions': 18,
        'alternate_resolution_id': 'PB-CRED-ALT-008',
        'alternate_playbook': 'Mass Credential Reset & TLS Fingerprinting: Correlate against breach dumps, enforce mandatory FIDO2 passkeys, and block JA3 bot fingerprints.',
        'alternate_steps': [
            'Cross-reference targeted usernames against breached credential databases and force batch password resets.',
            'Block automated credential stuffing headless browser clients using TLS JA3/JA4 fingerprint matching.',
            'Enable mandatory FIDO2 Passkey enrollment for high-privilege customer and administrative tiers.'
        ],
        'escalation_tier': 'Tier-2 Fraud Prevention & Identity Protection Lead',
        'historical_matches': [
            {'incident_id': 'INC-2026-0066', 'similarity': 0.95, 'resolution': 'Throttled customer auth attempts and validated risky accounts.', 'outcome': 'success'}
        ]
    },
    'Unauthorized Access': {
        'resolution_id': 'PB-UNAUTH-009',
        'resolution': 'Terminate unauthorized user sessions, revoke active API tokens, and temporarily lock compromised account.',
        'response_domain': 'Identity & Session Defense',
        'priority': 'Critical',
        'rationale': 'Access anomalies from unapproved locations or impossible travel times indicate active session hijacking or stolen tokens.',
        'response_steps': [
            'Terminate active web and API sessions across all identity providers for the compromised user.',
            'Revoke active OAuth bearer tokens and temporarily lock the account pending analyst verification.',
            'Review authentication logs for unauthorized configuration modifications or privilege elevation.'
        ],
        'confidence': 0.94,
        'times_used': 26,
        'successful_resolutions': 24,
        'alternate_resolution_id': 'PB-UNAUTH-ALT-009',
        'alternate_playbook': 'Privilege Escalation & Lateral Movement Quarantine: Invalidate STS session tokens, freeze assumed IAM roles, and audit cloud trail logs.',
        'alternate_steps': [
            'Audit and delete newly created service accounts, SSH keys, or cloud IAM credentials created during the session.',
            'Invalidate root and privilege delegation policies across cloud organizations.',
            'Initiate forensic review of privileged database and storage accesses made during the incident window.'
        ],
        'escalation_tier': 'Tier-2 Cloud IAM & Incident Response Specialist',
        'historical_matches': [
            {'incident_id': 'INC-2026-0687', 'similarity': 0.94, 'resolution': 'Revoked API keys and locked suspicious account.', 'outcome': 'success'}
        ]
    },
    'Cloud IAM Misconfiguration': {
        'resolution_id': 'PB-IAM-010',
        'resolution': 'Detach overly permissive policies (*:*), restrict public storage buckets, and enforce least-privilege role boundaries.',
        'response_domain': 'Cloud Governance & Access Control',
        'priority': 'Critical',
        'rationale': 'Wildcard permissions or exposed cloud storage buckets create massive data breach and privilege escalation attack vectors.',
        'response_steps': [
            'Revoke wildcard (*) administrative permissions from IAM policies and bind to scoped least-privilege roles.',
            'Enable Block Public Access at the cloud organization level for all S3 and Blob storage buckets.',
            'Invalidate temporary STS and cloud session tokens for affected service accounts.'
        ],
        'confidence': 0.92,
        'times_used': 17,
        'successful_resolutions': 15,
        'alternate_resolution_id': 'PB-IAM-ALT-010',
        'alternate_playbook': 'Infrastructure-as-Code Drift Rollback: Revert Terraform/CloudFormation to immutable baseline and enforce SCP governance guardrails.',
        'alternate_steps': [
            'Trigger CI/CD drift reconciliation to overwrite unauthorized IAM role modifications.',
            'Enforce organization-level Service Control Policies blocking privilege escalations.',
            'Audit cross-account trust relationships for rogue external AWS/Azure tenant IDs.'
        ],
        'escalation_tier': 'Tier-2 Cloud SecOps & DevSecOps Lead',
        'historical_matches': [
            {'incident_id': 'INC-2026-0711', 'similarity': 0.93, 'resolution': 'Replaced wildcard IAM policy with scoped role.', 'outcome': 'success'}
        ]
    },
    'Prompt Injection': {
        'resolution_id': 'PB-AI-PI-011',
        'resolution': 'Enforce prompt boundary isolation, strip instruction override tags, and restrict agent tool privileges.',
        'response_domain': 'AI System Defense',
        'priority': 'Critical',
        'rationale': 'Direct or indirect prompt injections manipulate LLM instruction hierarchy to trigger unauthorized actions.',
        'response_steps': [
            'Isolate and sanitize untrusted user inputs with input guardrails and instruction tag stripping.',
            'Revoke high-risk tool execution privileges for compromised agent sessions.',
            'Update system prompts with standard instruction delimiter boundaries.'
        ],
        'confidence': 0.96,
        'times_used': 25,
        'successful_resolutions': 23,
        'alternate_resolution_id': 'PB-AI-PI-ALT-011',
        'alternate_playbook': 'Dual-LLM Guardrail & Sandboxed Agent Quarantine: Deploy an independent Judge LLM for prompt arbitration and strip agent shell tools.',
        'alternate_steps': [
            'Deploy dual-model arbitration where a separate safety model audits intent before execution.',
            'Terminate active conversational context memory and purge injected instructions.',
            'Restrict LLM tool access to read-only non-destructive operations.'
        ],
        'escalation_tier': 'AI Red Team & LLM Security Safety Officer',
        'historical_matches': [
            {'incident_id': 'INC-2026-0912', 'similarity': 0.98, 'resolution': 'Applied strict input delimiters and disabled bash tool execution.', 'outcome': 'success'},
            {'incident_id': 'INC-2026-0881', 'similarity': 0.92, 'resolution': 'Sanitized incoming prompt payload.', 'outcome': 'success'}
        ]
    },
    'Agent Goal Hijacking': {
        'resolution_id': 'PB-AI-GH-012',
        'resolution': 'Terminate hijacked agent task plan, validate objective alignment against user intent, and reset working scratchpad memory.',
        'response_domain': 'Autonomous Agent Safety',
        'priority': 'Critical',
        'rationale': 'Adversarial manipulation has steered the agent toward unauthorized objectives deviating from the user goal.',
        'response_steps': [
            'Immediately halt active multi-step autonomous agent execution loop.',
            'Compare agent execution trace against original authorized user objective.',
            'Invalidate hijacked working scratchpad and task memory.'
        ],
        'confidence': 0.95,
        'times_used': 16,
        'successful_resolutions': 15,
        'alternate_resolution_id': 'PB-AI-GH-ALT-012',
        'alternate_playbook': 'Deterministic Execution Fallback & Human Gateway: Enforce synchronous human approval for every agent step and freeze tool tokens.',
        'alternate_steps': [
            'Require synchronous human authorization for each downstream tool invocation.',
            'Inspect web scraping and document retrieval pipelines for embedded indirect prompt hijacking.',
            'Reset agent model temperature and reinforce system goal guardrails.'
        ],
        'escalation_tier': 'Autonomous Systems SecOps & AI Alignment Lead',
        'historical_matches': [
            {'incident_id': 'INC-2026-0955', 'similarity': 0.96, 'resolution': 'Terminated divergent agent subtasks and restored core goal.', 'outcome': 'success'}
        ]
    },
    'Unsafe Tool Invocation': {
        'resolution_id': 'PB-AI-TOOL-013',
        'resolution': 'Intercept unauthorized tool arguments, reject dangerous system calls (rm, drop, exec), and return synthetic error.',
        'response_domain': 'AI Tool Runtime Protection',
        'priority': 'Critical',
        'rationale': 'LLM generated tool calls with parameters violating safe boundaries or attempting filesystem/network destruction.',
        'response_steps': [
            'Execute AST schema validation on LLM tool function call arguments.',
            'Block calls attempting file system deletion, shell execution, or remote exfiltration.',
            'Return synthetic error message to model preventing retry.'
        ],
        'confidence': 0.94,
        'times_used': 18,
        'successful_resolutions': 17,
        'alternate_resolution_id': 'PB-AI-TOOL-ALT-013',
        'alternate_playbook': 'Ephemeral Micro-VM Sandboxing: Revoke high-privilege tools permanently and isolate operations in an air-gapped micro-VM.',
        'alternate_steps': [
            'Revoke bash/exec/eval tool capabilities permanently for the active user session.',
            'Route file operations to isolated in-memory ramdisk with strict size limits.',
            'Trigger security telemetry alert to LLM platform administrators.'
        ],
        'escalation_tier': 'AI Platform Infrastructure Security Engineer',
        'historical_matches': [
            {'incident_id': 'INC-2026-0941', 'similarity': 0.95, 'resolution': 'Blocked unauthorized OS shell execution from agent.', 'outcome': 'success'}
        ]
    },
    'Excessive Agent Permissions': {
        'resolution_id': 'PB-AI-PERM-014',
        'resolution': 'Apply Least-Privilege Agent Scope (LPAS), downgrade agent session tokens, and block write actions on protected resources.',
        'response_domain': 'Agent Privilege Governance',
        'priority': 'High',
        'rationale': 'Agent possesses broader write and delete permissions than necessary for current objective, creating blast-radius risks.',
        'response_steps': [
            'Downgrade agent runtime token from admin to scoped read-only role.',
            'Reject tool execution requests exceeding task requirements.',
            'Audit database mutations attempted by the agent.'
        ],
        'confidence': 0.93,
        'times_used': 14,
        'successful_resolutions': 13,
        'alternate_resolution_id': 'PB-AI-PERM-ALT-014',
        'alternate_playbook': 'Just-In-Time (JIT) Permission Brokerage: Revoke persistent keys and require short-lived cryptographic tokens per tool call.',
        'alternate_steps': [
            'Enforce STS short-lived credential minting with 5-minute TTL per task.',
            'Invalidate all wildcards in agent manifest and bind permissions to explicit resource ARNs.',
            'Audit historical agent logs for unauthorized data access.'
        ],
        'escalation_tier': 'AI Governance & Cloud IAM Architect',
        'historical_matches': [
            {'incident_id': 'INC-2026-0922', 'similarity': 0.93, 'resolution': 'Restricted agent tool scope to readonly queries.', 'outcome': 'success'}
        ]
    },
    'Sensitive Data Leakage': {
        'resolution_id': 'PB-AI-LEAK-015',
        'resolution': 'Redact PII and secrets with regex/Presidio masking, block output transmission, and alert data protection officer.',
        'response_domain': 'Data Loss Prevention & Privacy',
        'priority': 'Critical',
        'rationale': 'Model response or retrieved RAG context contains plaintext PII, credit card numbers, or cryptographic secrets.',
        'response_steps': [
            'Mask detected credit card numbers, API keys, and PII from model output before rendering.',
            'Block outgoing HTTP webhook with leaking payload.',
            'Audit prompt context for source of leaked sensitive data.'
        ],
        'confidence': 0.95,
        'times_used': 21,
        'successful_resolutions': 20,
        'alternate_resolution_id': 'PB-AI-LEAK-ALT-015',
        'alternate_playbook': 'Vector Store / RAG Poisoning Quarantine: Purge corrupted embeddings from knowledge base and rotate exposed API keys.',
        'alternate_steps': [
            'Locate source chunk in vector database and delete/re-index document.',
            'Immediately invalidate and rotate exposed API keys/credentials across cloud services.',
            'Enforce tenant-isolated metadata filtering on all semantic search queries.'
        ],
        'escalation_tier': 'Data Privacy & Cryptographic Security Officer',
        'historical_matches': [
            {'incident_id': 'INC-2026-0977', 'similarity': 0.96, 'resolution': 'Redacted SSN and API key from agent completion stream.', 'outcome': 'success'}
        ]
    },
    'AI Tool Abuse': {
        'resolution_id': 'PB-AI-ABUSE-016',
        'resolution': 'Rate-limit high-frequency tool calls, flag anomalous tool execution patterns, and throttle user session.',
        'response_domain': 'AI API Rate & Resource Defense',
        'priority': 'High',
        'rationale': 'Automated scripts are exploiting LLM tool calling endpoints causing resource exhaustion and unexpected billing spikes.',
        'response_steps': [
            'Enforce token bucket rate limiting on expensive external API tools.',
            'Detect cyclic recursive tool calls and abort execution.',
            'Log abuse telemetry with user account identifier.'
        ],
        'confidence': 0.92,
        'times_used': 13,
        'successful_resolutions': 12,
        'alternate_resolution_id': 'PB-AI-ABUSE-ALT-016',
        'alternate_playbook': 'Fraud Circuit Breaker & Behavioral Blacklisting: Trip global circuit breaker on abused downstream APIs and ban client key.',
        'alternate_steps': [
            'Engage automated circuit breaker to prevent denial-of-wallet cloud cost spikes.',
            'Ban client IP and associated user tenant from platform tools.',
            'Audit downstream third-party service logs for data manipulation.'
        ],
        'escalation_tier': 'FinSecOps & API Security Specialist',
        'historical_matches': [
            {'incident_id': 'INC-2026-0931', 'similarity': 0.91, 'resolution': 'Applied rate limiter and broke recursive tool invocation loop.', 'outcome': 'success'}
        ]
    },
    'Model Manipulation': {
        'resolution_id': 'PB-AI-MOD-017',
        'resolution': 'Detect adversarial perturbation patterns in inputs, reject malformed tensor weights, and alert model monitoring service.',
        'response_domain': 'Model Integrity & Robustness',
        'priority': 'Critical',
        'rationale': 'Adversarial inputs or attempts to manipulate model runtime weights compromise inference accuracy and safety boundaries.',
        'response_steps': [
            'Run adversarial input detection filter on incoming model tensors.',
            'Validate cryptographic checksums of local model weights against golden artifact.',
            'Reject suspicious inference inputs.'
        ],
        'confidence': 0.94,
        'times_used': 11,
        'successful_resolutions': 10,
        'alternate_resolution_id': 'PB-AI-MOD-ALT-017',
        'alternate_playbook': 'Model Checkpoint Rollback & Cryptographic Attestation: Re-deploy model weights from signed cold storage and verify SLSA provenance.',
        'alternate_steps': [
            'Drain traffic from suspect inference container pods and re-image with certified container image.',
            'Verify Sigstore/Cosign digital signatures on model weight files.',
            'Run complete model evaluation benchmark to detect fine-tuning poisoning.'
        ],
        'escalation_tier': 'MLOps Security & Model Integrity Lead',
        'historical_matches': [
            {'incident_id': 'INC-2026-0968', 'similarity': 0.94, 'resolution': 'Restored model weights from verified cryptographic baseline.', 'outcome': 'success'}
        ]
    },
    'Generic Security Event': {
        'resolution_id': 'PB-GEN-018',
        'resolution': 'Isolate affected host assets, collect volatile forensic logs, and review access control policies.',
        'response_domain': 'General Incident Containment',
        'priority': 'Medium',
        'rationale': 'Unclassified security anomalies require immediate host isolation and telemetry extraction.',
        'response_steps': [
            'Isolate the impacted host/endpoint from the network.',
            'Capture volatile memory and system log snapshots.',
            'Perform privilege escalation and access log review.'
        ],
        'confidence': 0.85,
        'times_used': 12,
        'successful_resolutions': 10,
        'alternate_resolution_id': 'PB-GEN-ALT-018',
        'alternate_playbook': 'Zero-Trust Triage & Threat Surface Quarantine: Blackhole originating subnet, reset active user credentials, and initiate full DFIR investigation.',
        'alternate_steps': [
            'Enforce full subnet micro-segmentation at SDN layer.',
            'Revoke all Kerberos/Active Directory ticket-granting tickets for the host.',
            'Hand over triage dossier to Tier-2 Security Operations Center.'
        ],
        'escalation_tier': 'Senior SOC Lead & Threat Intelligence Analyst',
        'historical_matches': [
            {'incident_id': 'INC-2026-0010', 'similarity': 0.88, 'resolution': 'Host isolation and volatile memory collection.', 'outcome': 'success'}
        ]
    }
}
