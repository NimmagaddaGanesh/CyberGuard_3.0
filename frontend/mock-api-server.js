const http = require('http');

const PORT = 8000;

const scenarioAliases = {
  'ssh brute force': 'SSH Brute Force',
  'credential stuffing': 'Credential Stuffing',
  'sql injection': 'SQL Injection',
  'phishing': 'Phishing',
  'malware detection': 'Malware Detection',
  'port scanning': 'Port Scanning',
  'ddos attack': 'DDoS Attack',
  'ddos': 'DDoS Attack',
  'ransomware': 'Ransomware',
  'unauthorized access': 'Unauthorized Access',
  'cloud iam misconfiguration': 'Cloud IAM Misconfiguration',
  'prompt injection': 'Prompt Injection',
  'tool abuse': 'AI Tool Abuse',
  'ai tool abuse': 'AI Tool Abuse',
  'excessive agent permissions': 'Excessive Agent Permissions',
  'sensitive data leakage': 'Sensitive Data Leakage',
  'model manipulation': 'Model Manipulation',
  'unsafe tool invocation': 'Unsafe Tool Invocation',
  'agent goal hijacking': 'Agent Goal Hijacking',
};

const scenarioToResolution = {
  'SSH Brute Force': 'RES-SSH-001',
  'Credential Stuffing': 'RES-CRED-002',
  'SQL Injection': 'RES-APP-003',
  'Phishing': 'RES-APP-004',
  'Malware Detection': 'RES-END-005',
  'Ransomware': 'RES-END-006',
  'Port Scanning': 'RES-NET-007',
  'DDoS Attack': 'RES-NET-008',
  'Unauthorized Access': 'RES-IDENT-009',
  'Cloud IAM Misconfiguration': 'RES-IAM-010',
  'Prompt Injection': 'RES-AI-PI-011',
  'AI Tool Abuse': 'RES-AI-TOOL-012',
  'Excessive Agent Permissions': 'RES-AI-PERM-013',
  'Sensitive Data Leakage': 'RES-AI-LEAK-014',
  'Model Manipulation': 'RES-AI-MODEL-015',
  'Unsafe Tool Invocation': 'RES-AI-UNSAFE-016',
  'Agent Goal Hijacking': 'RES-AI-HIJACK-017',
};

const resolutionProfiles = {
  'RES-SSH-001': {
    pattern: /ssh|brute force|credential|login attempts/,
    recommendation: {
      resolution_id: 'RES-SSH-001',
      resolution: 'Throttle SSH authentication attempts, block attacking IPs, and enforce MFA for impacted accounts.',
      response_domain: 'Identity containment',
      priority: 'High',
      rationale: 'Rapid failed SSH logins often indicate automation against privileged access paths.',
      response_steps: ['Rate-limit SSH auth attempts and block the offending source addresses.', 'Require MFA and reset credentials for any account with repeated failures.', 'Review successful login events and harden SSH access policy.'],
      confidence: 0.94,
      times_used: 3,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0156', similarity: 0.97, resolution: 'Throttle login attempts and enforce MFA for impacted SSH accounts.', outcome: 'success' },
      { incident_id: 'INC-2026-0042', similarity: 0.91, resolution: 'Rate-limit authentication attempts and rotate impacted credentials.', outcome: 'success' },
    ],
  },
  'RES-CRED-002': {
    pattern: /credential stuffing|credential|login flood|customer authentication/,
    recommendation: {
      resolution_id: 'RES-CRED-002',
      resolution: 'Distribute malicious login traffic with challenge throttling, IP blocking, and customer account verification.',
      response_domain: 'Access defense',
      priority: 'Critical',
      rationale: 'Credential stuffing spreads password spray traffic across customer accounts and can lead to mass account takeover.',
      response_steps: ['Block abusive IP ranges and enforce progressive delay for repeated login failures.', 'Add step-up verification for suspicious customers and require password resets for high-risk accounts.', 'Inspect authentication telemetry for a successful takeover pattern.'],
      confidence: 0.93,
      times_used: 2,
      successful_resolutions: 1,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0066', similarity: 0.96, resolution: 'Throttle customer authentication attempts and validate risky accounts.', outcome: 'success' },
      { incident_id: 'INC-2026-0042', similarity: 0.9, resolution: 'Limit login attempts and reset suspicious credentials.', outcome: 'failed' },
    ],
  },
  'RES-APP-003': {
    pattern: /sql injection|union select|db payload|injection/,
    recommendation: {
      resolution_id: 'RES-APP-003',
      resolution: 'Block the malicious SQL payload, isolate the affected database path, and validate input sanitization.',
      response_domain: 'Application defense',
      priority: 'Critical',
      rationale: 'Structured query abuse can expose sensitive rows and bypass application trust boundaries.',
      response_steps: ['Add WAF and application-layer blocking for the confirmed SQL pattern.', 'Isolate read access to impacted tables and review database audit logs.', 'Patch the vulnerable input handling path and validate user input sanitization.'],
      confidence: 0.97,
      times_used: 2,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0607', similarity: 0.97, resolution: 'Patch the vulnerable query path and block malicious SQL payloads.', outcome: 'success' },
      { incident_id: 'INC-2026-0817', similarity: 0.74, resolution: 'Validate input handling and inspect downstream database access.', outcome: 'failed' },
    ],
  },
  'RES-APP-004': {
    pattern: /phishing|impersonation|malicious attachment|suspicious email/,
    recommendation: {
      resolution_id: 'RES-APP-004',
      resolution: 'Quarantine the malicious message, revoke impacted sessions, and run user awareness containment for the affected cohort.',
      response_domain: 'Application defense',
      priority: 'High',
      rationale: 'Phishing campaigns can harvest credentials or enable downstream malware execution through user trust.',
      response_steps: ['Block the sender, domain, and malicious attachment across mail gateways.', 'Reset credentials for any user that clicked or replied to the message.', 'Review mailbox and endpoint telemetry for malicious follow-on activity.'],
      confidence: 0.91,
      times_used: 3,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0317', similarity: 0.95, resolution: 'Quarantine the malicious email and reset affected user credentials.', outcome: 'success' },
      { incident_id: 'INC-2026-0048', similarity: 0.9, resolution: 'Disconnect the user session and block the malicious attachment flow.', outcome: 'success' },
    ],
  },
  'RES-END-005': {
    pattern: /malware detection|process injection|unverified binary|edr/,
    recommendation: {
      resolution_id: 'RES-END-005',
      resolution: 'Isolate the compromised endpoint, collect forensic evidence, and restore from a clean trusted image.',
      response_domain: 'Endpoint containment',
      priority: 'Critical',
      rationale: 'Endpoint malware can escalate to privilege abuse, persistence, and lateral movement.',
      response_steps: ['Isolate the workstation from the network while preserving forensic evidence.', 'Terminate malicious processes and block the file hash across endpoint controls.', 'Restore the endpoint from a clean image and rotate credentials used on that device.'],
      confidence: 0.92,
      times_used: 2,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0492', similarity: 0.96, resolution: 'Isolate the endpoint and remove malware persistence before recovery.', outcome: 'success' },
      { incident_id: 'INC-2026-0446', similarity: 0.82, resolution: 'Contain the infected host and restore from a clean backup.', outcome: 'failed' },
    ],
  },
  'RES-END-006': {
    pattern: /ransomware|encryption|file renaming|locked files/,
    recommendation: {
      resolution_id: 'RES-END-006',
      resolution: 'Immediately isolate affected hosts, block lateral movement, and recover from validated immutable backups.',
      response_domain: 'Recovery operations',
      priority: 'Critical',
      rationale: 'Encryption activity often spreads rapidly across shared storage and connected hosts.',
      response_steps: ['Isolate the impacted systems and segment them from shared storage.', 'Block the ransomware process, revoke exposed credentials, and preserve forensic artifacts.', 'Restore clean data from known-good backup and verify integrity before reconnecting systems.'],
      confidence: 0.96,
      times_used: 4,
      successful_resolutions: 3,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0446', similarity: 0.98, resolution: 'Cut off network access and restore from validated backup.', outcome: 'success' },
      { incident_id: 'INC-2026-0492', similarity: 0.84, resolution: 'Contain the infected host and verify restored integrity before reactivation.', outcome: 'failed' },
    ],
  },
  'RES-NET-007': {
    pattern: /port scanning|scan|network reconnaissance|port probe/,
    recommendation: {
      resolution_id: 'RES-NET-007',
      resolution: 'Block the scanning source, inspect exposed service surfaces, and harden edge filtering.',
      response_domain: 'Network defense',
      priority: 'Medium',
      rationale: 'Reconnaissance often precedes credential abuse, service exploitation, or lateral movement.',
      response_steps: ['Capture the scanner address, ports, and packet characteristics.', 'Apply ACL or firewall restrictions on the observed source path.', 'Review exposed services and verify that only approved ports remain reachable.'],
      confidence: 0.91,
      times_used: 1,
      successful_resolutions: 1,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0093', similarity: 0.95, resolution: 'Limit access to the scanning source and review exposed services.', outcome: 'success' },
      { incident_id: 'INC-2026-0045', similarity: 0.76, resolution: 'Tighten edge filtering and alert on repeated reconnaissance activity.', outcome: 'failed' },
    ],
  },
  'RES-NET-008': {
    pattern: /ddos|denial.of.service|volumetric|traffic surge/,
    recommendation: {
      resolution_id: 'RES-NET-008',
      resolution: 'Apply edge rate limiting, traffic scrubbing, and priority filtering to keep legitimate service traffic online.',
      response_domain: 'Network defense',
      priority: 'Critical',
      rationale: 'Traffic floods can saturate perimeter controls and reduce service availability for customers and internal teams.',
      response_steps: ['Activate WAF, CDN, or upstream filtering for the impacted endpoints.', 'Prioritize critical services and rate-limit excess traffic patterns.', 'Monitor recovery and remove temporary restrictions once the traffic load stabilizes.'],
      confidence: 0.95,
      times_used: 2,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0597', similarity: 0.96, resolution: 'Scrub the attack traffic and preserve critical service availability.', outcome: 'success' },
      { incident_id: 'INC-2026-0045', similarity: 0.92, resolution: 'Rate-limit traffic and isolate the attack path from the edge.', outcome: 'success' },
    ],
  },
  'RES-IDENT-009': {
    pattern: /unauthorized access|revoked credentials|administrative session|privilege escalation/,
    recommendation: {
      resolution_id: 'RES-IDENT-009',
      resolution: 'Revoke the unauthorized session, rotate credentials, and inspect identity activity for lateral movement.',
      response_domain: 'Access control',
      priority: 'Critical',
      rationale: 'Compromised administrative sessions can unlock privileged actions and expose high-value systems.',
      response_steps: ['Invalidate active sessions and force password reset for the affected identity.', 'Review identity logs for privilege escalation and suspicious resource access.', 'Validate least-privilege policy and restore the last known-good access configuration.'],
      confidence: 0.94,
      times_used: 3,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0687', similarity: 0.97, resolution: 'Terminate the active unauthorized session and rotate privileged credentials.', outcome: 'success' },
      { incident_id: 'INC-2026-0049', similarity: 0.89, resolution: 'Revoke all stale privileged sessions and audit access control history.', outcome: 'failed' },
    ],
  },
  'RES-IAM-010': {
    pattern: /iam misconfiguration|public access|bucket policy|privilege drift/,
    recommendation: {
      resolution_id: 'RES-IAM-010',
      resolution: 'Restore least-privilege policies, revoke public exposure, and review access governance for the affected environment.',
      response_domain: 'Identity governance',
      priority: 'Critical',
      rationale: 'Overexposed cloud permissions create easy paths for data theft and unauthorized access across the environment.',
      response_steps: ['Restore the last known-good policy state and revoke public access entries.', 'Review role assignments for drift or overly broad entitlements.', 'Audit access history and notify service owners before re-enabling the environment.'],
      confidence: 0.95,
      times_used: 2,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0249', similarity: 0.96, resolution: 'Revoke public data access and restore the last valid IAM baseline.', outcome: 'success' },
      { incident_id: 'INC-2026-0050', similarity: 0.9, resolution: 'Remove public access and audit service-to-service permissions.', outcome: 'success' },
    ],
  },
  'RES-AI-PI-011': {
    pattern: /prompt injection|override system instructions|untrusted content|prompt manipulation/,
    recommendation: {
      resolution_id: 'RES-AI-PI-011',
      resolution: 'Isolate the prompt injection path, quarantine the affected model session, and tighten instruction boundary validation.',
      response_domain: 'AI safety containment',
      priority: 'Critical',
      rationale: 'Prompt injection attempts can override system guidance and expose context or trigger unauthorized behavior.',
      response_steps: ['Pause the active agent workflow and remove the untrusted instruction source from the session.', 'Review prompts, outputs, and retrieval artifacts for instruction override behavior.', 'Re-enforce model trust boundaries and verify the safe prompt policy before resuming.'],
      confidence: 0.93,
      times_used: 2,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0817', similarity: 0.96, resolution: 'Quarantine the malicious prompt session and restore trust boundaries.', outcome: 'success' },
      { incident_id: 'INC-2026-0057', similarity: 0.9, resolution: 'Reset the impacted model context and validate prompt integrity before resume.', outcome: 'success' },
    ],
  },
  'RES-AI-TOOL-012': {
    pattern: /tool abuse|ai tool abuse|unauthorized tool|tool invocation|unsafe tool/,
    recommendation: {
      resolution_id: 'RES-AI-TOOL-012',
      resolution: 'Revoke the unsafe tool scope, suspend the agent session, and validate all tool permissions before reactivation.',
      response_domain: 'AI tool governance',
      priority: 'Critical',
      rationale: 'Excessive or unauthorized tool access can lead to network activity, code execution, or data exposure outside approved policy.',
      response_steps: ['Disable the tool access path and suspend the affected agent instance.', 'Review the tool call trace for unauthorized execution or outbound behavior.', 'Reapply the least-privilege policy and validate the tool allowlist before re-enabling access.'],
      confidence: 0.96,
      times_used: 3,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0859', similarity: 0.98, resolution: 'Suspend unsafe tool access and restore the approved execution boundary.', outcome: 'success' },
      { incident_id: 'INC-2026-0062', similarity: 0.91, resolution: 'Disable the unapproved tool path and review outbound actions.', outcome: 'failed' },
    ],
  },
  'RES-AI-PERM-013': {
    pattern: /excessive agent permissions|least privilege|privilege scope|broad write access/,
    recommendation: {
      resolution_id: 'RES-AI-PERM-013',
      resolution: 'Remove the over-broad permissions, downgrade the agent to a least-privilege state, and revalidate access approvals.',
      response_domain: 'AI privileges',
      priority: 'High',
      rationale: 'Expanded agent authority creates a path for unsafe actions even when the model itself is otherwise normal.',
      response_steps: ['Reduce the agent to the minimum required permissions for its approved workflow.', 'Review all tool and data access scopes and remove anything beyond the approved task list.', 'Verify the policy approval chain before the agent is allowed to resume.'],
      confidence: 0.95,
      times_used: 2,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0969', similarity: 0.97, resolution: 'Restore least privilege and narrow the tool scope for the affected agent.', outcome: 'success' },
      { incident_id: 'INC-2026-0059', similarity: 0.9, resolution: 'Remove the broad access grant and validate policy approval before resume.', outcome: 'success' },
    ],
  },
  'RES-AI-LEAK-014': {
    pattern: /sensitive data leakage|pii|payment data|customer data|exposed secrets/,
    recommendation: {
      resolution_id: 'RES-AI-LEAK-014',
      resolution: 'Contain the data exposure, block the leaking outbound response path, and audit sensitive content handling for the affected workflow.',
      response_domain: 'Data protection',
      priority: 'Critical',
      rationale: 'Sensitive content leakage can expose regulated data and trigger legal or compliance risk.',
      response_steps: ['Stop the affected response session and block outbound content matching the sensitive pattern.', 'Review logs for exposed PII or payment strings and identify the impacted customer data.', 'Apply content filtering controls and validate the security controls before resuming the workflow.'],
      confidence: 0.94,
      times_used: 3,
      successful_resolutions: 2,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0738', similarity: 0.97, resolution: 'Contain the data leak and tighten output filtering for the affected AI pipeline.', outcome: 'success' },
      { incident_id: 'INC-2026-0060', similarity: 0.92, resolution: 'Review and block the sensitive response path before re-enabling the workflow.', outcome: 'failed' },
    ],
  },
  'RES-AI-MODEL-015': {
    pattern: /model manipulation|poisoning|retrieval poisoning|context tampering/,
    recommendation: {
      resolution_id: 'RES-AI-MODEL-015',
      resolution: 'Remove the malicious context source, restore trusted retrieval policies, and validate model integrity before reactivation.',
      response_domain: 'Model trust',
      priority: 'High',
      rationale: 'Poisoned context can degrade model reasoning and bias behavior toward attacker-controlled instructions.',
      response_steps: ['Suspend retrieval and context ingestion for the affected workflow.', 'Review ingestion sources and remove suspicious documents or model context entries.', 'Rebuild trust signals, validate data provenance, and re-enable the model after policy review.'],
      confidence: 0.9,
      times_used: 1,
      successful_resolutions: 1,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0061', similarity: 0.94, resolution: 'Remove adversarial context and restore trusted retrieval sources.', outcome: 'success' },
      { incident_id: 'INC-2026-0817', similarity: 0.78, resolution: 'Quarantine the context source and validate model output integrity.', outcome: 'failed' },
    ],
  },
  'RES-AI-UNSAFE-016': {
    pattern: /unsafe tool invocation|unapproved code|outbound network operations|code interpreter/,
    recommendation: {
      resolution_id: 'RES-AI-UNSAFE-016',
      resolution: 'Suspend the unsafe tool execution, block the outbound action path, and enforce a stricter allowlist for approved tool calls.',
      response_domain: 'AI tool governance',
      priority: 'Critical',
      rationale: 'Tool execution outside expected operations can trigger network or code actions that bypass organizational controls.',
      response_steps: ['Block the unsafe tool call and suspend the current execution session.', 'Review any generated code, outbound requests, or files created by the tool invocation.', 'Reinstate the allowlist and verify the tool policy before enabling the agent again.'],
      confidence: 0.95,
      times_used: 2,
      successful_resolutions: 1,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0847', similarity: 0.97, resolution: 'Block the unsafe execution path and revalidate the tool policy.', outcome: 'success' },
      { incident_id: 'INC-2026-0062', similarity: 0.9, resolution: 'Suspend code execution and restrict network access from the affected tool.', outcome: 'failed' },
    ],
  },
  'RES-AI-HIJACK-017': {
    pattern: /goal hijacking|redirected agent|unauthorized account creation|agent objective hijack/,
    recommendation: {
      resolution_id: 'RES-AI-HIJACK-017',
      resolution: 'Suspend the hijacked agent objective, invalidate unauthorized task flow, and reinitialize the operational policy boundary.',
      response_domain: 'AI control plane',
      priority: 'Critical',
      rationale: 'Goal hijacking can steer an autonomous agent away from the approved task toward unauthorized or harmful actions.',
      response_steps: ['Pause the active autonomous workflow and revoke any unauthorized task actions.', 'Review the prompt and task transcript to identify the hijack vector.', 'Restore the approved operational objective and validate agent policy before returning to production.'],
      confidence: 0.92,
      times_used: 2,
      successful_resolutions: 1,
    },
    historical_matches: [
      { incident_id: 'INC-2026-0784', similarity: 0.96, resolution: 'Terminate the unauthorized objective flow and reinitialize the policy boundary.', outcome: 'success' },
      { incident_id: 'INC-2026-0063', similarity: 0.89, resolution: 'Suspend the hijacked agent and restore the original objective set.', outcome: 'failed' },
    ],
  },
  'RES-ISOLATE-002': {
    pattern: /./,
    recommendation: {
      resolution_id: 'RES-ISOLATE-002',
      resolution: 'Quarantine untrusted activity, preserve evidence, and verify the trusted policy before resuming.',
      response_domain: 'AI safety containment', priority: 'High',
      rationale: 'Untrusted inputs or tool activity should be isolated before they affect models, data, or systems.',
      response_steps: ['Pause the affected agent session and revoke unneeded tool access.', 'Preserve input, tool-call trace, and output for analyst review.', 'Validate trusted policy and scan for exposed secrets or unauthorized actions.'],
      confidence: 0.61, times_used: 0, successful_resolutions: 0,
    },
    historical_matches: [],
  },
};

function normalizeScenario(rawInput) {
  const text = typeof rawInput === 'string' ? rawInput : JSON.stringify(rawInput ?? {});
  const lower = text.toLowerCase();

  if (rawInput && typeof rawInput === 'object' && rawInput.incident_type) {
    const direct = rawInput.incident_type.toLowerCase();
    if (scenarioAliases[direct]) {
      return scenarioAliases[direct];
    }
  }

  for (const [alias, canonical] of Object.entries(scenarioAliases)) {
    if (lower.includes(alias)) {
      return canonical;
    }
  }

  return null;
}

function findProfile(rawInput) {
  const text = (typeof rawInput === 'string' ? rawInput : JSON.stringify(rawInput ?? {})).toLowerCase();
  const normalizedScenario = normalizeScenario(rawInput);

  if (normalizedScenario && scenarioToResolution[normalizedScenario]) {
    return resolutionProfiles[scenarioToResolution[normalizedScenario]];
  }

  return Object.values(resolutionProfiles).find((profile) => profile.pattern.test(text))
    ?? resolutionProfiles['RES-ISOLATE-002'];
}

function currentMetrics(profile) {
  const { times_used, successful_resolutions } = profile.recommendation;
  return {
    times_used,
    successful_resolutions,
    success_rate: times_used ? successful_resolutions / times_used : 0,
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  res.setHeader('Content-Type', 'application/json');
  const origin = req.headers.origin;
  if (origin === 'http://localhost:3000' || origin === 'http://127.0.0.1:3000') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }

  if (method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  try {
  if (method === 'POST' && url === '/api/investigate') {
    const payload = await readBody(req);
    const rawInput = payload.raw_input || '';
    const source = payload.source || 'RAW_SYSLOG_WEBHOOK';
    const profile = findProfile(rawInput);
    const severity = typeof rawInput === 'object' && rawInput !== null
      ? String(rawInput.severity ?? '').toLowerCase()
      : '';
    const recommendation = {
      ...profile.recommendation,
      ...currentMetrics(profile),
      priority: severity === 'critical' ? 'Critical' : profile.recommendation.priority,
    };
    const historicalMatches = profile.historical_matches.map((match) => ({ ...match }));
    const result = {
      is_cold_start: historicalMatches.length === 0,
      historical_matches: historicalMatches,
      recommendation,
      source,
      user_input_preview: typeof rawInput === 'string' ? rawInput.slice(0, 200) : rawInput,
    };

    res.statusCode = 200;
    res.end(JSON.stringify(result));
    return;
  }

  if (method === 'POST' && url === '/api/feedback') {
    const payload = await readBody(req);
    const profile = resolutionProfiles[payload.resolution_id];
    if (!profile || !['success', 'failed'].includes(payload.feedback_outcome)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Unknown resolution or invalid feedback outcome' }));
      return;
    }

    profile.recommendation.times_used += 1;
    if (payload.feedback_outcome === 'success') {
      profile.recommendation.successful_resolutions += 1;
    }
    profile.historical_matches.unshift({
      incident_id: payload.incident_id,
      similarity: 1,
      resolution: profile.recommendation.resolution,
      outcome: payload.feedback_outcome,
    });

    res.statusCode = 200;
    res.end(
      JSON.stringify({
        memory_updated: true,
        metrics: currentMetrics(profile),
        historical_matches: profile.historical_matches.map((match) => ({ ...match })),
        received: payload,
      })
    );
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: 'Not found' }));
  } catch (error) {
    res.statusCode = 400;
    res.end(JSON.stringify({ error: error instanceof Error ? error.message : 'Invalid request' }));
  }
});

server.listen(PORT, () => {
  console.log(`Mock CyberGuard API listening on http://localhost:${PORT}`);
});
