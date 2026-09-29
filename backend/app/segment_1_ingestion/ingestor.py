"""
Segment 1: Alert Ingestion & Parsing Engine
Responsible for parsing raw syslog streams, webhooks, or API requests into normalized incident objects.
"""
import json
from typing import Dict, Any, Tuple

SCENARIO_ALIASES = {
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
}

class AlertIngestor:
    @staticmethod
    def parse_raw_input(raw_input: Any) -> Tuple[str, str, Dict[str, Any]]:
        """
        Parses raw string or object input and returns (normalized_scenario, severity, metadata).
        """
        if isinstance(raw_input, dict):
            text = json.dumps(raw_input).lower()
            severity = str(raw_input.get('severity', 'High')).capitalize()
        else:
            text = str(raw_input).lower()
            severity = 'Critical' if 'critical' in text else 'High'

        normalized_scenario = 'Generic Security Event'
        for alias, canonical in SCENARIO_ALIASES.items():
            if alias in text:
                normalized_scenario = canonical
                break

        return normalized_scenario, severity, {"raw_text": text}
