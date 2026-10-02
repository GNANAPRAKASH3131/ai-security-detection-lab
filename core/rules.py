"""
Traditional Signature & Threshold Detection Rules (SIEM / Sigma-style Rules)
Distinguished explicitly from AI/behavioral anomaly detection.
"""

from typing import List, Dict, Any, Optional
from core.models import SecurityEvent, DetectionAlert
import re

class RuleResult:
    def __init__(self, triggered: bool, rule_name: str, severity: str, description: str, score_contribution: float = 0.0):
        self.triggered = triggered
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.score_contribution = score_contribution

class TraditionalRuleEngine:
    """Evaluates deterministic, signature-based, and heuristic rules against events."""

    def __init__(self):
        # State buffers for sliding window/threshold rules
        self.failed_logins: Dict[str, List[float]] = {}  # user -> timestamps
        self.port_scan_tracker: Dict[str, set] = {}     # src_ip -> set(dest_ports)

    def evaluate_event(self, event: SecurityEvent) -> List[RuleResult]:
        results: List[RuleResult] = []

        # 1. Rule: Suspicious PowerShell Reconnaissance Command
        if event.process_name and ("powershell" in event.process_name.lower() or "pwsh" in event.process_name.lower()):
            cmd = (event.command_line or "").lower()
            suspicious_patterns = [
                "net group \"domain admins\"",
                "get-aduser",
                "get-domaincontroller",
                "bloodhound",
                "sharphound",
                "mimikatz",
                "invoke-command",
                "whoami /all",
                "nltest /dclist",
                "net view"
            ]
            for pat in suspicious_patterns:
                if pat in cmd:
                    results.append(RuleResult(
                        triggered=True,
                        rule_name="SIG-WIN-001: Active Directory Discovery via Command Line",
                        severity="MEDIUM",
                        description=f"Detected internal discovery command matching signature pattern: '{pat}' executed by {event.user}.",
                        score_contribution=0.35
                    ))
                    break

        # 2. Rule: Repeated Failed Authentication / Brute-force Threshold (e.g. >= 5 failures)
        if event.event_type == "authentication" and event.action == "failure":
            user_key = f"{event.host}:{event.user}"
            # In a real environment, timestamps would be tracked in sliding windows
            current_count = event.metadata.get("consecutive_failures", 1)
            if current_count >= 5:
                results.append(RuleResult(
                    triggered=True,
                    rule_name="SIG-AUTH-002: Multiple Failed Authentication Attempts (Brute Force/Spray)",
                    severity="HIGH",
                    description=f"Host {event.host} reported {current_count} consecutive failed authentication attempts for user '{event.user}'.",
                    score_contribution=0.50
                ))

        # 3. Rule: Pass-the-Hash / Overpass-the-Hash Indicator (Logon Type 9 with New Credentials or EID 4624 Type 9/3 mismatch)
        if event.event_code == 4624:
            logon_type = event.metadata.get("logon_type")
            auth_package = event.metadata.get("auth_package", "").upper()
            if logon_type == 9 and "KERBEROS" not in auth_package:
                results.append(RuleResult(
                    triggered=True,
                    rule_name="SIG-WIN-003: Suspicious Explicit Credential Usage (LogonType 9 / PTH)",
                    severity="HIGH",
                    description=f"Suspicious LogonType 9 with non-standard package on host {event.host} for user {event.user}.",
                    score_contribution=0.45
                ))

        # 4. Rule: Linux Sudo Privilege Elevation by Non-Standard Sudoer
        if event.log_source in ("AuthLog", "Auditd", "Syslog") and event.event_type == "privilege_elevation":
            if event.user not in ("root", "administrator", "analyst") and event.action == "executed":
                results.append(RuleResult(
                    triggered=True,
                    rule_name="SIG-LNX-004: Unauthorized or Unaudited Sudo Execution",
                    severity="HIGH",
                    description=f"Non-admin user '{event.user}' executed privileged command via sudo on {event.host}: '{event.command_line}'.",
                    score_contribution=0.60
                ))

        # 5. Rule: Port Scanning / Rapid Multi-Port Connection Pattern
        if event.event_type == "discovery" and event.metadata.get("probed_ports_count", 0) > 10:
            results.append(RuleResult(
                triggered=True,
                rule_name="SIG-NET-005: Internal Port Scan / Service Sweep Detected",
                severity="MEDIUM",
                description=f"Source {event.source_ip} probed {event.metadata.get('probed_ports_count')} ports on target {event.destination_ip} in short duration.",
                score_contribution=0.40
            ))

        # 6. Rule: Windows Service Creation (EID 7045 / Sysmon EID 13)
        if event.event_code == 7045 or event.event_type == "service_creation":
            srv_name = (event.service_name or "").lower()
            if any(k in srv_name for k in ["psexec", "psexesvc", "csexec", "winexesvc", "paexec"]):
                results.append(RuleResult(
                    triggered=True,
                    rule_name="SIG-WIN-006: PsExec/Lateral Movement Remote Service Installed",
                    severity="CRITICAL",
                    description=f"Remote execution service installed on {event.host}: '{event.service_name}' by user '{event.user}'.",
                    score_contribution=0.80
                ))

        return results
