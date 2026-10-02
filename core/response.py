"""
Automated Response (SOAR Simulation) Engine
Executes SAFE, non-destructive response actions for lab research.
Never disables host networking or harms actual system assets.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from core.models import DetectionAlert, ResponseAction

class AutomatedResponseEngine:
    """
    Evaluates alerts and triggers simulated, safe containment actions.
    Records decisions, policies, and remediation outcomes for audit.
    """

    def __init__(self):
        self.action_history: List[ResponseAction] = []
        self.isolated_hosts: Dict[str, Dict[str, Any]] = {}
        self.flagged_accounts: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}

    def evaluate_and_respond(self, alert: DetectionAlert) -> Optional[ResponseAction]:
        """Determine appropriate response policy based on alert severity and anomaly score."""
        action: Optional[ResponseAction] = None

        # Policy 1: Critical / High Anomaly (Score >= 0.80) -> Simulated Host Isolation + Account Flag
        if alert.anomaly_score >= 0.80 or alert.severity == "CRITICAL":
            self.isolated_hosts[alert.host] = {
                "isolated_at": datetime.now().isoformat(),
                "reason": alert.rule_name,
                "score": alert.anomaly_score
            }
            self.flagged_accounts[alert.user] = {
                "flagged_at": datetime.now().isoformat(),
                "status": "REQUIRES_SOC_INVESTIGATION",
                "reason": alert.description
            }
            action = ResponseAction(
                alert_id=alert.alert_id,
                target_host=alert.host,
                target_user=alert.user,
                action_type="SIMULATED_HOST_ISOLATION_AND_ACCOUNT_FLAG",
                status="EXECUTED_SAFE_SIMULATION",
                details=f"[SAFE LAB SIMULATION] Host '{alert.host}' isolated on software-switch port; User '{alert.user}' flagged for session termination.",
                remediation_notes="Requires Tier 2 Analyst triage before releasing network segment."
            )

        # Policy 2: Medium-High Anomaly (Score 0.61 - 0.79) -> Flag Account + Generate Investigation Ticket
        elif alert.anomaly_score >= 0.61 or alert.severity == "HIGH":
            self.flagged_accounts[alert.user] = {
                "flagged_at": datetime.now().isoformat(),
                "status": "REQUIRES_SOC_INVESTIGATION",
                "reason": alert.description
            }
            action = ResponseAction(
                alert_id=alert.alert_id,
                target_host=alert.host,
                target_user=alert.user,
                action_type="SIMULATED_ACCOUNT_INVESTIGATION_FLAG",
                status="EXECUTED_SAFE_SIMULATION",
                details=f"[SAFE LAB SIMULATION] User '{alert.user}' flagged for behavioral review; Generated SOC Ticket for host '{alert.host}'.",
                remediation_notes="Review authentication logs in SIEM; check for concurrent interactive sessions."
            )

        # Policy 3: Traditional Rule / Discovery -> Simulated IP Block
        elif "Scan" in alert.rule_name or "Discovery" in alert.rule_name:
            src_ip = alert.host
            self.blocked_ips[src_ip] = {
                "blocked_at": datetime.now().isoformat(),
                "reason": alert.rule_name
            }
            action = ResponseAction(
                alert_id=alert.alert_id,
                target_host=alert.host,
                target_user=alert.user,
                action_type="SIMULATED_IP_BLOCK",
                status="EXECUTED_SAFE_SIMULATION",
                details=f"[SAFE LAB SIMULATION] Added temporary firewall drop rule for internal scanning host '{alert.host}'.",
                remediation_notes="Internal reconnaissance containment rule applied."
            )

        if action:
            self.action_history.append(action)
            alert.response_triggered = action.action_type

        return action

    def get_status(self) -> Dict[str, Any]:
        return {
            "total_actions": len(self.action_history),
            "isolated_hosts": list(self.isolated_hosts.keys()),
            "flagged_accounts": list(self.flagged_accounts.keys()),
            "blocked_ips": list(self.blocked_ips.keys())
        }
