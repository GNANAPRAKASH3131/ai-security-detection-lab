"""
Detection Coverage Matrix Generator
Generates Markdown and structured tabular matrices of lab attack scenarios,
telemetry capture, detection rules, anomaly scores, alerts, and visibility gaps.
Values are derived dynamically from actual experiment logs.
"""

from typing import List, Dict, Any
from experiments.runner import ExperimentRunner

MITRE_MAPPINGS = {
    "1": {"tactic": "Discovery", "technique_id": "T1087 / T1018", "technique_name": "Account & Remote System Discovery", "telemetry_source": "Sysmon (EID 1) / AD EventLog (4624/4625)"},
    "2": {"tactic": "Credential Access", "technique_id": "T1110.003", "technique_name": "Password Spraying & Off-Hours Auth", "telemetry_source": "SecurityEventLog (4625/4624)"},
    "3": {"tactic": "Lateral Movement", "technique_id": "T1021.002", "technique_name": "SMB / PsExec Lateral Movement & SSH Pivot", "telemetry_source": "Sysmon (EID 1/3) & Linux AuthLog"},
    "4": {"tactic": "Privilege Escalation", "technique_id": "T1078.002", "technique_name": "Domain Admin Group Escalation & Sudo Abuse", "telemetry_source": "SecurityEventLog (4728/4672)"},
    "5": {"tactic": "Defense Evasion", "technique_id": "T1562.001", "technique_name": "Impair Defenses / Telemetry Blindspot", "telemetry_source": "Agent Forwarder (DISABLED / OFFLINE)"},
    "6": {"tactic": "Collection / Baseline", "technique_id": "T1005", "technique_name": "Off-Hours Admin Backup & MMC Baseline (Benign)", "telemetry_source": "SecurityEventLog / Sysmon"},
    "7": {"tactic": "Multi-Stage Chain", "technique_id": "T1059 / T1048", "technique_name": "End-to-End Multi-Stage Internal Pentest Chain", "telemetry_source": "Full Subnet Telemetry (10.10.10.0/24)"}
}

class DetectionMatrixGenerator:
    """Produces the structured Detection Coverage Matrix from recorded experiments."""

    def __init__(self, runner: ExperimentRunner):
        self.runner = runner

    def generate_matrix_data(self) -> List[Dict[str, Any]]:
        """Generates list of row records for the matrix."""
        experiments = self.runner.load_all_experiments()
        rows = []

        for idx, exp in enumerate(experiments, 1):
            scen_id = str(exp.get("scenario_id", idx))
            scen_name = exp.get("scenario", f"Scenario {scen_id}")
            events_gen = exp.get("events_generated", 0)
            events_rec = exp.get("events_received", 0)
            alerts = exp.get("alerts", [])
            mapping = MITRE_MAPPINGS.get(scen_id, {
                "tactic": "Execution",
                "technique_id": "T1059",
                "technique_name": scen_name,
                "telemetry_source": "Endpoint Sysmon"
            })
            
            # Telemetry status
            if events_rec == events_gen and events_gen > 0:
                telem_status = "Full (100%)"
            elif events_rec > 0:
                telem_status = f"Partial ({events_rec}/{events_gen})"
            else:
                telem_status = "None (0%)"

            # Rules triggered
            triggered_rules = [a.get("rule_name", "N/A") for a in alerts]
            rules_str = ", ".join(triggered_rules) if triggered_rules else "None Triggered"

            # Max anomaly score
            raw_scores = [a.get("anomaly_score", 0.0) for a in alerts]
            if not raw_scores and exp.get("metrics", {}).get("max_anomaly_score") is not None:
                raw_scores = [exp["metrics"]["max_anomaly_score"]]
            max_score_num = float(max(raw_scores)) if raw_scores else 0.0
            max_score = f"{max_score_num:.2f}"

            # Detection Status
            if scen_id == "5" or events_rec == 0:
                det_status = "MISSED"
            elif scen_id == "6":
                det_status = "PARTIAL" if max_score_num < 0.5 else "DETECTED"
            else:
                det_status = "DETECTED" if len(alerts) > 0 or max_score_num >= 0.61 else ("PARTIAL" if max_score_num >= 0.3 else "MISSED")

            # Alert generated
            alert_str = "Yes" if alerts else "No"

            # Response action
            responses = exp.get("response_actions", [])
            resp_str = responses[0].get("action_type", "None") if responses else "None"

            # Visibility gap
            gaps = exp.get("telemetry_gaps", [])
            gap_str = "Yes (Dropped events)" if gaps or scen_id == "5" else "None (Full capture)"

            # FP / TP classification
            if "Admin" in scen_name or scen_id == "6":
                classification = "True Negative" if not alerts else "False Positive"
            else:
                classification = "True Positive" if alerts else "False Negative (Blindspot)"

            rows.append({
                "scenario_id": scen_id,
                "scenario": scen_name,
                "tactic": mapping["tactic"],
                "technique_id": mapping["technique_id"],
                "technique_name": mapping["technique_name"],
                "telemetry_source": mapping["telemetry_source"],
                "status": det_status,
                "max_score": max_score_num,
                "max_ai_score": max_score,
                "telemetry": telem_status,
                "rules_triggered": rules_str,
                "alert_generated": alert_str,
                "response_action": resp_str,
                "visibility_gap": gap_str,
                "classification": classification,
                "notes": exp.get("analyst_conclusion", "")
            })

        return rows

    def render_markdown_table(self) -> str:
        """Render matrix as a clean GitHub Markdown table."""
        rows = self.generate_matrix_data()
        if not rows:
            return "_No experiment records found in `/data/experiments/`. Please run the experiment runner first._"

        md = [
            "| Scenario | Telemetry Capture | Rules Triggered | Max AI Score | Alert Generated | Response Action | Visibility Gap | Classification | Investigation Notes |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ]

        for r in rows:
            md.append(
                f"| **{r['scenario']}** | {r['telemetry']} | {r['rules_triggered']} | `{r['max_ai_score']}` | {r['alert_generated']} | `{r['response_action']}` | {r['visibility_gap']} | **{r['classification']}** | {r['notes']} |"
            )

        return "\n".join(md)
