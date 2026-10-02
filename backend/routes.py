"""
Backend API Route Handlers & Controllers
Provides modular handling for all AI Security Detection Lab REST endpoints.
"""

import json
from pathlib import Path
from typing import Dict, Any, Tuple, List
from experiments.runner import ExperimentRunner
from experiments.matrix_generator import DetectionMatrixGenerator
from experiments.telemetry_failure import TelemetryFailureExperiment
from experiments.report_generator import ResearchReportGenerator
from core.baseline import BaselineEngine
from core.log_analyzer import LogAnalyzer
from core.db import db
from core.config import EXPERIMENTS_DIR, LOGS_DIR, BASELINES_DIR

class LabApiController:
    def __init__(self):
        self.runner = ExperimentRunner()
        self.matrix_gen = DetectionMatrixGenerator(self.runner)
        self.failure_exp = TelemetryFailureExperiment(self.runner)
        self.report_gen = ResearchReportGenerator(self.runner)
        self.baseline_engine = BaselineEngine()
        self.log_analyzer = LogAnalyzer()
        self.db = db

    def handle_health(self) -> Tuple[int, Dict[str, Any]]:
        return 200, {
            "status": "healthy",
            "service": "AI Security Detection Lab API",
            "version": "2.0.0",
            "network": "10.10.10.0/24 (Simulated Lab Subnet)",
            "experiments_count": len(self.runner.load_all_experiments()),
            "logs_count": len(list(LOGS_DIR.glob("*.json"))),
            "telemetry_health": self.runner.collector.get_health_status(),
            "database": self.db.get_status()
        }

    def handle_get_db_status(self) -> Tuple[int, Dict[str, Any]]:
        return 200, self.db.get_status()

    def handle_sync_db(self) -> Tuple[int, Dict[str, Any]]:
        sync_result = self.db.sync_from_filesystem()
        return 200, {
            "status": "success",
            "message": "Database synchronized with filesystem records.",
            "sync": sync_result,
            "db_status": self.db.get_status()
        }

    def handle_get_experiments(self) -> Tuple[int, Any]:
        experiments = self.runner.load_all_experiments()
        return 200, experiments

    def handle_get_matrix(self) -> Tuple[int, Dict[str, Any]]:
        matrix_data = self.matrix_gen.generate_matrix_data()
        return 200, {
            "status": "success",
            "matrix": matrix_data
        }

    def handle_get_failure_analysis(self) -> Tuple[int, Dict[str, Any]]:
        metrics = self.failure_exp.execute_experiment()
        return 200, metrics

    def handle_get_baselines(self) -> Tuple[int, Dict[str, Any]]:
        from core.config import ANOMALY_THRESHOLDS
        established = self.baseline_engine.get_established_baseline()
        user_profiles = {
            user: baseline.to_dict() 
            for user, baseline in self.runner.siem.analytics_engine.baselines.items()
        }
        return 200, {
            "status": "success",
            "established": established,
            "user_profiles": user_profiles,
            "anomaly_thresholds": ANOMALY_THRESHOLDS
        }

    def handle_establish_baseline(self) -> Tuple[int, Dict[str, Any]]:
        res = self.baseline_engine.establish_normal_baseline()
        return 200, {
            "status": "success",
            "message": "Normal baseline established and recorded successfully.",
            "data": res
        }

    def handle_get_telemetry_health(self) -> Tuple[int, Dict[str, Any]]:
        status = self.runner.collector.get_health_status()
        return 200, status

    def handle_update_telemetry_health(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        component = payload.get("component", "")
        state = payload.get("state", "ONLINE")
        
        if component:
            self.runner.collector.set_component_health(component, state)
            
        # Support batch update of components
        components = payload.get("components", {})
        for comp, st in components.items():
            self.runner.collector.set_component_health(comp, st)

        return 200, {
            "status": "success",
            "message": f"Telemetry health state updated.",
            "health": self.runner.collector.get_health_status()
        }

    def handle_get_research_findings(self) -> Tuple[int, Dict[str, Any]]:
        """
        Synthesizes overall lab findings structured into:
        - DETECTED (Why?)
        - MISSED (Why?)
        - PARTIAL (Why?)
        - Internal Pentest Analysis
        - Recommendations
        """
        experiments = self.runner.load_all_experiments()
        
        findings = {
            "core_question": "If an internal attacker is already inside the network, what does an AI-based security system see, what does it miss, and why?",
            "total_experiments_evaluated": len(experiments),
            "taxonomy": {
                "detected": {
                    "count": sum(1 for e in experiments if e.get("metrics", {}).get("detection_triggered") and e.get("metrics", {}).get("telemetry_coverage_pct", 0) > 80),
                    "summary": "Attacks traversing monitored log sources with sharp baseline deviations were reliably detected.",
                    "reasons": [
                        "High Destination Host Novelty: Standard client attempting direct connection to DC01 or Linux Server.",
                        "Volume & Burst Velocity: 5+ failed logons in <60 seconds triggered anomaly score > 0.80.",
                        "High-Risk Process Names: Known pentest binaries (nltest, net group, psexec) heavily penalize the rare process score.",
                        "Direct Privilege Jumps: Non-admin adding themselves to Domain Admins triggers an immediate 0.96 anomaly score."
                    ]
                },
                "missed": {
                    "count": sum(1 for e in experiments if not e.get("metrics", {}).get("detection_triggered") or e.get("metrics", {}).get("telemetry_coverage_pct", 0) < 50),
                    "summary": "Attacks executed during telemetry gaps or with zero forwarding were completely invisible to the AI engine.",
                    "reasons": [
                        "Telemetry Interruption: An AI model cannot detect what it cannot observe (0 events received = 0 score).",
                        "Silent Endpoint Execution: Unforwarded Sysmon / PowerShell script block logs create a total detection black-out.",
                        "Agent Tampering: Disabling or choking the collector allows arbitrary weaponized commands without alerts."
                    ]
                },
                "partial": {
                    "count": sum(1 for e in experiments if e.get("metrics", {}).get("telemetry_coverage_pct", 100) < 100 and e.get("metrics", {}).get("telemetry_coverage_pct", 100) > 0),
                    "summary": "Attacks traversing mixed monitored and unmonitored segments yielded fragmented incident alerts.",
                    "reasons": [
                        "Single-Log Source Dependence: If network telemetry is down, port sweeps appear only as individual process spawns.",
                        "Intermittent Ingestion: Partial packet drops lower anomaly velocity calculations below alerting thresholds."
                    ]
                }
            },
            "internal_pentest_analysis": [
                "1. Living off the Land (LotL) commands that mimic administrative utilities during active business hours have the highest stealth profile.",
                "2. Statistical anomaly detection struggles when adversaries execute single-shot commands spaced over hours (low-and-slow).",
                "3. Telemetry health is the single biggest attack surface: attacking the logging agent provides complete cover."
            ],
            "recommendations": [
                "Deploy independent out-of-band network monitoring (Zeek/Suricata) to detect lateral movement even if endpoint agents are silenced.",
                "Implement strict Heartbeat Loss alerts (<60s) for all workstation and server logging agents.",
                "Enforce dual-layer detection: use rigid deterministic signatures alongside behavioral models.",
                "Enforce Just-In-Time (JIT) and Privileged Access Management (PAM) to minimize persistent domain admin rights."
            ]
        }
        return 200, findings

    def handle_get_logs(self) -> Tuple[int, Dict[str, Any]]:
        """List available log files and recent events."""
        log_files = []
        for f in sorted(LOGS_DIR.glob("*.json"), reverse=True):
            try:
                log_files.append({
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                    "modified": f.stat().st_mtime
                })
            except Exception:
                pass

        # Collect recent events across all executed scenarios
        all_events = []
        experiments = self.runner.load_all_experiments()
        for exp in experiments:
            for al in exp.get("alerts", []):
                all_events.append({
                    "timestamp": exp.get("start_time", ""),
                    "host": al.get("host", "WIN-LAB01"),
                    "user": al.get("user", "user01"),
                    "event_type": "ALERT_TRIGGERED",
                    "source": "SIEM_ENGINE",
                    "severity": al.get("severity", "MEDIUM"),
                    "rule": al.get("rule_name", "Anomaly"),
                    "score": al.get("anomaly_score", 0.0),
                    "details": al.get("description", "")
                })

        return 200, {
            "status": "success",
            "log_files": log_files,
            "recent_events": all_events
        }

    def handle_get_log_content(self, filename: str) -> Tuple[int, Dict[str, Any]]:
        """Read content of a specific log file in /data/logs/."""
        safe_filename = Path(filename).name
        target = LOGS_DIR / safe_filename
        if not target.exists():
            target = EXPERIMENTS_DIR / safe_filename

        if not target.exists():
            return 404, {"status": "error", "message": f"Log file '{safe_filename}' not found."}

        try:
            with open(target, "r", encoding="utf-8") as f:
                content = json.load(f) if target.suffix == ".json" else f.read()
            return 200, {
                "status": "success",
                "filename": safe_filename,
                "content": content
            }
        except Exception as e:
            return 500, {"status": "error", "message": str(e)}

    def handle_analyze_logs(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """Analyze raw text logs or JSON event lists."""
        content = payload.get("content", "")
        if not content:
            return 400, {"status": "error", "message": "Missing 'content' in log analysis request."}

        analysis = self.log_analyzer.analyze_log_content(content)
        return 200, analysis

    def handle_run_scenario(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        scenario_id = str(payload.get("scenario_id", "1"))
        record = self.runner.run_scenario(scenario_id)
        if record:
            return 200, {
                "status": "success",
                "scenario_id": scenario_id,
                "experiment": record.to_dict()
            }
        return 400, {
            "status": "error",
            "message": f"Invalid scenario ID '{scenario_id}'. Choose from 1 to 7."
        }

    def handle_run_all(self) -> Tuple[int, Dict[str, Any]]:
        records = self.runner.run_all()
        return 200, {
            "status": "success",
            "count": len(records),
            "experiments": [r.to_dict() for r in records]
        }

    def handle_generate_report(self) -> Tuple[int, Dict[str, Any]]:
        report_path = self.report_gen.generate_report()
        with open(report_path, "r", encoding="utf-8") as f:
            report_content = f.read()

        return 200, {
            "status": "success",
            "report_path": str(report_path),
            "report_markdown": report_content
        }

    def handle_reset_lab(self) -> Tuple[int, Dict[str, Any]]:
        exp_deleted = 0
        logs_deleted = 0
        for f in EXPERIMENTS_DIR.glob("*.json"):
            f.unlink()
            exp_deleted += 1
        for f in LOGS_DIR.glob("*.json"):
            f.unlink()
            logs_deleted += 1

        # Re-establish clean baseline
        self.baseline_engine.establish_normal_baseline()

        return 200, {
            "status": "success",
            "message": f"Lab wiped cleanly: {exp_deleted} experiments, {logs_deleted} logs deleted. Baseline re-established.",
            "experiments_cleared": exp_deleted,
            "logs_cleared": logs_deleted
        }
