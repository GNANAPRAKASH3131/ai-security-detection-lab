"""
Experiment Runner Suite
Executes research scenarios, records telemetry, saves experimental evidence to /data/experiments/,
and coordinates the multi-scenario lifecycle.
"""

from typing import List, Dict, Any, Optional
import json
from pathlib import Path
from core.siem import SIEMEngine
from telemetry.collector import TelemetryCollector
from core.config import EXPERIMENTS_DIR
from core.models import ExperimentRecord
from core.db import db

# Import Scenarios
from attacks.scenario_1_recon import InternalReconScenario
from attacks.scenario_2_auth_anomaly import AuthAnomalyScenario
from attacks.scenario_3_lateral_movement import LateralMovementScenario
from attacks.scenario_4_privilege_activity import PrivilegeActivityScenario
from attacks.scenario_5_telemetry_gap import TelemetryGapScenario
from attacks.scenario_6_admin_baseline import AdminBaselineScenario
from attacks.scenario_7_attack_chain import Scenario7CompleteAttackChain

SCENARIO_MAP = {
    "1": InternalReconScenario,
    "2": AuthAnomalyScenario,
    "3": LateralMovementScenario,
    "4": PrivilegeActivityScenario,
    "5": TelemetryGapScenario,
    "6": AdminBaselineScenario,
    "7": Scenario7CompleteAttackChain,
    "recon": InternalReconScenario,
    "auth": AuthAnomalyScenario,
    "lateral": LateralMovementScenario,
    "privilege": PrivilegeActivityScenario,
    "gap": TelemetryGapScenario,
    "admin": AdminBaselineScenario,
    "chain": Scenario7CompleteAttackChain
}

class ExperimentRunner:
    """Manages execution, logging, and evaluation of all pentest research scenarios."""

    def __init__(self):
        self.siem = SIEMEngine()
        self.collector = TelemetryCollector(self.siem)
        self.results: List[ExperimentRecord] = []
        self.db = db

    def run_scenario(self, scenario_key: str) -> Optional[ExperimentRecord]:
        """Run single scenario by key (e.g. '1', '2', 'gap')."""
        scenario_cls = SCENARIO_MAP.get(str(scenario_key).lower())
        if not scenario_cls:
            print(f"[-] Unknown scenario key: {scenario_key}")
            return None

        # Reset state for clean experiment isolation
        self.siem.reset()
        self.collector.reset_stats()

        scenario_instance = scenario_cls()
        print(f"\n[*] Executing {scenario_instance.scenario_id}: {scenario_instance.name}...")
        
        record = scenario_instance.run(self.collector, self.siem)
        self.results.append(record)

        # Save experiment record to /data/experiments/
        exp_file = EXPERIMENTS_DIR / f"experiment-{scenario_instance.scenario_id.lower()}.json"
        record.save(str(exp_file))
        
        # Save detailed SIEM session log to /data/logs/
        self.siem.dump_session_logs(f"siem_session_{scenario_instance.scenario_id.lower()}.json")

        # Auto-save to persistent database (PostgreSQL / SQLite)
        try:
            self.db.save_experiment(record.to_dict())
        except Exception as e:
            print(f"[-] DB save warning: {e}")
        
        print(f"[+] Experiment record saved to {exp_file.name} & Database ({self.db.active_engine})")
        print(f"    - Generated: {record.events_generated} events | Received: {record.events_received} | Alerts: {len(record.alerts)}")
        print(f"    - Max Anomaly Score: {record.metrics.get('max_anomaly_score', 0.0):.2f}")
        return record

    def run_all(self) -> List[ExperimentRecord]:
        """Run all 6 research scenarios in sequence."""
        self.results.clear()
        print("\n" + "="*70)
        print(" STARTING COMPLETE RESEARCH EXPERIMENT SUITE (SCENARIOS 1-7)")
        print("="*70)

        for key in ["1", "2", "3", "4", "5", "6", "7"]:
            self.run_scenario(key)

        print("\n" + "="*70)
        print(" ALL RESEARCH EXPERIMENTS COMPLETED")
        print("="*70)
        return self.results

    def load_all_experiments(self) -> List[Dict[str, Any]]:
        """Load all saved experiment records from disk."""
        records = []
        for json_file in sorted(EXPERIMENTS_DIR.glob("*.json")):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    records.append(json.load(f))
            except Exception as e:
                print(f"[-] Error reading {json_file}: {e}")
        return records
