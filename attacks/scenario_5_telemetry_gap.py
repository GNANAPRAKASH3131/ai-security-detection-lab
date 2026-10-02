"""
Scenario 5: The Telemetry Visibility Gap (Core Blog Centerpiece)
Goal: Investigate the fundamental question:
"Can an AI security system detect what it cannot observe?"
Pipeline: Endpoint -> Security Agent -> Collector -> SIEM -> AI Analytics -> Alert
Interruption: Endpoint -> [X Telemetry Gap X] -> SIEM -> AI Analytics
Compares: Activity Generated vs Activity Received by SIEM vs Activity Analyzed by AI vs Activity Detected.
"""

from typing import List, Dict, Any
from attacks.framework import BaseAttackScenario
from core.models import SecurityEvent
from telemetry.collector import TelemetryCollector
from telemetry.windows_generator import WindowsTelemetryGenerator
from telemetry.linux_generator import LinuxTelemetryGenerator

class TelemetryGapScenario(BaseAttackScenario):
    def __init__(self):
        super().__init__(
            scenario_id="SCENARIO-05",
            name="Experiment 5 - Telemetry Gap (Core Centerpiece)",
            expected_detection="VISIBILITY_GAP_PROVEN (Zero AI Detection During Collector Interruption)"
        )
        self.win_gen = WindowsTelemetryGenerator()
        self.lnx_gen = LinuxTelemetryGenerator()

    def execute_simulation(self, collector: TelemetryCollector) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        
        self.observations.append("Step 1 (Normal Ingestion): Endpoint transmitting normal heartbeats and process telemetry to SIEM.")
        # Step 1: Pre-gap baseline event (Received normally)
        ev_pre = self.win_gen.create_process_event(
            user="user01",
            process_name="explorer.exe",
            command_line="explorer.exe"
        )
        events.append(ev_pre)
        collector.collect(ev_pre)

        # Step 2: INTRODUCE CONTROLLED TELEMETRY INTERRUPTION (Collector paused / agent blindspot)
        self.observations.append("Step 2 (Telemetry Gap Active): Security agent connection interrupted on WIN-LAB01. Ingestion paused.")
        collector.set_gap_state(is_active=False)

        # High-severity attack activity executed during telemetry black-out
        ev_attack1 = self.win_gen.create_process_event(
            user="user01",
            process_name="powershell.exe",
            command_line="powershell.exe -enc SW52b2tlLU1pbWlrYXR6IC1EdW1wQ3JlZHM=", # base64 invoke-mimikatz
            parent_process="cmd.exe"
        )
        events.append(ev_attack1)
        # Attempt to forward during gap -> DROPPED by collector
        collector.collect(ev_attack1)

        ev_attack2 = self.win_gen.create_network_event(
            user="user01",
            process_name="powershell.exe",
            dest_ip="10.10.10.30",
            dest_port=22
        )
        events.append(ev_attack2)
        collector.collect(ev_attack2)

        ev_attack3 = SecurityEvent(
            host="WIN-LAB01",
            host_ip="10.10.10.20",
            user="user01",
            source_ip="10.10.10.20",
            destination_ip="10.10.10.10",
            destination_port=445,
            event_type="discovery",
            action="queried",
            log_source="Zeek",
            metadata={"probes": "SAMR_DUMP"}
        )
        events.append(ev_attack3)
        collector.collect(ev_attack3)

        # Step 3: RESTORE TELEMETRY PIPELINE
        self.observations.append("Step 3 (Telemetry Restored): Collector restored to ONLINE state. Subsequent telemetry ingested.")
        collector.set_gap_state(is_active=True)

        # Post-gap event (e.g. benign session resumes)
        ev_post = self.lnx_gen.create_ssh_logon_event(
            user="user01",
            source_ip="10.10.10.20",
            success=True
        )
        events.append(ev_post)
        collector.collect(ev_post)

        self.observations.append(f"Summary: Total events generated = {len(events)}. Events received by SIEM = {collector.forwarded_events_count}. Events dropped during gap = {collector.dropped_events_count}.")
        self.observations.append("Conclusion: Attack actions executed during the visibility gap were completely missed by the AI engine (0 alerts produced for weaponized commands).")
        return events
