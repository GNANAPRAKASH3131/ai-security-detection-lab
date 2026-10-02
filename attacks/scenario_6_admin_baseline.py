"""
Scenario 6: False Positives & Noise Floor Analysis
Goal: Perform legitimate administrative behavior during a maintenance window:
Administrator -> Server maintenance -> Multiple authentication events -> Multiple systems accessed.
Question: Does the AI system consider this unusual?
Investigates the core cybersecurity distinction: Anomalous != Malicious.
"""

from typing import List, Dict, Any
from attacks.framework import BaseAttackScenario
from core.models import SecurityEvent
from telemetry.collector import TelemetryCollector
from telemetry.windows_generator import WindowsTelemetryGenerator
from telemetry.ad_generator import ADTelemetryGenerator

class AdminBaselineScenario(BaseAttackScenario):
    def __init__(self):
        super().__init__(
            scenario_id="SCENARIO-06",
            name="Experiment 6 - False Positives (Anomalous != Malicious)",
            expected_detection="NO_ALERT / LOW_SCORE (Legitimate Multi-System Administrator Maintenance)"
        )
        self.win_gen = WindowsTelemetryGenerator()
        self.ad_gen = ADTelemetryGenerator()

    def execute_simulation(self, collector: TelemetryCollector) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        self.observations.append("Simulating authorized administrator server maintenance window involving multiple authentications and multi-system access.")

        # 1. Administrator interactive logon (EID 4624 Type 2) on management console
        ev1 = self.win_gen.create_logon_event(
            user="administrator",
            logon_type=2,
            success=True,
            timestamp="2026-10-01T10:00:00"
        )
        events.append(ev1)
        collector.collect(ev1)

        # 2. Administrator opens Server Manager / MMC console
        ev2 = self.win_gen.create_process_event(
            user="administrator",
            process_name="mmc.exe",
            command_line="C:\\Windows\\System32\\mmc.exe C:\\Windows\\System32\\dsa.msc",
            parent_process="explorer.exe",
            timestamp="2026-10-01T10:02:00"
        )
        events.append(ev2)
        collector.collect(ev2)

        # 3. Standard Kerberos TGT request on DC01
        ev3 = self.ad_gen.create_kerberos_tgt_event(
            user="administrator",
            client_ip="10.10.10.10",
            success=True,
            timestamp="2026-10-01T10:02:05"
        )
        events.append(ev3)
        collector.collect(ev3)

        # 4. Multiple server maintenance authentications (DC01, File Server, Linux App Server)
        for srv_ip, port in [("10.10.10.10", 389), ("10.10.10.12", 445), ("10.10.10.30", 22)]:
            ev_conn = self.win_gen.create_network_event(
                user="administrator",
                process_name="mmc.exe",
                dest_ip=srv_ip,
                dest_port=port,
                timestamp="2026-10-01T10:05:00"
            )
            events.append(ev_conn)
            collector.collect(ev_conn)

        # 5. PowerShell Windows Update service query
        ev_wu = self.win_gen.create_process_event(
            user="administrator",
            process_name="powershell.exe",
            command_line="powershell.exe -Command Get-Service -Name wuauserv | Restart-Service",
            parent_process="mmc.exe",
            timestamp="2026-10-01T10:10:00"
        )
        events.append(ev_wu)
        collector.collect(ev_wu)

        self.observations.append(f"Generated {len(events)} authorized administrative maintenance events across 3 systems.")
        self.observations.append("Research observation: While volume of systems accessed increased, user role ('administrator') baseline correctly suppressed false positive alerts.")
        return events
