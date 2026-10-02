"""
Scenario 1: Internal Reconnaissance & Discovery Simulation
Goal: Simulate an attacker who has already obtained internal access.
Measures: Events generated -> Events collected -> Events analyzed -> Traditional detection -> Behavior anomaly -> Alert -> Detection delay.
"""

from typing import List
from attacks.framework import BaseAttackScenario
from core.models import SecurityEvent
from telemetry.collector import TelemetryCollector
from telemetry.windows_generator import WindowsTelemetryGenerator

class InternalReconScenario(BaseAttackScenario):
    def __init__(self):
        super().__init__(
            scenario_id="SCENARIO-01",
            name="Experiment 1 - Internal Discovery",
            expected_detection="SIG-WIN-001 (AD Discovery) + Zeek Port Sweep Anomaly"
        )
        self.win_gen = WindowsTelemetryGenerator()

    def execute_simulation(self, collector: TelemetryCollector) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        self.observations.append("Simulating internal host and Active Directory domain discovery commands from WIN-LAB01.")

        # 1. Process: Net group domain admins enumeration (Sysmon EID 1)
        ev1 = self.win_gen.create_process_event(
            user="user01",
            process_name="powershell.exe",
            command_line="powershell.exe -Command net group \"domain admins\" /domain",
            parent_process="explorer.exe"
        )
        events.append(ev1)
        collector.collect(ev1)

        # 2. Process: nltest DC list discovery
        ev2 = self.win_gen.create_process_event(
            user="user01",
            process_name="nltest.exe",
            command_line="nltest /dclist:corp.lab",
            parent_process="powershell.exe"
        )
        events.append(ev2)
        collector.collect(ev2)

        # 3. Process: whoami privileges inspection
        ev3 = self.win_gen.create_process_event(
            user="user01",
            process_name="cmd.exe",
            command_line="cmd.exe /c whoami /all",
            parent_process="powershell.exe"
        )
        events.append(ev3)
        collector.collect(ev3)

        # 4. Process: net localgroup administrators
        ev4 = self.win_gen.create_process_event(
            user="user01",
            process_name="net.exe",
            command_line="net localgroup administrators",
            parent_process="cmd.exe"
        )
        events.append(ev4)
        collector.collect(ev4)

        # 5. Network Discovery: Controlled multi-host, multi-port sweep generating total 150 events
        target_hosts = ["10.10.10.10", "10.10.10.30", "10.10.10.1", "10.10.10.5", "10.10.10.15", "10.10.10.25"]
        probed_ports = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 1433, 1521, 3306, 3389, 5432, 5985, 8080, 8443, 9000, 9200]
        
        # Remaining events to reach exactly 150 total events
        target_event_count = 150
        remaining_needed = target_event_count - len(events)
        
        idx = 0
        while len(events) < target_event_count:
            dest_host = target_hosts[idx % len(target_hosts)]
            dest_port = probed_ports[idx % len(probed_ports)]
            ev_net = SecurityEvent(
                host="WIN-LAB01",
                host_ip="10.10.10.20",
                user="user01",
                source_ip="10.10.10.20",
                destination_ip=dest_host,
                destination_port=dest_port,
                event_type="discovery",
                action="queried",
                log_source="Zeek",
                event_code=3,
                metadata={
                    "probed_target": dest_host,
                    "probed_port": dest_port,
                    "scan_type": "SYN_STEALTH_SWEEP",
                    "total_probes": remaining_needed
                }
            )
            events.append(ev_net)
            collector.collect(ev_net)
            idx += 1

        self.observations.append(f"Discovery simulation complete: Generated exactly {len(events)} events (Host Discovery, Port Sweeps, AD queries).")
        self.observations.append("Telemetry pipeline delivered events to SIEM & AI Analytics engine.")
        return events
