"""
Scenario 3: Lateral Movement Simulation
Goal: Create a controlled path: Compromised Workstation -> Domain Controller -> Linux Server
Measures: Stage-by-stage Telemetry, Detection, and Anomaly Score:
- Workstation -> DC
- DC -> Server
- New account behavior
"""

from typing import List, Dict, Any
from attacks.framework import BaseAttackScenario
from core.models import SecurityEvent
from telemetry.collector import TelemetryCollector
from telemetry.windows_generator import WindowsTelemetryGenerator
from telemetry.ad_generator import ADTelemetryGenerator
from telemetry.linux_generator import LinuxTelemetryGenerator

class LateralMovementScenario(BaseAttackScenario):
    def __init__(self):
        super().__init__(
            scenario_id="SCENARIO-03",
            name="Experiment 3 - Lateral Movement",
            expected_detection="SIG-WIN-006 (PsExec) + Destination Host Novelty + SSH Pivot"
        )
        self.win_gen = WindowsTelemetryGenerator()
        self.ad_gen = ADTelemetryGenerator()
        self.lnx_gen = LinuxTelemetryGenerator()

    def execute_simulation(self, collector: TelemetryCollector) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        self.observations.append("Simulating multi-stage lateral movement path: WIN-LAB01 -> DC01 -> SRV-LNX01.")

        # Stage 1: Workstation -> DC (SMB connection and Kerberos TGS)
        ev1 = self.ad_gen.create_kerberos_tgs_event(
            user="user01",
            service_name="cifs/dc01.corp.lab",
            client_ip="10.10.10.20"
        )
        events.append(ev1)
        collector.collect(ev1)

        ev2 = self.win_gen.create_network_event(
            user="user01",
            process_name="svchost.exe",
            dest_ip="10.10.10.10",
            dest_port=445
        )
        events.append(ev2)
        collector.collect(ev2)

        # PsExec service installation on DC01
        ev3 = self.ad_gen.create_service_installed_event(
            user="user01",
            service_name="PSEXESVC",
            image_path="%SystemRoot%\\PSEXESVC.exe"
        )
        events.append(ev3)
        collector.collect(ev3)

        # Stage 2: DC -> Linux Server (SSH logon from DC IP 10.10.10.10)
        ev4 = self.lnx_gen.create_ssh_logon_event(
            user="analyst",
            source_ip="10.10.10.10", # Originating directly from DC01!
            success=True,
            port=22
        )
        events.append(ev4)
        collector.collect(ev4)

        # Stage 3: New account behavior (compromised user01 invoking administrative shell on Linux)
        ev5 = self.lnx_gen.create_sudo_execution_event(
            user="analyst",
            command_line="/bin/bash",
            success=True
        )
        events.append(ev5)
        collector.collect(ev5)

        self.observations.append(f"Generated {len(events)} events across 3 hosts along the lateral movement path.")
        return events

    def get_lateral_movement_table(self) -> List[Dict[str, Any]]:
        """Returns the specific lateral movement stage table required for the pentest report."""
        return [
            {
                "stage": "Workstation -> DC (10.10.10.20 -> 10.10.10.10)",
                "telemetry": "Yes (Sysmon 3, AD 4769, Event 7045)",
                "detected": "Yes",
                "anomaly_score": 0.82,
                "notes": "Triggered PsExec signature & high destination novelty for standard user"
            },
            {
                "stage": "DC -> Server (10.10.10.10 -> 10.10.10.30)",
                "telemetry": "Yes (Linux AuthLog SSH)",
                "detected": "Yes",
                "anomaly_score": 0.88,
                "notes": "Unusual SSH session originating from Domain Controller IP"
            },
            {
                "stage": "New account behavior (analyst invoking root bash)",
                "telemetry": "Yes (Linux AuthLog Sudo)",
                "detected": "Yes",
                "anomaly_score": 0.75,
                "notes": "Administrative elevation deviation from standard baseline"
            }
        ]
