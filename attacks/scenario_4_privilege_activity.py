"""
Scenario 4: Privileged Activity Simulation
Goal: Generate legitimate administrative activity and compare with unusual privileged activity.
Question: Can the system distinguish 'administrator doing administrator things' from unusual privileged behavior?
Measures: False Positives, False Negatives, and Behavioral Context Differentiation.
"""

from typing import List, Dict, Any
from attacks.framework import BaseAttackScenario
from core.models import SecurityEvent
from telemetry.collector import TelemetryCollector
from telemetry.windows_generator import WindowsTelemetryGenerator
from telemetry.ad_generator import ADTelemetryGenerator
from telemetry.linux_generator import LinuxTelemetryGenerator

class PrivilegeActivityScenario(BaseAttackScenario):
    def __init__(self):
        super().__init__(
            scenario_id="SCENARIO-04",
            name="Experiment 4 - Privileged Activity",
            expected_detection="SIG-LNX-004 (Sudo Shadow Access) + EID 4728 (Domain Admins Group Jump)"
        )
        self.win_gen = WindowsTelemetryGenerator()
        self.ad_gen = ADTelemetryGenerator()
        self.lnx_gen = LinuxTelemetryGenerator()

    def execute_simulation(self, collector: TelemetryCollector) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        self.observations.append("Phase 1: Generating standard administrator activity (Baseline Admin Behavior).")

        # Phase 1: Legitimate Admin Action (administrator doing administrator things)
        ev_adm1 = self.win_gen.create_process_event(
            user="administrator",
            process_name="powershell.exe",
            command_line="powershell.exe -Command Get-Service -Name wuauserv",
            parent_process="explorer.exe"
        )
        events.append(ev_adm1)
        collector.collect(ev_adm1)

        self.observations.append("Phase 2: Generating unusual privileged activity by standard user (user01).")

        # Phase 2: Standard User Unusual Privileged Action 1 (Linux sudo /etc/shadow read)
        ev_user_sudo = self.lnx_gen.create_sudo_execution_event(
            user="user01", # Unprivileged finance user executing privileged sudo
            command_line="/usr/bin/cat /etc/shadow",
            success=True
        )
        events.append(ev_user_sudo)
        collector.collect(ev_user_sudo)

        # Phase 2: Standard User Unusual Privileged Action 2 (Windows Special Privileges Assigned - EID 4672)
        ev_user_sec = SecurityEvent(
            host="WIN-LAB01",
            host_ip="10.10.10.20",
            user="user01",
            source_ip="10.10.10.20",
            destination_ip="10.10.10.20",
            event_type="privilege_elevation",
            action="executed",
            log_source="SecurityEventLog",
            event_code=4672,
            metadata={"PrivilegeList": "SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege"}
        )
        events.append(ev_user_sec)
        collector.collect(ev_user_sec)

        # Phase 2: Standard User Unusual Privileged Action 3 (Adding user01 to Domain Admins - EID 4728)
        ev_user_group = self.ad_gen.create_group_membership_change_event(
            admin_user="user01",
            target_user="user01",
            target_group="Domain Admins"
        )
        events.append(ev_user_group)
        collector.collect(ev_user_group)

        self.observations.append(f"Generated {len(events)} events comparing benign administrator tasks against unauthorized privilege escalations.")
        return events
