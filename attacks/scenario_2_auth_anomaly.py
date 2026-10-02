"""
Scenario 2: Authentication Anomaly & Multi-Server Credential Propagation
Goal: Generate a controlled authentication pattern involving lab accounts.
Normal: user01 -> workstation, user01 -> DC
Abnormal: user01 -> DC, user01 -> server1, user01 -> server2, user01 -> server3, user01 -> server4
Measures: Normal behavior -> Changed behavior -> Anomaly score -> Detection.
"""

from typing import List
from attacks.framework import BaseAttackScenario
from core.models import SecurityEvent
from telemetry.collector import TelemetryCollector
from telemetry.windows_generator import WindowsTelemetryGenerator
from telemetry.ad_generator import ADTelemetryGenerator

class AuthAnomalyScenario(BaseAttackScenario):
    def __init__(self):
        super().__init__(
            scenario_id="SCENARIO-02",
            name="Experiment 2 - Authentication Anomaly",
            expected_detection="SIG-AUTH-002 (Failed Logins) + UEBA Multi-Host Authentication Jump"
        )
        self.win_gen = WindowsTelemetryGenerator()
        self.ad_gen = ADTelemetryGenerator()

    def execute_simulation(self, collector: TelemetryCollector) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        
        self.observations.append("Step 1 (Normal baseline reference): user01 routinely connects to WIN-LAB01 (10.10.10.20) and DC01 (10.10.10.10).")
        self.observations.append("Step 2 (Abnormal attack pattern): user01 suddenly attempts sequential Kerberos authentications across DC01 and multiple novel internal servers.")

        # 1. Abnormal Multi-Server Authentication Pattern for user01
        abnormal_servers = [
            {"name": "DC01 (Domain Controller)", "ip": "10.10.10.10", "service": "krbtgt/corp.lab"},
            {"name": "Server1 (File Server / SMB)", "ip": "10.10.10.12", "service": "cifs/fs01.corp.lab"},
            {"name": "Server2 (SQL Database)", "ip": "10.10.10.14", "service": "mssql/db01.corp.lab"},
            {"name": "Server3 (App Server)", "ip": "10.10.10.30", "service": "http/app01.corp.lab"},
            {"name": "Server4 (Backup Storage)", "ip": "10.10.10.45", "service": "cifs/bak01.corp.lab"},
        ]

        # First generate 5 failed authentication attempts against DC and servers (credential spray)
        for i, srv in enumerate(abnormal_servers):
            ev_fail = self.win_gen.create_logon_event(
                user="user01",
                logon_type=3, # Network Logon
                success=False,
                consecutive_failures=i + 1,
                source_ip="10.10.10.20",
                timestamp=f"2026-10-01T03:1{i}:00" # 03:10 AM - 03:15 AM (Off-hours)
            )
            events.append(ev_fail)
            collector.collect(ev_fail)

        # Then generate rapid successful Kerberos TGS ticket grants to all 5 servers in rapid succession
        for i, srv in enumerate(abnormal_servers):
            ev_tgt = self.ad_gen.create_kerberos_tgs_event(
                user="user01",
                service_name=srv["service"],
                client_ip="10.10.10.20",
                success=True,
                timestamp=f"2026-10-01T03:2{i}:00"
            )
            # Add metadata on destination IP to trigger dest_host_novelty
            ev_tgt.destination_ip = srv["ip"]
            events.append(ev_tgt)
            collector.collect(ev_tgt)

        self.observations.append(f"Generated {len(events)} authentication events: 5 off-hours failures followed by 5 multi-server TGS grants across 5 internal hosts.")
        self.observations.append("AI / UEBA Behavioral Engine evaluated user profile deviation from baseline (1 host -> 5 novel hosts).")
        return events
