"""
Windows Endpoint Telemetry Generator
Produces realistic Sysmon (EID 1, 3, 7, 13) and Windows Security Event Logs (4624, 4625, 4672, 4104, 7045).
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from core.models import SecurityEvent
from core.config import HOST_WIN_CLIENT

class WindowsTelemetryGenerator:
    """Generates synthetic, highly accurate Windows Endpoint & Sysmon telemetry events."""

    def __init__(self, host: Optional[Dict[str, Any]] = None):
        self.host_info = host or HOST_WIN_CLIENT
        self.hostname = self.host_info["hostname"]
        self.host_ip = self.host_info["ip"]

    def create_process_event(
        self,
        user: str,
        process_name: str,
        command_line: str,
        parent_process: str = "explorer.exe",
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Sysmon EID 1 - Process Creation."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=self.host_ip,
            destination_ip=None,
            event_type="process_creation",
            action="executed",
            process_name=process_name,
            command_line=command_line,
            parent_process=parent_process,
            log_source="Sysmon",
            event_code=1,
            metadata={
                "Image": f"C:\\Windows\\System32\\{process_name}",
                "ParentImage": f"C:\\Windows\\{parent_process}",
                "IntegrityLevel": "High" if user == "administrator" else "Medium",
                "Hashes": "SHA256=MOCK_HASH_FOR_LAB_TELEMETRY"
            }
        )

    def create_network_event(
        self,
        user: str,
        process_name: str,
        dest_ip: str,
        dest_port: int,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Sysmon EID 3 - Network Connection."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=self.host_ip,
            destination_ip=dest_ip,
            destination_port=dest_port,
            event_type="network_connection",
            action="connected",
            process_name=process_name,
            log_source="Sysmon",
            event_code=3,
            metadata={
                "Protocol": "tcp",
                "Initiated": True,
                "DestinationIsIpv6": False
            }
        )

    def create_logon_event(
        self,
        user: str,
        logon_type: int = 2,
        success: bool = True,
        source_ip: Optional[str] = None,
        consecutive_failures: int = 0,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Windows Security EID 4624 (Success) or 4625 (Failure)."""
        src = source_ip or self.host_ip
        event_code = 4624 if success else 4625
        action = "success" if success else "failure"

        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=src,
            destination_ip=self.host_ip,
            event_type="authentication",
            action=action,
            log_source="SecurityEventLog",
            event_code=event_code,
            metadata={
                "logon_type": logon_type,
                "auth_package": "Kerberos" if success else "NTLM",
                "consecutive_failures": consecutive_failures,
                "Status": "0x0" if success else "0xC000006D" # STATUS_LOGON_FAILURE
            }
        )

    def create_powershell_script_event(
        self,
        user: str,
        script_block: str,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Windows PowerShell EID 4104 - Script Block Logging."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=self.host_ip,
            destination_ip=None,
            event_type="process_creation",
            action="executed",
            process_name="powershell.exe",
            command_line=script_block,
            log_source="PowerShell",
            event_code=4104,
            metadata={
                "ScriptBlockText": script_block,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        )
