"""
Linux Server Telemetry Generator
Generates Ubuntu/Debian AuthLog (SSH, PAM, Sudo), Syslog, and Auditd syscall telemetry events.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from core.models import SecurityEvent
from core.config import HOST_LINUX_SRV

class LinuxTelemetryGenerator:
    """Generates realistic Linux server authentication, sudo, and audit logs."""

    def __init__(self, host: Optional[Dict[str, Any]] = None):
        self.host_info = host or HOST_LINUX_SRV
        self.hostname = self.host_info["hostname"]
        self.host_ip = self.host_info["ip"]

    def create_ssh_logon_event(
        self,
        user: str,
        source_ip: str,
        success: bool = True,
        port: int = 22,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """SSH Login via auth.log / PAM."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=source_ip,
            destination_ip=self.host_ip,
            destination_port=port,
            event_type="authentication",
            action="success" if success else "failure",
            log_source="AuthLog",
            event_code=1001 if success else 1002,
            metadata={
                "service": "sshd",
                "message": f"Accepted publickey for {user} from {source_ip} port 54321 ssh2" if success else f"Failed password for invalid user {user} from {source_ip} port 54321 ssh2",
                "auth_method": "publickey" if success else "password"
            }
        )

    def create_ssh_auth_event(
        self,
        user: str,
        source_ip: str,
        success: bool = True,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Alias helper for SSH logon event."""
        return self.create_ssh_logon_event(user=user, source_ip=source_ip, success=success, timestamp=timestamp)

    def create_sudo_execution_event(
        self,
        user: str,
        command_line: str,
        success: bool = True,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Sudo execution / privilege elevation via auth.log."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=self.host_ip,
            destination_ip=self.host_ip,
            event_type="privilege_elevation",
            action="executed" if success else "blocked",
            command_line=f"sudo {command_line}",
            process_name="sudo",
            log_source="AuthLog",
            event_code=1003,
            metadata={
                "service": "sudo",
                "pwd": f"/home/{user}",
                "target_user": "root",
                "tty": "pts/0",
                "command": command_line
            }
        )

    def create_sudo_event(
        self,
        user: str,
        command: str,
        success: bool = True,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Alias helper for Sudo event."""
        return self.create_sudo_execution_event(user=user, command_line=command, success=success, timestamp=timestamp)

    def create_http_access_event(
        self,
        source_ip: str,
        method: str,
        endpoint: str,
        status_code: int,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Nginx / Apache web server access log."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user="www-data",
            source_ip=source_ip,
            destination_ip=self.host_ip,
            destination_port=80,
            event_type="network_connection",
            action="success" if status_code < 400 else "failure",
            log_source="Nginx",
            event_code=200,
            metadata={
                "http_method": method,
                "request_uri": endpoint,
                "status": status_code,
                "user_agent": "Mozilla/5.0 (Pentest Lab Environment)"
            }
        )
