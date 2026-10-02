"""
Active Directory / Domain Controller Telemetry Generator
Generates Kerberos TGT (EID 4768), Service Tickets (EID 4769), NTLM (EID 4776),
Service Installations (EID 7045), and AD Group Membership modifications (EID 4728).
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from core.models import SecurityEvent
from core.config import HOST_AD_DC, LAB_DOMAIN

class ADTelemetryGenerator:
    """Generates synthetic Active Directory Domain Services security events."""

    def __init__(self, host: Optional[Dict[str, Any]] = None):
        self.host_info = host or HOST_AD_DC
        self.hostname = self.host_info["hostname"]
        self.host_ip = self.host_info["ip"]
        self.domain = LAB_DOMAIN

    def create_kerberos_tgt_event(
        self,
        user: str,
        client_ip: str,
        success: bool = True,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Event ID 4768: A Kerberos authentication ticket (TGT) was requested."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=client_ip,
            destination_ip=self.host_ip,
            destination_port=88,
            event_type="authentication",
            action="success" if success else "failure",
            log_source="SecurityEventLog",
            event_code=4768,
            metadata={
                "TargetDomainName": self.domain,
                "ServiceName": f"krbtgt/{self.domain}",
                "TicketOptions": "0x40810010",
                "Status": "0x0" if success else "0x6", # 0x6 = KDC_ERR_C_PRINCIPAL_UNKNOWN
                "PreAuthType": "15" # PA-ENC-TIMESTAMP
            }
        )

    def create_kerberos_auth_event(
        self,
        user: str,
        client_ip: str,
        success: bool = True,
        consecutive_failures: int = 0,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Alias helper for Kerberos auth simulation."""
        ev = self.create_kerberos_tgt_event(user=user, client_ip=client_ip, success=success, timestamp=timestamp)
        ev.metadata["consecutive_failures"] = consecutive_failures
        return ev

    def create_kerberos_tgs_event(
        self,
        user: str,
        service_name: str,
        client_ip: str,
        success: bool = True,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Event ID 4769: A Kerberos service ticket was requested."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip=client_ip,
            destination_ip=self.host_ip,
            destination_port=88,
            event_type="authentication",
            action="success" if success else "failure",
            log_source="SecurityEventLog",
            event_code=4769,
            metadata={
                "TargetDomainName": self.domain,
                "ServiceName": service_name,
                "TicketOptions": "0x40810000",
                "TicketEncryptionType": "0x12", # AES256-CTS-HMAC-SHA1-96
                "Status": "0x0" if success else "0x1B"
            }
        )

    def create_service_installed_event(
        self,
        user: str,
        service_name: str = "PSEXESVC",
        image_path: str = "%SystemRoot%\\PSEXESVC.exe",
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Event ID 7045: A service was installed in the system (PsExec / Lateral Movement)."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=user,
            source_ip="10.10.10.20",
            destination_ip=self.host_ip,
            event_type="service_creation",
            action="executed",
            service_name=service_name,
            log_source="SecurityEventLog",
            event_code=7045,
            metadata={
                "ServiceName": service_name,
                "ImagePath": image_path,
                "ServiceType": "user mode service",
                "StartType": "demand start"
            }
        )

    def create_group_membership_change_event(
        self,
        admin_user: str,
        target_user: str,
        target_group: str = "Domain Admins",
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Event ID 4728: A member was added to a security-enabled global group."""
        return SecurityEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            host=self.hostname,
            host_ip=self.host_ip,
            user=admin_user,
            source_ip=self.host_ip,
            destination_ip=self.host_ip,
            event_type="privilege_elevation",
            action="executed",
            log_source="SecurityEventLog",
            event_code=4728,
            metadata={
                "SubjectUserName": admin_user,
                "MemberName": f"CN={target_user},CN=Users,DC=corp,DC=lab",
                "TargetGroupName": target_group,
                "PrivilegeJump": True
            }
        )

    def create_security_group_change_event(
        self,
        admin_user: str,
        target_user: str,
        group_name: str = "Domain Admins",
        event_code: int = 4728,
        timestamp: Optional[str] = None
    ) -> SecurityEvent:
        """Alias helper for group modifications."""
        return self.create_group_membership_change_event(
            admin_user=admin_user,
            target_user=target_user,
            target_group=group_name,
            timestamp=timestamp
        )

# Alias for backwards-compatibility
ActiveDirectoryTelemetryGenerator = ADTelemetryGenerator
