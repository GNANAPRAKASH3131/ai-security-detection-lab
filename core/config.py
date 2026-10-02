"""
Lab Configuration and Constants
AI-Based Infrastructure Cyber Security - Internal Pentest Lab
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
EXPERIMENTS_DIR = DATA_DIR / "experiments"
BASELINES_DIR = DATA_DIR / "baselines"
LOGS_DIR = DATA_DIR / "logs"

# Ensure directories exist
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
BASELINES_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Lab Network Topology (10.10.10.0/24 - Strictly Isolated Lab Network)
LAB_DOMAIN = "corp.lab"
LAB_SUBNET = "10.10.10.0/24"

HOST_AD_DC = {
    "hostname": "DC01",
    "fqdn": "dc01.corp.lab",
    "ip": "10.10.10.10",
    "os": "Windows Server 2022 (Domain Controller)",
    "role": "Active Directory Domain Services, Kerberos KDC, DNS, LDAP",
    "criticality": "HIGH"
}

HOST_WIN_CLIENT = {
    "hostname": "WIN-LAB01",
    "fqdn": "win-lab01.corp.lab",
    "ip": "10.10.10.20",
    "os": "Windows 11 Enterprise (Client Workstation)",
    "role": "Internal Workstation / Initial Compromise Vector",
    "criticality": "MEDIUM"
}

HOST_LINUX_SRV = {
    "hostname": "SRV-LNX01",
    "fqdn": "srv-lnx01.corp.lab",
    "ip": "10.10.10.30",
    "os": "Ubuntu 22.04 LTS (Internal Application Server)",
    "role": "Internal Web API, SSH, PostgreSQL Database",
    "criticality": "HIGH"
}

HOST_ATTACKER = {
    "hostname": "KALI-ATTACK01",
    "fqdn": "kali-attack01.corp.lab",
    "ip": "10.10.10.50",
    "os": "Kali Linux 2024.1",
    "role": "Internal Testing & Controlled Simulation Runner",
    "criticality": "LOW"
}

HOSTS = {
    "10.10.10.10": HOST_AD_DC,
    "10.10.10.20": HOST_WIN_CLIENT,
    "10.10.10.30": HOST_LINUX_SRV,
    "10.10.10.50": HOST_ATTACKER,
    "DC01": HOST_AD_DC,
    "WIN-LAB01": HOST_WIN_CLIENT,
    "SRV-LNX01": HOST_LINUX_SRV,
    "KALI-ATTACK01": HOST_ATTACKER,
}

# Strictly Documented Lab Credentials (MOCK/ISOLATED LAB ONLY)
LAB_USERS = {
    "administrator": {
        "domain": "corp.lab",
        "role": "Domain Administrator",
        "privilege_level": "Domain Admin",
        "groups": ["Domain Admins", "Enterprise Admins", "Schema Admins"],
        "normal_hosts": ["10.10.10.10", "10.10.10.20"],
        "normal_work_hours": (7, 20),
        "lab_mock_pass": "LabP@ssw0rd_Admin2026!"
    },
    "analyst": {
        "domain": "corp.lab",
        "role": "Security Analyst / Tier 2",
        "privilege_level": "Elevated User",
        "groups": ["SOC Analysts", "Server Operators"],
        "normal_hosts": ["10.10.10.20", "10.10.10.30"],
        "normal_work_hours": (8, 18),
        "lab_mock_pass": "LabP@ssw0rd_Analyst2026!"
    },
    "user01": {
        "domain": "corp.lab",
        "role": "Finance Associate",
        "privilege_level": "Standard User",
        "groups": ["Domain Users", "Finance Dept"],
        "normal_hosts": ["10.10.10.20"],
        "normal_work_hours": (8, 17),
        "lab_mock_pass": "LabP@ssw0rd_User01_2026!"
    },
    "user02": {
        "domain": "corp.lab",
        "role": "HR Specialist",
        "privilege_level": "Standard User",
        "groups": ["Domain Users", "HR Dept"],
        "normal_hosts": ["10.10.10.20"],
        "normal_work_hours": (9, 17),
        "lab_mock_pass": "LabP@ssw0rd_User02_2026!"
    },
    "svc-monitor": {
        "domain": "corp.lab",
        "role": "Automated Monitoring Service Account",
        "privilege_level": "Service Account",
        "groups": ["Service Accounts", "Performance Monitor Users"],
        "normal_hosts": ["10.10.10.10", "10.10.10.20", "10.10.10.30"],
        "normal_work_hours": (0, 24),
        "lab_mock_pass": "LabP@ssw0rd_SvcMon2026!"
    }
}

# Anomaly Scoring Tiers (LAB RESEARCH SPECIFICATION ONLY)
ANOMALY_THRESHOLDS = {
    "NORMAL": (0.00, 0.30),
    "UNUSUAL": (0.31, 0.60),
    "SUSPICIOUS": (0.61, 0.80),
    "HIGHLY_ANOMALOUS": (0.81, 1.00)
}

# Behavioral Feature Weights for Multivariate Anomaly Model
FEATURE_WEIGHTS = {
    "auth_frequency": 0.15,
    "dest_host_novelty": 0.20,
    "dest_port_novelty": 0.10,
    "failed_ratio": 0.15,
    "off_hours_deviation": 0.10,
    "rare_process": 0.15,
    "admin_privilege_jump": 0.15
}

# Web Server Port (supports cloud container $PORT injection)
WEB_PORT = int(os.environ.get("PORT", os.environ.get("WEB_PORT", 8080)))
WEB_HOST = os.environ.get("HOST", os.environ.get("WEB_HOST", "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"))

