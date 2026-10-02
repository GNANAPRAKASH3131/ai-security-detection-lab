# Laboratory Setup & Deployment Guide

This guide outlines setup procedures for all three deployment modes of the cybersecurity research lab.

---

## Prerequisites & Host System Check

Before deployment, verify system resources:
- **Operating System:** Windows 10/11, Ubuntu 22.04+, or macOS.
- **Python:** Version `3.10` or higher (Python 3.12 verified).
- **Disk Space:** Minimum 2 GB free for logs and experiment artifacts.

---

## Deployment Mode Quickstart

### Mode C: Native Python Research Engine (Default & Fastest)

Mode C runs natively on your system with zero hypervisor overhead.

1. **Verify Python Environment:**
   ```powershell
   python --version
   ```

2. **Run all 6 Research Scenarios:**
   ```powershell
   python lab.py run all
   ```

3. **Execute Telemetry Failure Experiment:**
   ```powershell
   python lab.py experiment
   ```

4. **Launch Interactive Web Dashboard & REST API:**
   ```powershell
   python lab.py dashboard --port 8080
   ```
   Open your browser to: [http://127.0.0.1:8080](http://127.0.0.1:8080)

5. **Generate Academic Research Report:**
   ```powershell
   python lab.py report
   ```

---

### Mode B: Lightweight Container Deployment (Docker Compose)

For containerized SIEM, collectors, and analytics services:

1. **Navigate to Docker directory:**
   ```bash
   cd docker
   ```

2. **Start containers:**
   ```bash
   docker compose up -d
   ```

3. **Verify running containers:**
   ```bash
   docker ps
   ```

4. **Access Web Interface:**
   Navigate to `http://localhost:8080`.

---

### Mode A: Full Multi-VM Architecture (VirtualBox / Vagrant)

For bare-metal virtualization with real Windows Server, Windows Client, and Linux Server virtual machines:

1. **Install VirtualBox & Vagrant:**
   Ensure hardware virtualization (VT-x/AMD-V) is enabled in BIOS.

2. **Launch Lab Virtual Machines:**
   ```bash
   cd vagrant
   vagrant up
   ```

3. **Configure Windows Endpoint Logging:**
   - Install **Sysmon** with SwiftOnSecurity configuration:
     ```powershell
     .\Sysmon64.exe -i sysmonconfig-export.xml
     ```
   - Enable **PowerShell Script Block Logging** via Group Policy:
     `Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging`.

4. **Configure Linux Auditd & Syslog:**
   - Install auditd:
     ```bash
     sudo apt-get update && sudo apt-get install -y auditd
     sudo auditctl -w /etc/shadow -p wa -k shadow_mod
     ```
   - Forward auth.log to collector via rsyslog:
     `*.* @10.10.10.1:514`

5. **Execute Test Attacks from Kali:**
   Run the attack scripts from `attacks/` inside the Kali VM targeting the lab IPs.
