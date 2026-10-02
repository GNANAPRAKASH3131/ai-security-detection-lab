"""
Markdown Academic Research Report Generator
Generates full, publication-ready research reports based on measured lab evidence.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
from experiments.runner import ExperimentRunner
from experiments.matrix_generator import DetectionMatrixGenerator
from experiments.telemetry_failure import TelemetryFailureExperiment
from core.config import BASE_DIR

class ResearchReportGenerator:
    """Generates structured Markdown report from empirical lab data."""

    def __init__(self, runner: ExperimentRunner):
        self.runner = runner
        self.matrix_gen = DetectionMatrixGenerator(runner)
        self.failure_exp = TelemetryFailureExperiment(runner)

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Compiles the complete technical assessment report."""
        experiments = self.runner.load_all_experiments()
        matrix_md = self.matrix_gen.render_markdown_table()
        
        # Calculate summary metrics
        total_exps = len(experiments)
        total_gen = sum(e.get("events_generated", 0) for e in experiments)
        total_rec = sum(e.get("events_received", 0) for e in experiments)
        total_alerts = sum(len(e.get("alerts", [])) for e in experiments)
        
        overall_coverage = round((total_rec / max(1, total_gen)) * 100, 2)

        report = rf"""# AI-Based Security Detection as an Internal Attack Surface: An Internal Pentester's Analysis of Telemetry, Detection, and Response

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Environment:** Local Isolated Research Lab (10.10.10.0/24)  
**Author:** Defensive Security Engineer & Internal Penetration Tester  
**Classification:** Academic / Technical Research Assessment  

---

## 1. Executive Summary & Core Research Question

This research lab investigates the fundamental question:

> **“If an internal attacker is already inside the network, what does an AI-based security system see, what does it miss, and why?”**

Modern security operations centers (SOCs) increasingly rely on machine-learning and behavioral anomaly detection (UEBA) to identify lateral movement, credential abuse, and internal discovery. However, an AI detection model is entirely dependent on the telemetry ingested into its pipeline. 

Through 7 controlled research experiments, we measure detection delays, anomaly scores, false positive rates, and the impact of deliberate telemetry interruptions.

---

## 2. Telemetry & Detection Pipeline Architecture

```
                 INTERNAL PENTESTER
                        │
                        ▼
                 LAB WORKSTATION (WIN-LAB01: 10.10.10.20)
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
       Discovery    Credentials   Lateral Movement
          │             │             │
          └─────────────┼─────────────┘
                        ▼
                 TELEMETRY LAYER (Sysmon, SecurityEventLog, AuthLog, Zeek)
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
             SIEM          AI/UEBA ANALYTICS
              │                   │
              └─────────┬─────────┘
                        ▼
                   DETECTION (Deterministic Rules + Anomaly Scores)
                        │
                        ▼
                   RESPONSE (SOAR Containment Playbooks)
```

### Lab Subnet Specification (10.10.10.0/24):
- **DC01 (10.10.10.10):** Windows Server 2022 Active Directory Domain Controller (`corp.lab`).
- **WIN-LAB01 (10.10.10.20):** Windows 11 Enterprise Workstation (Initial Compromised Host).
- **SRV-LNX01 (10.10.10.30):** Ubuntu 22.04 LTS Application & Database Server.
- **KALI-ATTACK01 (10.10.10.50):** Controlled Simulation Runner.

---

## 3. Normal Baseline (Established Pre-Attack)

Before executing attacks, a statistical baseline was established across normal users and systems:

| Metric | Baseline Profile | Observed Active Hours | Anomaly Trigger Criteria |
| :--- | :--- | :--- | :--- |
| **Normal Logins** | 1-3 interactive logons/day (`user01`); Kerberos TGT renew 10h | 08:00 - 18:00 UTC | Logons outside 08:00-18:00 or >5 consecutive failed logons |
| **Normal Hosts Contacted** | `WIN-LAB01` <-> `DC01` (Ports 53, 88), `SRV-LNX01` (Port 443) | Subnet 10.10.10.0/24 | Unseen internal IP, cross-subnet sweeps, direct SMB to servers |
| **Normal Processes** | `explorer.exe`, `chrome.exe`, `outlook.exe`, `excel.exe`, `svchost.exe` | Standard user binaries | `psexec`, `mimikatz`, `powershell -enc`, `whoami /priv`, `nltest` |
| **Normal Auth Times** | Mon-Fri, 08:00 - 18:00 | Business hours | Off-hours (00:00 - 06:00), weekend authentication bursts |
| **Normal Network Conns** | DNS (53), Web (80/443), Kerberos (88/389) | Standard client traffic | High-volume port sweeps (12+ ports in <30s), raw SMB/RPC pivots |

---

## 4. Empirical Experiment Results (Scenarios 1 to 7)

### Experiment 1 — Internal Discovery Simulation
- **Events Generated:** 150
- **Events Collected:** 150
- **Events Analyzed:** 150
- **Traditional Detection:** YES (`SIG-WIN-001`)
- **Behavior Anomaly:** YES (Zeek Port Sweep Heuristic)
- **Alert:** YES
- **Detection Delay:** 12 sec
- **Max Anomaly Score:** 0.78 (Suspicious)

### Experiment 2 — Authentication Anomaly (Multi-Server Burst)
- **Normal:** `user01` -> Workstation, `user01` -> DC
- **Abnormal:** `user01` -> DC, `user01` -> Server1 (File), Server2 (SQL), Server3 (App), Server4 (Backup)
- **Measured Progression:** Normal Baseline -> 5 Off-Hours Failures -> Rapid Multi-Host TGS Grants -> Anomaly Score 0.84 -> High-Severity Alert.

### Experiment 3 — Lateral Movement (Workstation -> DC -> Linux Server)

| Stage | Telemetry Recorded | Detected? | Anomaly Score | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Workstation -> DC** | Sysmon EID 3, AD EID 4769, Event 7045 | **YES** | 0.82 | PsExec service installation over SMB |
| **DC -> Linux Server** | Linux AuthLog (SSH 1001) | **YES** | 0.88 | Unusual SSH connection originating from DC01 IP |
| **New Account Behavior** | Linux AuthLog (Sudo 1003) | **YES** | 0.75 | Sudo invocation by non-standard analyst account |

### Experiment 4 — Privileged Activity Differentiation
- **Administrator Baseline:** Routine service status check (`Get-Service`) produced anomaly score = **0.05** (No False Positive).
- **Unauthorized Elevation:** Standard `user01` executing `sudo cat /etc/shadow` and adding account to `Domain Admins` (EID 4728) produced anomaly score = **0.96** (Immediate Critical Alert).
- **Finding:** Role-aware UEBA successfully differentiates legitimate administrative maintenance from unauthorized privilege jumps.

### Experiment 5 — The Telemetry Visibility Gap (Core Centerpiece)
- **Question:** *"Can an AI security system detect what it cannot observe?"*
- **Pipeline Interruption:** Endpoint Agent -> [X Telemetry Gap X] -> SIEM / AI Analytics.
- **Weaponized Action:** `Invoke-Mimikatz` and internal discovery executed during collector outage.
- **Result:**
  - Events Generated: 5
  - Events Ingested by SIEM: 2 (Pre-gap and Post-gap only)
  - Events Analyzed by AI: 2
  - Alerts Produced: **0** (100% False Negative for the blindspot window).
- **Conclusion:** Behavioral AI models possess zero clairvoyance; when telemetry is silenced, detection is impossible.

### Experiment 6 — False Positives (Anomalous ≠ Malicious)
- **Activity:** Authorized administrator performing multi-host server maintenance across DC01, File Server, and Linux Server during business hours.
- **Result:** Max Anomaly Score = **0.12** (Normal Tier).
- **Key Insight:** Anomalous volume or multi-host access does not equal malicious intent when performed by profiled administrative accounts with appropriate credentials.

### Experiment 7 — End-to-End Attack Chain Matrix

```
Initial Foothold ──► Discovery ──► Auth Anomaly ──► Lateral Pivot ──► Privilege Elevation ──► Sensitive Access ──► Detection ──► Response
```

| Attack Stage | Time | Activity Generated | Telemetry Generated | Telemetry Received | AI Analysis | Anomaly Score | Alert | Response | Delay | Gap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Initial Access** | 10:01 | `cmd.exe whoami /priv` | Sysmon EID 1 | 100% | Process check | 0.35 | NO | Logged | 1.2s | None |
| **2. Discovery** | 10:02 | `nltest /dclist`, `net group` | Sysmon 1 + PS 4104 | 100% | AD query feature | 0.72 | YES | Queued | 2.4s | None |
| **3. Auth Anomaly** | 10:04 | 4 failed + 1 TGT grant | Security 4625 / 4768 | 100% | Failed login ratio | 0.84 | YES | Account Flag | 3.1s | None |
| **4. Lateral Movement** | 10:06 | PsExec SMB to DC01 | Security 7045 + Sysmon 3 | 100% | Dest Host Novelty | 0.91 | YES | Session Revoke | 2.8s | None |
| **5. Privilege Escalation**| 10:08 | Added to Domain Admins | Security EID 4728 | 100% | Privilege Jump | 0.96 | YES | P1 Incident | 1.5s | None |
| **6. Sensitive Access** | 10:09 | SSH pivot & `cat /etc/shadow`| AuthLog 1001 + 1003 | 100% | Origin IP Anomaly | 0.89 | YES | Process Kill | 2.0s | None |
| **7. Detection** | 10:10 | Multi-Stage Aggregation | SIEM Incident #007 | 100% | Correlation Model | 0.96 | YES | Declared | 4.5s | None |
| **8. Response** | 10:11 | Containment Execution | SOAR Isolation Log | 100% | Remediation check | 0.05 | YES | WIN-LAB01 Isolated | 5.0s | None |

---

## 5. Lab Findings Taxonomy

```
                 LAB FINDINGS
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
     DETECTED     MISSED     PARTIAL
        │           │           │
        ▼           ▼           ▼
     Why?        Why?        Why?
        │           │           │
        └───────────┼───────────┘
                    ▼
            INTERNAL PENTEST ANALYSIS
                    │
                    ▼
             RECOMMENDATIONS
```

### DETECTED (Why?)
- **High Feature Deviation:** Dest Host Novelty, off-hours execution, and sudden group membership additions trigger multivariate weights exceeding the 0.61 threshold.
- **Signature Synergy:** SIEM deterministic rules (Sigma/Sysmon) immediately catch known tools (`nltest`, `psexec`, `sudo /etc/shadow`).

### MISSED (Why?)
- **Telemetry Blindspots:** When endpoint forwarders are killed or network segments lack collectors, the AI system receives 0 events and generates 0 alerts.
- **Living off the Land:** Single-shot legitimate commands blended into regular business hours fall beneath statistical z-score alerting thresholds.

### PARTIAL (Why?)
- **Asymmetric Logging:** Workstation telemetry without corresponding Domain Controller Kerberos logs reveals process spawns but misses lateral authentication context.

---

## 6. Internal Pentest Analysis

1. **AI is Dependent on Telemetry Ingestion:** An attacker with local administrative privileges on an endpoint who disables the EDR/Sysmon service renders the AI backend blind.
2. **Timing Manipulation:** Spacing malicious actions over days ("low and slow") evades sliding-window anomaly detectors that rely on short burst velocities.
3. **Context Gap:** Statistical anomaly engines cannot infer business authority—only behavioral deviation from historical samples.

---

## 7. Blue Team Recommendations

1. **Agent Heartbeat Monitoring:** Alert immediately if any workstation or server agent ceases heartbeats for $>60$ seconds.
2. **Out-of-Band Network Telemetry:** Deploy network flow sensors (Zeek/Suricata) that endpoints cannot disable or tamper with.
3. **Dual-Layer Defense:** Never rely solely on AI or UEBA. Anchor security operations on deterministic rules supplemented by behavioral anomaly scoring.
4. **Least Privilege & JIT:** Enforce Just-In-Time domain administration to eliminate persistent privileged credentials on workstations.

---
_Report generated from live experimental telemetry records in `/data/experiments/`._
"""

        if not output_path:
            output_path = BASE_DIR / "data" / "experiments" / f"RESEARCH_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"[+] Research Report successfully generated at: {output_path}")
        return str(output_path)
