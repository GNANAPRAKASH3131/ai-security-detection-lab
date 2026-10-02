# AI-Based Security Detection as an Internal Attack Surface: An Internal Pentester's Analysis of Telemetry, Detection, and Response

> **Academic & Defensive Cybersecurity Research Laboratory**  
> An isolated, reproducible experimental environment evaluating the visibility, detection boundaries, and blindspots of behavioral AI security monitoring during internal attack chains.

---

## 🔬 Core Research Question

> **“If an internal attacker is already inside the network, what does an AI-based security system see, what does it miss, and why?”**

This laboratory allows empirical measurement across every phase of the defense pipeline:

$$\text{Attack Activity} \longrightarrow \text{Telemetry Generated} \longrightarrow \text{Collector Ingestion} \longrightarrow \text{SIEM \& AI Analytics} \longrightarrow \text{Detection} \longrightarrow \text{Response}$$

---

## 🏛️ Lab Architecture & Topology

The logical lab environment represents an isolated RFC 1918 internal enterprise subnet (`10.10.10.0/24`):

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
- **WIN-LAB01 (10.10.10.20):** Windows 11 Enterprise Workstation (Initial Foothold).
- **SRV-LNX01 (10.10.10.30):** Ubuntu 22.04 LTS Internal Application & Database Server.
- **KALI-ATTACK01 (10.10.10.50):** Controlled Simulation Runner.

---

## 🚀 Quickstart: Command-by-Command Execution

### Step 1: Establish Normal Pre-Attack Baseline
Generates normal user01 logins, DNS queries, web access, and administrator MMC tasks to calibrate behavioral UEBA models:
```powershell
python lab.py baseline
```

### Step 2: Run All Research Scenarios (Experiments 1 through 7)
Executes all simulations, captures telemetry, evaluates rules and behavioral models, and records evidence to `/data/experiments/`:
```powershell
python lab.py run all
```

### Step 3: View Detection Coverage Matrix
Prints the empirical detection matrix generated from verified lab run records:
```powershell
python lab.py matrix
```

### Step 4: Launch Web Dashboard & Investigation Workbench
Starts the local web server and REST API:
```powershell
python lab.py dashboard --port 8080
```
Open [http://127.0.0.1:8080](http://127.0.0.1:8080) to inspect:
- **Section A: Attack Timeline:** Chronological attack journey with exact timestamps and detections.
- **Section B: Detection Coverage:** Visual coverage meters across Discovery, Auth, Lateral Movement, Privilege, and Telemetry Gap.
- **Section C: AI Analytics:** User, Host, Baseline vs Current Behavior, Anomaly Score, and Detection Reasons.
- **Section D: Telemetry Health:** Interactive component toggles (ONLINE/OFFLINE/PARTIAL) to simulate collector blindspots.
- **Lab Findings & Taxonomy:** DETECTED, MISSED, PARTIAL (Why?), Internal Pentest Analysis, and Recommendations.

### Step 5: Export Blog-Ready Research Report
Compiles a publication-ready Markdown research report based on measured lab data:
```powershell
python lab.py report
```

---

## 📋 The 7 Research Experiments

| Experiment | Name | Core Research Objective & Methodology | Measured Detection |
| :--- | :--- | :--- | :--- |
| **01** | **Internal Discovery** | 150 events generated: host discovery, port sweep, AD enumeration (`nltest`, `net group`). | `SIG-WIN-001` (AD Enum) + Port Sweep Heuristic (Score: 0.78) |
| **02** | **Authentication Anomaly** | Normal (user01 -> WS, DC) vs Abnormal (user01 -> DC, Server 1, 2, 3, 4 at 03:15 AM). | `SIG-AUTH-002` (Spray) + Dest Novelty (Score: 0.84) |
| **03** | **Lateral Movement** | Controlled path: `WIN-LAB01` -> `DC01` (PsExec/SMB) -> `SRV-LNX01` (SSH). | `SIG-WIN-006` (Remote Service) + SSH Pivot (Score: 0.88) |
| **04** | **Privileged Activity** | Compares `administrator` routine tasks vs `user01` adding to `Domain Admins` (EID 4728). | `SIG-LNX-004` (Sudo) + EID 4728 Jump (Score: 0.96) |
| **05** | **Telemetry Gap (Centerpiece)** | Pipeline: Endpoint -> `[X Collector Gap X]` -> SIEM. Tests if AI can detect unobserved actions. | **0 Alerts Generated** (100% False Negative during outage) |
| **06** | **False Positives** | Legitimate administrator multi-system maintenance window. (Anomalous ≠ Malicious). | **No Alert** (Score: 0.12 - Benign Noise Floor) |
| **07** | **Full Attack Chain** | End-to-end multi-stage correlation from initial access to automated containment. | **Critical Incident Declared** (Score: 0.96 + SOAR Playbook) |

---

## 📊 Findings Taxonomy

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

- **DETECTED:** High destination novelty, burst velocity (>5 failures/min), and privilege group manipulation trigger weighted anomaly scores $\ge 0.61$.
- **MISSED:** Telemetry collector outages prevent ingestion. An AI detection system cannot detect what it cannot observe.
- **PARTIAL:** Asymmetric sensor coverage creates fragmented alerts lacking holistic attack chain context.
