# Lab Architecture & Technical Specifications

## Logical Topology & Telemetry Flow

The research environment simulates an internal corporate network (`corp.lab`, subnet `10.10.10.0/24`) with heterogeneous endpoints, centralized telemetry collectors, a multi-tier SIEM, and a behavioral anomaly engine.

```mermaid
flowchart TD
    subgraph LAB_HOSTS["Lab Hosts (10.10.10.0/24)"]
        DC["Domain Controller (DC01)<br/>10.10.10.10<br/>AD DS / Kerberos / DNS / LDAP"]
        WIN["Windows Endpoint (WIN-LAB01)<br/>10.10.10.20<br/>Workstation / Initial Access"]
        LNX["Linux App Server (SRV-LNX01)<br/>10.10.10.30<br/>SSH / Nginx / Database"]
        KALI["Internal Attacker (KALI-ATTACK01)<br/>10.10.10.50<br/>Controlled Test Runner"]
    end

    WIN -->|Sysmon EID 1, 3 / Security Logs| TC["Telemetry Collector & Buffer"]
    LNX -->|AuthLog / Sudo / Syslog| TC
    DC -->|Kerberos EID 4768, 4769 / AD EID 4728| TC
    KALI -.->|Safe Network Probes| WIN
    KALI -.->|Safe Network Probes| DC
    KALI -.->|Safe Network Probes| LNX

    TC -->|Normalized Stream| SIEM["Central SIEM Engine"]

    subgraph DETECTION_ENGINE["Dual-Layer Detection Engine"]
        SIEM -->|Signature Match| RULE["Traditional Rule Engine<br/>(Sigma / Thresholds)"]
        SIEM -->|Feature Extraction| AI["AI / Behavioral Analytics<br/>(Statistical Baseline Deviation)"]
    end

    RULE --> ALERTS["Detection & Alert Broker"]
    AI --> ALERTS

    ALERTS --> SOAR["Automated Response Simulation (SOAR)"]
    SOAR --> ACTIONS["Containment Actions<br/>• Simulated Host Isolation<br/>• Account Review Flags<br/>• SOC Tickets & IP Blocks"]

    SIEM --> EXP_STORE["/data/experiments/ (JSON Records)"]
    EXP_STORE --> DASHBOARD["Investigation Web Interface & Attack Chain Graph"]
```

---

## Deployment Modes

### Mode A: Full Virtual Machine Architecture
Recommended when host hardware has $\ge 32\text{ GB}$ RAM and nested hardware virtualization enabled.
- **Hypervisor:** VirtualBox / VMware / Hyper-V.
- **VM 1:** Windows Server 2022 (`DC01` - 4 GB RAM, 2 vCPUs).
- **VM 2:** Windows 11 Enterprise (`WIN-LAB01` - 4 GB RAM, 2 vCPUs).
- **VM 3:** Ubuntu 22.04 LTS (`SRV-LNX01` - 2 GB RAM, 1 vCPU).
- **VM 4:** Kali Linux / Test Runner (`KALI-ATTACK01` - 2 GB RAM, 2 vCPUs).
- **VM 5:** SIEM / Analytics Host (Wazuh / ELK - 4 GB RAM, 2 vCPUs).

### Mode B: Lightweight Containerized Architecture (Docker Compose)
Recommended when Docker Desktop or Linux container engine is available.
- Containers for Telemetry Collectors, Logstash/Wazuh Indexer, Python Analytics Engine, and Dashboard Web Server.
- Lightweight alpine Linux nodes simulating endpoints and network routing.

### Mode C: High-Performance Standalone Python Engine (Host / Zero-Footprint)
Active by default in this workspace. Runs without hypervisors or container overhead while maintaining $100\%$ protocol and log schema fidelity:
- Direct ingestion and normalization pipeline.
- Native multithreaded web server and REST API.
- Full mathematical anomaly scoring and feature extraction.
- Deterministic simulation framework with zero host risk.

---

## Data Flow & Processing Stages

1. **Generation:** Endpoint agents (Sysmon, Windows Event Log, Linux AuthLog, Zeek) produce structured telemetry.
2. **Collection:** The `TelemetryCollector` ingests logs and supports dynamic blindspot/gap injection to test collector outages.
3. **Normalization:** Events are normalized into `SecurityEvent` objects with standard fields (`host`, `user`, `src_ip`, `dest_ip`, `dest_port`, `event_type`, `process_name`).
4. **Layer 1 Detection (Deterministic):** Evaluates Sigma/traditional rules (e.g. brute force threshold, PsExec service install, unauthorized sudo).
5. **Layer 2 Detection (AI / Behavioral):** Evaluates multidimensional baseline deviation across 7 features, calculating composite scores $[0.00, 1.00]$.
6. **SOAR Layer:** Executes non-destructive simulated containment policies.
7. **Audit & Report:** All raw events, alert structures, and analyst notes are persisted to `/data/experiments/experiment-XXX.json`.
