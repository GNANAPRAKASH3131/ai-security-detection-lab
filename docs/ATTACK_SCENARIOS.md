# Research Attack Scenarios Specification

This document details the 6 safe attack simulations designed to evaluate AI and rule-based detection capabilities.

---

## Scenario 1: Internal Reconnaissance & Discovery (`SCENARIO-01`)
- **Objective:** Evaluate whether SIEM and network monitoring identify anomalous internal host and port sweeps.
- **Simulated Actions:**
  1. Active Directory enumeration via PowerShell (`net group "domain admins" /domain`).
  2. Domain Controller discovery via `nltest /dclist:corp.lab`.
  3. Rapid TCP port probe targeting 12 infrastructure ports on DC01 (`10.10.10.10`).
- **Telemetry Generated:** Sysmon Event ID 1 (Process Create), Zeek network connection records.
- **Detection Triggered:** `SIG-WIN-001` (AD Discovery via CLI), `SIG-NET-005` (Internal Port Scan).

---

## Scenario 2: Authentication Anomaly & Off-Hours Spray (`SCENARIO-02`)
- **Objective:** Evaluate behavioral UEBA response to off-hours credential brute-forcing followed by successful login.
- **Simulated Actions:**
  1. 6 sequential failed logon events (`user02`) at `03:15 AM` (normal hours: 09:00 - 17:00).
  2. 1 successful logon event at `03:20 AM`.
  3. Kerberos TGT request issued to Domain Controller (`10.10.10.10`).
- **Telemetry Generated:** Windows Security Event ID 4625 (Failed Logon), 4624 (Logon Type 3), AD Kerberos Event ID 4768.
- **Detection Triggered:** `SIG-AUTH-002` (Brute Force Threshold) + Behavioral Off-Hours Anomaly.

---

## Scenario 3: Lateral Movement (`SCENARIO-03`)
- **Objective:** Determine if behavioral engines identify multi-hop pivot chains across network tiers.
- **Simulated Actions:**
  1. Kerberos Ticket Granting Service (TGS) request for CIFS service on DC01.
  2. SMB connection initiated from `WIN-LAB01` (10.10.10.20) to `DC01` (10.10.10.10).
  3. Remote service installation on DC01 (`PSEXESVC.exe`).
  4. SSH logon from DC01 to Linux Application Server (`SRV-LNX01`, 10.10.10.30).
- **Telemetry Generated:** AD Event ID 4769, Sysmon Event ID 3, Windows Event ID 7045, Linux `auth.log` SSH session.
- **Detection Triggered:** `SIG-WIN-006` (Remote Service Installation) + High Behavioral Host Novelty.

---

## Scenario 4: Privilege Escalation (`SCENARIO-04`)
- **Objective:** Distinguish unauthorized privilege jumps by standard users from authorized administrator actions.
- **Simulated Actions:**
  1. Linux sudo execution of `/usr/bin/cat /etc/shadow` by unprivileged user `user01`.
  2. Windows token privilege elevation (`SeDebugPrivilege`, Event ID 4672).
  3. Active Directory group manipulation: adding `user01` into `Domain Admins` (Event ID 4728).
- **Telemetry Generated:** Linux `auth.log` sudo record, Windows Security Event ID 4672, AD Event ID 4728.
- **Detection Triggered:** `SIG-LNX-004` (Unauthorized Sudo) + High Privilege Jump Anomaly.

---

## Scenario 5: Telemetry Visibility Gap (`SCENARIO-05`)
- **Objective:** Test monitoring blindspots when endpoint collectors or agents are suppressed or severed.
- **Simulated Actions:**
  1. Normal baseline telemetry transmitted before failure.
  2. Telemetry Collector suppressed (`is_active=False`).
  3. Simulated weaponized command execution (`powershell.exe -enc Invoke-Mimikatz`) during the gap.
  4. Telemetry Collector restored.
  5. Post-gap event arrives.
- **Telemetry Generated:** 4 events generated on endpoint; only 2 received by collector.
- **Detection Result:** **False Negative / Blindspot.** Zero alerts generated because the AI model received no telemetry during the attack execution.

---

## Scenario 6: Legitimate Admin Baseline (`SCENARIO-06`)
- **Objective:** Measure false positive rates during authorized administrative workflows.
- **Simulated Actions:**
  1. Administrator interactive login (`10:00 AM`).
  2. Server Manager / MMC console launch (`dsa.msc`).
  3. Standard Kerberos TGT acquisition.
  4. Standard LDAP management query on port 389.
- **Telemetry Generated:** Windows Event ID 4624 (Logon Type 2), Sysmon Event ID 1 (`mmc.exe`), AD Event ID 4768.
- **Detection Result:** **True Negative.** Anomaly score calculated at $\approx 0.04$ (Normal Tier); 0 false alerts generated.
