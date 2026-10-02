# Security & Safety Principles

## Strict Isolation & Safety Guarantees

1. **Local Lab Only:** All telemetry, simulations, and network operations are restricted exclusively to the RFC 1918 private subnet `10.10.10.0/24` or local memory buffers.
2. **Zero External Requests:** The simulation suite never contacts external hosts, public IPs, cloud endpoints, or corporate networks.
3. **Safe Synthetic Actions:** No destructive malware, ransomware, disk wipers, or system-altering persistence mechanisms are included.
4. **Mock Lab Credentials:** All usernames and passwords (e.g. `LabP@ssw0rd_Admin2026!`) are synthetic lab fixtures documented in `core/config.py`.
5. **Non-Destructive Automated Response:** Simulated SOAR containment actions record actions and software-isolation states in memory and logs without severing real operating system network interfaces.
