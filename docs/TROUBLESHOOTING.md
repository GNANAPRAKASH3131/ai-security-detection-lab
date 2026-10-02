# Troubleshooting Guide

## Common Operational Issues & Solutions

### 1. Web Dashboard Fails to Bind (`Address already in use` or Port 8080 Occupied)
- **Symptom:** `OSError: [WinError 10048] Only one usage of each socket address is normally permitted`
- **Solution:** Specify a custom port with the `-p` or `--port` flag:
  ```powershell
  python lab.py dashboard --port 8090
  ```

---

### 2. Missing Experiment Logs or Empty Dashboard
- **Symptom:** The dashboard shows `0` experiments or `No alerts triggered`.
- **Solution:** Execute the simulation suite first to populate experimental records:
  ```powershell
  python lab.py run all
  ```

---

### 3. Resetting Lab State After Experiments
- **Symptom:** Need to start clean baseline benchmarking without previous run artifacts.
- **Solution:** Run the reset script:
  ```powershell
  python lab.py reset
  # Or: python reset_lab.py
  ```

---

### 4. Running Individual Scenarios for Step-by-Step Triage
- **Command:**
  ```powershell
  python lab.py run 1    # Reconnaissance only
  python lab.py run 5    # Telemetry gap blindspot test only
  ```
