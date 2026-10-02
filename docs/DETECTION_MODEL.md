# AI & Behavioral Detection Model Specification

## Mathematical Foundation & Scoring

The Behavioral Anomaly Engine implements a multivariate baseline deviation algorithm that normalizes multiple distinct telemetry features into a composite anomaly score $S \in [0.00, 1.00]$.

$$S = \frac{\sum_{i=1}^{n} w_i \cdot f_i}{\sum_{i=1}^{n} w_i}$$

Where $w_i$ represents the feature importance weight and $f_i \in [0.00, 1.00]$ is the feature deviation score.

---

## Behavioral Feature Dimensions

| Feature ($f_i$) | Weight ($w_i$) | Description & Formula |
| :--- | :--- | :--- |
| **`dest_host_novelty`** | `0.20` | Scored $1.0$ if target host is outside user's historical profile; $0.05$ if known. |
| **`auth_frequency`** | `0.15` | Z-score deviation $Z = \frac{x - \mu}{\sigma}$ from daily authentication mean. |
| **`failed_ratio`** | `0.15` | Non-linear score based on consecutive failed authentication attempts. |
| **`rare_process`** | `0.15` | Elevated ($0.85$) if high-risk administration binaries (`powershell`, `whoami`, `nltest`) are executed by non-admin accounts. |
| **`admin_privilege_jump`**| `0.15` | Elevated ($0.90$) upon token elevation or security group modification. |
| **`off_hours_deviation`** | `0.10` | Distance in hours between event timestamp and learned user active hours window. |
| **`dest_port_novelty`** | `0.10` | Evaluates if port (e.g. 22, 445, 3389, 5985) is typical for the user profile. |

---

## Anomaly Scoring Tiers (Lab Specification)

> **Important Research Disclaimer:** These thresholds are defined for this specific isolated research environment and do not represent universal enterprise standards.

- **`0.00 – 0.30` (NORMAL):** Expected benign user or administrative behavior.
- **`0.31 – 0.60` (UNUSUAL):** Minor baseline variance (e.g. minor time shift, new standard web port).
- **`0.61 – 0.80` (SUSPICIOUS):** Notable deviation (e.g. failed logins + off-hours access). Generates SOC investigation ticket.
- **`0.81 – 1.00` (HIGHLY ANOMALOUS):** High-risk baseline jump (e.g. lateral movement, unauthorized sudo). Triggers simulated containment.

---

## Limitations of the Model

1. **Dependence on Telemetry Ingestion:** The model evaluates only received events; unforwarded events produce a score of $0.00$.
2. **Context Blindness:** A standard user executing legitimate maintenance commands may score equally to an adversary using the same command line.
3. **Training Period Dependency:** Baselines require sufficient historical sample depth to prevent false alarms during normal organizational role shifts.
