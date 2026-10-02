# Research Experiments & Empirical Evidence Guide

## Experiment Data Schema (`/data/experiments/`)

Every executed scenario generates an immutable JSON record adhering to this schema:

```json
{
  "experiment_id": "EXP-SCENARIO-01-20261001120000",
  "scenario": "Internal Reconnaissance & Discovery",
  "start_time": "2026-10-01T12:00:00.000",
  "end_time": "2026-10-01T12:00:01.200",
  "hosts": ["WIN-LAB01", "DC01"],
  "users": ["user01"],
  "events_generated": 14,
  "events_received": 14,
  "events_detected": 13,
  "events_missed": 0,
  "alerts": [ ... ],
  "anomaly_scores": [ ... ],
  "telemetry_gaps": [ ... ],
  "response_actions": [ ... ],
  "attack_chain": [ ... ],
  "metrics": {
    "telemetry_coverage_pct": 100.0,
    "detection_triggered": true,
    "max_anomaly_score": 0.40
  },
  "observations": [ ... ],
  "analyst_conclusion": "..."
}
```

---

## Dedicated Telemetry Failure Experiment

The dedicated telemetry failure test benchmarks logging continuity against detection efficacy:

1. **Normal Operational Run:**
   - Evaluates multi-stage lateral movement.
   - Calculates baseline ingestion latency and alert count.
2. **Telemetry Gap Run:**
   - Suppresses collector during weaponized payload execution.
   - Measures missed telemetry volume and detection failure rate.
3. **Admin Baseline Run:**
   - Ingests standard authorized administrator activity.
   - Calculates empirical False Positive Rate ($FPR = \frac{FP}{FP + TN}$).

### CLI Command:
```powershell
python lab.py experiment
```
