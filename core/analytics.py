"""
AI / Behavioral Analytics Engine
Implements statistical anomaly detection, baseline deviation, behavioral scoring,
entropy analysis, and multi-feature anomaly correlation.
"""

import math
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from core.models import SecurityEvent, UserBaseline, DetectionAlert
from core.config import LAB_USERS, FEATURE_WEIGHTS, ANOMALY_THRESHOLDS

class BehavioralAnalyticsEngine:
    """
    Research-grade behavioral anomaly detection engine.
    Calculates multi-dimensional anomaly scores based on baseline deviation.
    """

    def __init__(self):
        self.baselines: Dict[str, UserBaseline] = {}
        self.host_baselines: Dict[str, Dict[str, Any]] = {}
        self.user_history: Dict[str, List[SecurityEvent]] = {}
        self._initialize_default_baselines()

    def _initialize_default_baselines(self):
        """Build initial learned normal profiles from documented lab users."""
        for username, user_info in LAB_USERS.items():
            start_hr, end_hr = user_info.get("normal_work_hours", (8, 18))
            active_hrs = list(range(start_hr, end_hr)) if start_hr < end_hr else list(range(0, 24))
            
            is_adm = "Admin" in user_info.get("privilege_level", "")
            normal_hosts = list(user_info.get("normal_hosts", ["10.10.10.20"]))
            normal_ports = [80, 443, 445, 88, 389, 53] if is_adm else [80, 443, 445]
            normal_procs = [
                "explorer.exe", "chrome.exe", "msedge.exe", "excel.exe", "outlook.exe",
                "svchost.exe", "conhost.exe", "taskhostw.exe"
            ]
            if is_adm:
                normal_procs.extend(["powershell.exe", "mmc.exe", "cmd.exe", "servermanager.exe", "ssh"])

            baseline = UserBaseline(
                user=username,
                sample_count=150,
                avg_daily_auths=12.0 if is_adm else 4.0,
                std_daily_auths=2.5 if is_adm else 1.0,
                normal_hosts=normal_hosts,
                normal_ports=normal_ports,
                normal_processes=normal_procs,
                active_hours=active_hrs,
                failed_login_ratio_mean=0.01,
                failed_login_ratio_std=0.01,
                is_admin=is_adm
            )
            self.baselines[username] = baseline

    def update_baseline(self, baseline: UserBaseline):
        """Update or insert a trained baseline."""
        self.baselines[baseline.user] = baseline

    def extract_features(self, event: SecurityEvent) -> Dict[str, float]:
        """
        Extract behavioral feature values (normalized between 0.0 and 1.0)
        based on deviation from the established user baseline.
        """
        user = event.user.lower() if event.user else "anonymous"
        baseline = self.baselines.get(user)
        
        # If user is completely unknown, assign higher baseline novelty
        if not baseline:
            baseline = UserBaseline(
                user=user,
                normal_hosts=["10.10.10.20"],
                normal_ports=[80, 443],
                normal_processes=["explorer.exe"],
                active_hours=list(range(8, 18)),
                is_admin=False
            )

        features: Dict[str, float] = {}

        # 1. Destination Host Novelty Feature (0.0 if known, 1.0 if novel/unseen target)
        dest_ip = event.destination_ip or event.host_ip
        if dest_ip and dest_ip not in baseline.normal_hosts:
            # Check if this is a high-criticality host jump (e.g. client -> DC or Linux Prod)
            if dest_ip == "10.10.10.10" and not baseline.is_admin:
                features["dest_host_novelty"] = 0.95
            elif dest_ip == "10.10.10.30" and user in ("user01", "user02"):
                features["dest_host_novelty"] = 0.85
            else:
                features["dest_host_novelty"] = 0.70
        else:
            features["dest_host_novelty"] = 0.05

        # 2. Destination Port Novelty (0.0 if standard service, 1.0 if rare admin/RPC/lateral port)
        dest_port = event.destination_port
        if dest_port:
            if dest_port in baseline.normal_ports:
                features["dest_port_novelty"] = 0.05
            elif dest_port in (22, 3389, 5985, 5986, 445, 135) and not baseline.is_admin:
                features["dest_port_novelty"] = 0.80
            else:
                features["dest_port_novelty"] = 0.50
        else:
            features["dest_port_novelty"] = 0.10

        # 3. Time-of-Day / Off-Hours Deviation
        try:
            event_dt = datetime.fromisoformat(event.timestamp)
            event_hour = event_dt.hour
        except Exception:
            event_hour = 12
        
        if event_hour in baseline.active_hours:
            features["off_hours_deviation"] = 0.05
        else:
            # Calculate distance from normal active hours
            min_dist = min(abs(event_hour - h) for h in baseline.active_hours)
            features["off_hours_deviation"] = min(1.0, 0.4 + (min_dist * 0.15))

        # 4. Authentication Frequency / Volume Spikes (Z-Score Deviation)
        recent_events = self.user_history.get(user, [])
        recent_auths = [e for e in recent_events if e.event_type == "authentication"]
        current_burst = len(recent_auths) + (1 if event.event_type == "authentication" else 0)
        
        # Calculate deviation from baseline daily/hourly average
        if baseline.std_daily_auths > 0:
            z_score = max(0.0, (current_burst - baseline.avg_daily_auths) / baseline.std_daily_auths)
            features["auth_frequency"] = min(1.0, z_score * 0.25)
        else:
            features["auth_frequency"] = 0.10

        # 5. Failed/Success Login Ratio Feature
        failed_count = event.metadata.get("consecutive_failures", 0)
        if event.action == "failure":
            failed_count = max(failed_count, 1)
        
        if failed_count == 0:
            features["failed_ratio"] = 0.02
        elif failed_count < 3:
            features["failed_ratio"] = 0.35
        elif failed_count < 6:
            features["failed_ratio"] = 0.75
        else:
            features["failed_ratio"] = 0.95

        # 6. Rare Process Execution Feature
        proc_name = (event.process_name or "").lower()
        if not proc_name:
            features["rare_process"] = 0.05
        elif any(p.lower() in proc_name for p in baseline.normal_processes):
            features["rare_process"] = 0.05
        else:
            # Check for high-risk administration/pentest tools
            high_risk_procs = ["powershell", "cmd.exe", "psexec", "whoami", "nltest", "net.exe", "rundll32", "certutil", "nmap", "nc"]
            if any(hr in proc_name for hr in high_risk_procs):
                features["rare_process"] = 0.85 if not baseline.is_admin else 0.30
            else:
                features["rare_process"] = 0.50

        # 7. Administrative Privilege Jump / Context Elevation
        if event.event_type == "privilege_elevation" or event.event_code in (4672, 4728):
            if not baseline.is_admin:
                features["admin_privilege_jump"] = 0.90
            else:
                features["admin_privilege_jump"] = 0.15
        elif "admin" in (event.command_line or "").lower() and not baseline.is_admin:
            features["admin_privilege_jump"] = 0.70
        else:
            features["admin_privilege_jump"] = 0.05

        return features

    def compute_anomaly_score(self, features: Dict[str, float]) -> Tuple[float, str]:
        """
        Computes composite multivariate weighted anomaly score in range [0.00, 1.00]
        and categorizes into LAB evaluation tiers.
        """
        total_score = 0.0
        total_weight = 0.0

        for feature_name, val in features.items():
            weight = FEATURE_WEIGHTS.get(feature_name, 0.10)
            total_score += val * weight
            total_weight += weight

        final_score = round(total_score / total_weight, 4) if total_weight > 0 else 0.0
        final_score = max(0.0, min(1.0, final_score))

        tier = "NORMAL"
        for tier_name, (low, high) in ANOMALY_THRESHOLDS.items():
            if low <= final_score <= high:
                tier = tier_name
                break

        return final_score, tier

    def analyze_event(self, event: SecurityEvent) -> Tuple[float, str, Dict[str, float], Optional[DetectionAlert]]:
        """
        Process single event, maintain user sliding history, compute score and
        produce Behavioral Anomaly Alert if score exceeds research threshold (>= 0.61).
        """
        user = event.user.lower() if event.user else "anonymous"
        if user not in self.user_history:
            self.user_history[user] = []
        self.user_history[user].append(event)
        
        # Keep window to last 50 events per user
        if len(self.user_history[user]) > 50:
            self.user_history[user].pop(0)

        features = self.extract_features(event)
        score, tier = self.compute_anomaly_score(features)

        alert = None
        if score >= 0.61: # Suspicious or Highly Anomalous in Lab Specification
            severity = "HIGH" if score >= 0.81 else "MEDIUM"
            alert = DetectionAlert(
                detection_type="BEHAVIORAL_ANOMALY",
                rule_name=f"BEH-ANOMALY: {tier} Deviation (Score: {score:.2f})",
                severity=severity,
                host=event.host,
                user=event.user,
                anomaly_score=score,
                contributing_features=features,
                description=(
                    f"Behavioral model detected significant baseline deviation for user '{event.user}' on {event.host}. "
                    f"Top anomalies: " + ", ".join([f"{k}={v:.2f}" for k, v in features.items() if v > 0.4])
                ),
                evidence_events=[event.event_id]
            )

        return score, tier, features, alert
