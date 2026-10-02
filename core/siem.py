"""
Core SIEM Engine (Ingestion, Normalization, Traditional Rules, Behavioral Analytics, Alerting)
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import json
from pathlib import Path
from core.models import SecurityEvent, DetectionAlert, ResponseAction
from core.rules import TraditionalRuleEngine, RuleResult
from core.analytics import BehavioralAnalyticsEngine
from core.response import AutomatedResponseEngine
from core.config import LOGS_DIR

class SIEMEngine:
    """
    Central SIEM processing pipeline.
    Receives raw/normalized telemetry, runs dual-layer detection (Signature + AI),
    and executes automated response actions.
    """

    def __init__(self):
        self.rule_engine = TraditionalRuleEngine()
        self.analytics_engine = BehavioralAnalyticsEngine()
        self.response_engine = AutomatedResponseEngine()

        self.ingested_events: List[SecurityEvent] = []
        self.alerts: List[DetectionAlert] = []
        self.anomaly_log: List[Dict[str, Any]] = []

    def ingest_event(self, event: SecurityEvent) -> Tuple[List[DetectionAlert], Optional[ResponseAction]]:
        """
        Process single security event through SIEM pipeline:
        1. Store & Index
        2. Evaluate Traditional Rules
        3. Evaluate AI / Behavioral Anomaly Engine
        4. Trigger Simulated SOAR Response
        """
        self.ingested_events.append(event)
        new_alerts: List[DetectionAlert] = []
        last_response: Optional[ResponseAction] = None

        # --- Layer 1: Traditional Signature / Threshold Rules ---
        rule_results: List[RuleResult] = self.rule_engine.evaluate_event(event)
        for res in rule_results:
            rule_alert = DetectionAlert(
                detection_type="TRADITIONAL_RULE",
                rule_name=res.rule_name,
                severity=res.severity,
                host=event.host,
                user=event.user,
                anomaly_score=res.score_contribution,
                description=res.description,
                evidence_events=[event.event_id]
            )
            resp = self.response_engine.evaluate_and_respond(rule_alert)
            if resp:
                last_response = resp
            self.alerts.append(rule_alert)
            new_alerts.append(rule_alert)

        # --- Layer 2: AI / Behavioral Anomaly Engine ---
        score, tier, features, beh_alert = self.analytics_engine.analyze_event(event)
        self.anomaly_log.append({
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "host": event.host,
            "user": event.user,
            "score": score,
            "tier": tier,
            "features": features
        })

        if beh_alert:
            resp = self.response_engine.evaluate_and_respond(beh_alert)
            if resp:
                last_response = resp
            self.alerts.append(beh_alert)
            new_alerts.append(beh_alert)

        return new_alerts, last_response

    def ingest_batch(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Ingest batch of security events."""
        generated_alerts = []
        generated_responses = []

        for ev in events:
            alerts, resp = self.ingest_event(ev)
            generated_alerts.extend(alerts)
            if resp:
                generated_responses.append(resp)

        return {
            "ingested_count": len(events),
            "alerts_generated": len(generated_alerts),
            "responses_triggered": len(generated_responses),
            "alerts": [a.to_dict() for a in generated_alerts]
        }

    def dump_session_logs(self, filename: Optional[str] = None):
        """Save ingested events and alerts to disk."""
        if not filename:
            filename = f"siem_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        target_file = LOGS_DIR / filename
        data = {
            "saved_at": datetime.now().isoformat(),
            "total_events": len(self.ingested_events),
            "total_alerts": len(self.alerts),
            "events": [e.to_dict() for e in self.ingested_events],
            "alerts": [a.to_dict() for a in self.alerts],
            "anomaly_logs": self.anomaly_log,
            "responses": [r.to_dict() for r in self.response_engine.action_history]
        }
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return str(target_file)

    def reset(self):
        """Reset SIEM state for clean experiment isolation."""
        self.ingested_events.clear()
        self.alerts.clear()
        self.anomaly_log.clear()
        self.rule_engine = TraditionalRuleEngine()
        self.analytics_engine = BehavioralAnalyticsEngine()
        self.response_engine = AutomatedResponseEngine()