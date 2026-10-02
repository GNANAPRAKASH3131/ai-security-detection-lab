"""
Telemetry Collector & Visibility Controller
Handles ingestion buffering, event forwarding, component health state,
and controlled telemetry gaps/blindspots.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from core.models import SecurityEvent
from core.siem import SIEMEngine

class TelemetryCollector:
    """
    Central telemetry collector supporting dynamic component health toggling
    to simulate network partitioning, agent crashes, collector outages, or unmonitored blindspots.
    """

    def __init__(self, siem: SIEMEngine):
        self.siem = siem
        self.is_active = True
        self.suppressed_sources: List[str] = [] # list of hostnames or log_sources suppressed
        self.buffer: List[SecurityEvent] = []
        self.dropped_events_count = 0
        self.forwarded_events_count = 0
        self.analyzed_events_count = 0

        # Component Health States: "ONLINE", "OFFLINE", "PARTIAL"
        self.health_states: Dict[str, str] = {
            "windows_telemetry": "ONLINE",
            "linux_telemetry": "ONLINE",
            "auth_logs": "ONLINE",
            "network_telemetry": "ONLINE",
            "collector": "ONLINE",
            "siem_ingestion": "ONLINE",
            "ai_analytics": "ONLINE"
        }

    def set_component_health(self, component: str, state: str):
        """Update individual component health state (ONLINE, OFFLINE, PARTIAL)."""
        valid_states = ["ONLINE", "OFFLINE", "PARTIAL"]
        normalized_state = state.upper() if state.upper() in valid_states else "ONLINE"
        
        if component in self.health_states:
            self.health_states[component] = normalized_state
            
            # Synchronize with global collector flags
            if component == "collector":
                self.is_active = (normalized_state == "ONLINE")

    def get_health_status(self) -> Dict[str, Any]:
        """Returns the current telemetry pipeline health status."""
        return {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "DEGRADED" if any(v != "ONLINE" for v in self.health_states.values()) else "HEALTHY",
            "components": self.health_states,
            "metrics": {
                "events_forwarded": self.forwarded_events_count,
                "events_dropped": self.dropped_events_count,
                "events_analyzed": self.analyzed_events_count
            }
        }

    def set_gap_state(self, is_active: bool, suppressed_sources: Optional[List[str]] = None):
        """Enable or disable telemetry collection to test AI blindspots."""
        self.is_active = is_active
        self.suppressed_sources = suppressed_sources or []
        self.health_states["collector"] = "ONLINE" if is_active else "OFFLINE"

    def collect(self, event: SecurityEvent) -> bool:
        """
        Ingest event from an endpoint agent.
        Applies component-level filtering and health degradation.
        Returns True if forwarded to SIEM, False if dropped/suppressed by gap.
        """
        # 1. Check Global Collector state
        if not self.is_active or self.health_states.get("collector") == "OFFLINE":
            self.dropped_events_count += 1
            return False

        # 2. Check Host / Log Source Specific Health
        if event.host == "WIN-LAB01" and self.health_states.get("windows_telemetry") == "OFFLINE":
            self.dropped_events_count += 1
            return False

        if event.host == "SRV-LNX01" and self.health_states.get("linux_telemetry") == "OFFLINE":
            self.dropped_events_count += 1
            return False

        if event.event_type == "authentication" and self.health_states.get("auth_logs") == "OFFLINE":
            self.dropped_events_count += 1
            return False

        if event.log_source in ("Zeek", "Nginx") and self.health_states.get("network_telemetry") == "OFFLINE":
            self.dropped_events_count += 1
            return False

        # 3. Check explicit suppressed sources
        if event.host in self.suppressed_sources or event.log_source in self.suppressed_sources:
            self.dropped_events_count += 1
            return False

        # 4. Partial state: intermittent sample dropping (drop every 2nd event if PARTIAL)
        if self.health_states.get("collector") == "PARTIAL":
            if (self.forwarded_events_count + self.dropped_events_count) % 2 == 1:
                self.dropped_events_count += 1
                return False

        # 5. Check SIEM Ingestion Health
        if self.health_states.get("siem_ingestion") == "OFFLINE":
            self.dropped_events_count += 1
            return False

        # Forward directly to SIEM
        self.siem.ingest_event(event)
        self.forwarded_events_count += 1
        
        if self.health_states.get("ai_analytics") != "OFFLINE":
            self.analyzed_events_count += 1

        return True

    def ingest_event(self, event: SecurityEvent) -> bool:
        """Alias for collect(event)."""
        return self.collect(event)

    def collect_batch(self, events: List[SecurityEvent]) -> Dict[str, int]:
        """Collect batch of events and forward active ones to SIEM."""
        forwarded = 0
        dropped = 0
        for ev in events:
            if self.collect(ev):
                forwarded += 1
            else:
                dropped += 1
        return {"forwarded": forwarded, "dropped": dropped}

    def reset_stats(self):
        self.dropped_events_count = 0
        self.forwarded_events_count = 0
        self.analyzed_events_count = 0
        self.is_active = True
        self.suppressed_sources.clear()
        self.buffer.clear()
        for k in self.health_states:
            self.health_states[k] = "ONLINE"
