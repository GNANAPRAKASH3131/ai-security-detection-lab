"""
Log File Analyzer & SIEM Detection Workbench
Parses raw log files (JSON, Windows Event Log text, Linux Syslog, auth.log, Zeek, Nginx),
evaluates them against the dual-layer detection engine, aggregates discovered fields,
and produces detailed forensic breakdowns.
"""

import re
import json
from collections import Counter
from typing import List, Dict, Any, Optional
from datetime import datetime
from core.models import SecurityEvent, DetectionAlert
from core.siem import SIEMEngine

class LogAnalyzer:
    """Forensic Log Analyzer & Rule Evaluation Engine."""

    def __init__(self):
        self.siem = SIEMEngine()

    def parse_raw_log_line(self, line: str, index: int = 1) -> Optional[SecurityEvent]:
        """Convert a raw string log line into a normalized SecurityEvent."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # 1. JSON Format
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                return SecurityEvent(
                    event_id=data.get("event_id", f"JSON-EVT-{index:04d}"),
                    timestamp=data.get("timestamp", datetime.now().isoformat()),
                    host=data.get("host", data.get("Computer", "WIN-LAB01")),
                    host_ip=data.get("host_ip", "10.10.10.20"),
                    user=data.get("user", data.get("TargetUserName", data.get("username", "user01"))),
                    source_ip=data.get("source_ip", data.get("IpAddress", "10.10.10.20")),
                    destination_ip=data.get("destination_ip", "10.10.10.10"),
                    destination_port=data.get("destination_port", data.get("DestPort", 445)),
                    event_type=data.get("event_type", "authentication" if "4624" in str(data) or "4625" in str(data) else "process_creation"),
                    action=data.get("action", "failure" if "4625" in str(data) or "fail" in str(data).lower() else "success"),
                    process_name=data.get("process_name", data.get("Image", "cmd.exe")),
                    command_line=data.get("command_line", data.get("CommandLine", line)),
                    parent_process=data.get("parent_process", "explorer.exe"),
                    service_name=data.get("service_name"),
                    log_source=data.get("log_source", "SecurityEventLog" if "4624" in str(data) or "4625" in str(data) else "Sysmon"),
                    event_code=data.get("event_code", data.get("EventID", 1)),
                    metadata=data.get("metadata", {"raw": line})
                )
            except Exception:
                pass

        # 2. Linux Syslog / auth.log (e.g. "Jan 04 15:16:01 combo sshd(pan_unix)[19939]: ... rhost=218.188.2.4 user=root")
        syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+([a-zA-Z0-9_\-\.]+)\s+([^:\[]+)(?:\[\d+\])?:\s*(.+)$", line)
        if syslog_match:
            log_time, host_name, raw_daemon, msg = syslog_match.groups()
            daemon_name = re.sub(r"\(.*?\)", "", raw_daemon).strip()
            
            # Extract user
            user_found = None
            user_m = re.search(r"\buser[=:\s]+([a-zA-Z0-9_\-\.\$]+)", msg, re.IGNORECASE)
            if user_m and user_m.group(1).lower() != "unknown":
                user_found = user_m.group(1)
            if not user_found:
                user_m = re.search(r"(?:for|user)\s+(?:invalid\s+user\s+)?([a-zA-Z0-9_\-\.\$]+)\s+from", msg, re.IGNORECASE)
                if user_m:
                    user_found = user_m.group(1)
            if not user_found and "sudo:" in line:
                user_m = re.search(r"sudo:\s+([a-zA-Z0-9_\-\.\$]+)\s+:", msg, re.IGNORECASE)
                if user_m:
                    user_found = user_m.group(1)
            if not user_found and "ruser=" in msg:
                ruser_m = re.search(r"\bruser=([a-zA-Z0-9_\-\.\$]+)", msg, re.IGNORECASE)
                if ruser_m and ruser_m.group(1):
                    user_found = ruser_m.group(1)
            
            if not user_found:
                if "user unknown" in msg.lower():
                    user_found = "unknown"
                elif "root" in msg.lower():
                    user_found = "root"
                else:
                    user_found = "system"

            # Extract source IP / rhost
            rhost_m = re.search(r"\b(?:rhost|from|ip)[=:\s]+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,})", msg, re.IGNORECASE)
            src_ip = rhost_m.group(1) if rhost_m else "10.10.10.20"

            # Determine success or failure
            is_failure = any(w in msg.lower() for w in ["fail", "invalid", "error", "refused", "denied", "break-in", "illegal", "unknown"])
            action_type = "failure" if is_failure else "success"
            
            if "sshd" in daemon_name.lower() or "ssh" in daemon_name.lower():
                ev_type = "authentication"
                eid = 1002 if is_failure else 1001
                log_src = "AuthLog"
            elif "sudo" in daemon_name.lower() or "sudo" in msg.lower():
                ev_type = "privilege_elevation"
                eid = 1003
                log_src = "AuthLog"
            elif "ftpd" in daemon_name.lower() or "ftp" in msg.lower():
                ev_type = "authentication"
                eid = 1021 if is_failure else 1020
                log_src = "FtpLog"
            else:
                ev_type = "system_event"
                eid = 1000
                log_src = "Syslog"

            return SecurityEvent(
                event_id=f"LNX-LOG-{index:04d}",
                timestamp=datetime.now().isoformat(),
                host=host_name,
                host_ip=src_ip if "." in src_ip and src_ip.startswith("10.") else "10.10.10.30",
                user=user_found,
                source_ip=src_ip,
                destination_ip="10.10.10.30",
                destination_port=22 if "ssh" in daemon_name.lower() else (21 if "ftp" in daemon_name.lower() else 80),
                event_type=ev_type,
                action=action_type,
                process_name=daemon_name or "syslog",
                command_line=msg,
                parent_process="init",
                log_source=log_src,
                event_code=eid,
                metadata={"raw_line": line, "daemon": daemon_name, "syslog_time": log_time}
            )

        # 3. Windows Security Event / Sysmon Regex Parser
        win_eid = re.search(r"(?:EventID|EID|EventCode)[:=]\s*(\d+)", line, re.IGNORECASE)
        win_user = re.search(r"(?:User|Account|UserName|TargetUserName)[:=]\s*([a-zA-Z0-9_\-\.\$]+)", line, re.IGNORECASE)
        win_host = re.search(r"(?:Host|Computer|Workstation|ComputerName)[:=]\s*([a-zA-Z0-9_\-\.]+)", line, re.IGNORECASE)
        win_cmd = re.search(r"(?:Process|CommandLine|Command|Cmd|Image)[:=]\s*(.+?)(?:\||$)", line, re.IGNORECASE)
        win_dest = re.search(r"(?:Dest|Target|DestHost|DestinationIp)[:=]\s*([a-zA-Z0-9_\-\.]+)", line, re.IGNORECASE)

        eid = int(win_eid.group(1)) if win_eid else 1
        username = win_user.group(1) if win_user else "user01"
        hostname = win_host.group(1) if win_host else "WIN-LAB01"
        command = win_cmd.group(1).strip() if win_cmd else line
        dest_host = win_dest.group(1) if win_dest else hostname

        # Map Windows Event Codes
        if eid == 4624:
            ev_type = "authentication"
            act = "success"
            log_src = "SecurityEventLog"
            proc = "lsass.exe"
        elif eid == 4625:
            ev_type = "authentication"
            act = "failure"
            log_src = "SecurityEventLog"
            proc = "lsass.exe"
        elif eid in (4768, 4769):
            ev_type = "authentication"
            act = "success" if "0x0" in line else "failure"
            log_src = "SecurityEventLog"
            proc = "kdc.exe"
        elif eid in (4728, 4672, 7045):
            ev_type = "privilege_elevation"
            act = "executed"
            log_src = "SecurityEventLog"
            proc = "services.exe" if eid == 7045 else "lsass.exe"
        elif eid == 3:
            ev_type = "network_connection"
            act = "connected"
            log_src = "Sysmon"
            proc = "svchost.exe"
        elif eid == 4104:
            ev_type = "process_creation"
            act = "executed"
            log_src = "PowerShell"
            proc = "powershell.exe"
        else:
            ev_type = "process_creation"
            act = "executed"
            log_src = "Sysmon" if eid < 1000 else "SecurityEventLog"
            proc = command.split()[0] if command else "cmd.exe"

        return SecurityEvent(
            event_id=f"PARSED-LOG-{index:04d}",
            timestamp=datetime.now().isoformat(),
            host=hostname,
            host_ip="10.10.10.10" if "DC" in hostname else ("10.10.10.30" if "LNX" in hostname else "10.10.10.20"),
            user=username,
            source_ip="10.10.10.20",
            destination_ip="10.10.10.10" if "DC" in dest_host else "10.10.10.30",
            destination_port=445 if "psexec" in command.lower() else 443,
            event_type=ev_type,
            action=act,
            process_name=proc,
            command_line=command,
            parent_process="explorer.exe",
            log_source=log_src,
            event_code=eid,
            metadata={"raw_line": line}
        )

    def analyze_log_content(self, content: str) -> Dict[str, Any]:
        """Parse multi-line or JSON log content, extract fields summary, and run detection."""
        self.siem.reset()
        events: List[SecurityEvent] = []

        # Case 1: Try parsing as JSON array
        try:
            raw_json = json.loads(content)
            if isinstance(raw_json, list):
                for idx, item in enumerate(raw_json, 1):
                    if isinstance(item, dict):
                        events.append(SecurityEvent(
                            event_id=item.get("event_id", f"JSON-EVT-{idx:04d}"),
                            timestamp=item.get("timestamp", datetime.now().isoformat()),
                            host=item.get("host", "WIN-LAB01"),
                            host_ip=item.get("host_ip", "10.10.10.20"),
                            user=item.get("user", "user01"),
                            source_ip=item.get("source_ip", "10.10.10.20"),
                            destination_ip=item.get("destination_ip", "10.10.10.10"),
                            destination_port=item.get("destination_port", 445),
                            event_type=item.get("event_type", "process_creation"),
                            action=item.get("action", "executed"),
                            process_name=item.get("process_name", "cmd.exe"),
                            command_line=item.get("command_line", ""),
                            parent_process=item.get("parent_process", "explorer.exe"),
                            service_name=item.get("service_name"),
                            log_source=item.get("log_source", "Sysmon"),
                            event_code=item.get("event_code", 1),
                            metadata=item.get("metadata", {})
                        ))
            elif isinstance(raw_json, dict) and "events" in raw_json:
                for idx, item in enumerate(raw_json["events"], 1):
                    events.append(SecurityEvent(
                        event_id=item.get("event_id", f"JSON-EVT-{idx:04d}"),
                        timestamp=item.get("timestamp", datetime.now().isoformat()),
                        host=item.get("host", "WIN-LAB01"),
                        host_ip=item.get("host_ip", "10.10.10.20"),
                        user=item.get("user", "user01"),
                        source_ip=item.get("source_ip", "10.10.10.20"),
                        destination_ip=item.get("destination_ip", "10.10.10.10"),
                        destination_port=item.get("destination_port", 445),
                        event_type=item.get("event_type", "process_creation"),
                        action=item.get("action", "executed"),
                        process_name=item.get("process_name", "cmd.exe"),
                        command_line=item.get("command_line", ""),
                        parent_process=item.get("parent_process", "explorer.exe"),
                        service_name=item.get("service_name"),
                        log_source=item.get("log_source", "Sysmon"),
                        event_code=item.get("event_code", 1),
                        metadata=item.get("metadata", {})
                    ))
        except Exception:
            pass

        # Case 2: Line-by-line text parsing
        if not events:
            lines = content.strip().split("\n")
            for idx, line in enumerate(lines, 1):
                ev = self.parse_raw_log_line(line, index=idx)
                if ev:
                    events.append(ev)

        if not events:
            return {
                "status": "error",
                "message": "No valid log events could be parsed from input.",
                "total_events": 0,
                "fields_summary": {
                    "log_sources": {},
                    "event_codes": {},
                    "hosts": {},
                    "users": {},
                    "total_fields": 0
                },
                "events": [],
                "alerts": []
            }

        # Calculate Discovered Fields Summary
        src_counter = Counter(e.log_source for e in events if e.log_source)
        eid_counter = Counter(str(e.event_code) for e in events if e.event_code is not None)
        host_counter = Counter(e.host for e in events if e.host)
        user_counter = Counter(e.user for e in events if e.user)

        total_unique_fields = len(src_counter) + len(eid_counter) + len(host_counter) + len(user_counter)

        fields_summary = {
            "log_sources": dict(src_counter.most_common(10)),
            "event_codes": dict(eid_counter.most_common(10)),
            "hosts": dict(host_counter.most_common(10)),
            "users": dict(user_counter.most_common(10)),
            "total_fields": total_unique_fields
        }

        # Run through SIEM Engine
        all_alerts: List[Dict[str, Any]] = []
        enriched_events: List[Dict[str, Any]] = []

        for ev in events:
            alerts, _ = self.siem.ingest_event(ev)
            score, tier, _, _ = self.siem.analytics_engine.analyze_event(ev)
            ev_dict = ev.to_dict()
            ev_dict["anomaly_score"] = score
            ev_dict["threat_level"] = "HIGH" if score >= 0.6 else ("MEDIUM" if score >= 0.3 else "LOW")
            ev_dict["raw_line"] = ev.metadata.get("raw_line", ev.command_line or "")
            enriched_events.append(ev_dict)

            for a in alerts:
                all_alerts.append(a.to_dict())

        scores = [e["anomaly_score"] for e in enriched_events]
        max_score = max(scores, default=0.0)

        high_alerts = [a for a in all_alerts if a.get("severity") == "HIGH"]
        med_alerts = [a for a in all_alerts if a.get("severity") == "MEDIUM"]

        return {
            "status": "success",
            "total_events": len(events),
            "total_alerts": len(all_alerts),
            "high_severity_alerts": len(high_alerts),
            "medium_severity_alerts": len(med_alerts),
            "max_anomaly_score": round(max_score, 2),
            "overall_threat": "HIGH" if max_score >= 0.6 or len(high_alerts) > 0 else ("MEDIUM" if max_score >= 0.3 else "LOW"),
            "fields_summary": fields_summary,
            "events": enriched_events[:500],
            "alerts": all_alerts
        }
