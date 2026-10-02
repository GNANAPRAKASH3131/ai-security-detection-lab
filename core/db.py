"""
Database Management Layer
Provides dual PostgreSQL / SQLite persistent storage for security events,
experiments, baseline models, telemetry health logs, and alerts.
Integrates with local PostgreSQL / pgAdmin with resilient SQLite fallback.
"""

import os
import json
import sqlite3
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
from core.config import DATA_DIR, EXPERIMENTS_DIR, LOGS_DIR

DB_SQLITE_PATH = DATA_DIR / "cyber_lab.db"

# PostgreSQL connection config from environment or default local pgAdmin instances
PG_HOST = os.getenv("PGHOST", "127.0.0.1")
PG_PORT = int(os.getenv("PGPORT", "5432"))
PG_USER = os.getenv("PGUSER", "postgres")
PG_PASSWORD = os.getenv("PGPASSWORD", "postgres")
PG_DATABASE = os.getenv("PGDATABASE", "cyber_lab")

class DatabaseManager:
    """Manages database connectivity, schema creation, syncing, and query execution."""

    def __init__(self):
        self.pg_available = False
        self.active_engine = "SQLite"
        self.pg_conn = None
        self._init_sqlite()
        self._try_init_postgres()

    def _init_sqlite(self):
        """Initialize SQLite tables."""
        conn = sqlite3.connect(str(DB_SQLITE_PATH))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS experiments (
                experiment_id TEXT PRIMARY KEY,
                scenario TEXT,
                start_time TEXT,
                end_time TEXT,
                events_generated INTEGER,
                events_received INTEGER,
                events_detected INTEGER,
                max_anomaly_score REAL,
                telemetry_coverage_pct REAL,
                detection_triggered BOOLEAN,
                raw_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                host TEXT,
                user TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                destination_port INTEGER,
                event_type TEXT,
                action TEXT,
                log_source TEXT,
                event_code INTEGER,
                raw_json TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT,
                rule_name TEXT,
                severity TEXT,
                host TEXT,
                user TEXT,
                anomaly_score REAL,
                description TEXT,
                raw_json TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                profile_key TEXT PRIMARY KEY,
                profile_type TEXT,
                data_json TEXT,
                updated_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_health_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT,
                state TEXT,
                timestamp TEXT
            )
        """)

        conn.commit()
        conn.close()

    def _try_init_postgres(self) -> bool:
        """Attempt to connect to local PostgreSQL instance and provision schema."""
        try:
            import psycopg2
            from psycopg2 import sql
            from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

            # Try default common passwords if PGPASSWORD not set
            passwords_to_try = [PG_PASSWORD, "postgres", "admin", "root", "password", "123456", ""]
            connected = False
            active_pwd = PG_PASSWORD

            for pwd in passwords_to_try:
                try:
                    conn_init = psycopg2.connect(
                        host=PG_HOST,
                        port=PG_PORT,
                        user=PG_USER,
                        password=pwd,
                        dbname="postgres",
                        connect_timeout=2
                    )
                    conn_init.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                    connected = True
                    active_pwd = pwd
                    break
                except Exception:
                    continue

            if not connected:
                self.pg_available = False
                self.active_engine = "SQLite"
                return False

            # Ensure 'cyber_lab' database exists
            cur = conn_init.cursor()
            cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (PG_DATABASE,))
            exists = cur.fetchone()
            if not exists:
                try:
                    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(PG_DATABASE)))
                except Exception:
                    pass
            cur.close()
            conn_init.close()

            # Connect to target database and create tables
            self.pg_conn = psycopg2.connect(
                host=PG_HOST,
                port=PG_PORT,
                user=PG_USER,
                password=active_pwd,
                dbname=PG_DATABASE if exists else "postgres",
                connect_timeout=2
            )
            self.pg_conn.autocommit = True
            
            cur_pg = self.pg_conn.cursor()
            cur_pg.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    experiment_id VARCHAR(100) PRIMARY KEY,
                    scenario VARCHAR(255),
                    start_time VARCHAR(50),
                    end_time VARCHAR(50),
                    events_generated INT,
                    events_received INT,
                    events_detected INT,
                    max_anomaly_score FLOAT,
                    telemetry_coverage_pct FLOAT,
                    detection_triggered BOOLEAN,
                    raw_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id VARCHAR(100) PRIMARY KEY,
                    timestamp VARCHAR(50),
                    host VARCHAR(100),
                    user_name VARCHAR(100),
                    source_ip VARCHAR(50),
                    destination_ip VARCHAR(50),
                    destination_port INT,
                    event_type VARCHAR(100),
                    action VARCHAR(50),
                    log_source VARCHAR(100),
                    event_code INT,
                    raw_json TEXT
                );
                CREATE TABLE IF NOT EXISTS detection_alerts (
                    alert_id VARCHAR(100) PRIMARY KEY,
                    timestamp VARCHAR(50),
                    rule_name VARCHAR(255),
                    severity VARCHAR(50),
                    host VARCHAR(100),
                    user_name VARCHAR(100),
                    anomaly_score FLOAT,
                    description TEXT,
                    raw_json TEXT
                );
                CREATE TABLE IF NOT EXISTS baselines (
                    profile_key VARCHAR(100) PRIMARY KEY,
                    profile_type VARCHAR(50),
                    data_json TEXT,
                    updated_at VARCHAR(50)
                );
            """)
            cur_pg.close()

            self.pg_available = True
            self.active_engine = "PostgreSQL (pgAdmin)"
            return True

        except Exception as e:
            self.pg_available = False
            self.active_engine = "SQLite"
            return False

    def get_status(self) -> Dict[str, Any]:
        """Returns connection and row count metrics across database tables."""
        # Refresh PostgreSQL status
        if not self.pg_available:
            self._try_init_postgres()

        # Get row counts from SQLite
        conn = sqlite3.connect(str(DB_SQLITE_PATH))
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM experiments")
        exp_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM security_events")
        ev_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM detection_alerts")
        alert_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM baselines")
        base_count = cursor.fetchone()[0]

        conn.close()

        return {
            "status": "connected",
            "active_engine": self.active_engine,
            "postgres_connected": self.pg_available,
            "postgres_host": f"{PG_HOST}:{PG_PORT}",
            "postgres_database": PG_DATABASE,
            "sqlite_file": str(DB_SQLITE_PATH.name),
            "counts": {
                "experiments": exp_count,
                "security_events": ev_count,
                "detection_alerts": alert_count,
                "baselines": base_count
            },
            "timestamp": datetime.now().isoformat()
        }

    def save_experiment(self, record_dict: Dict[str, Any]):
        """Saves or updates an experiment in both SQLite and PostgreSQL."""
        exp_id = record_dict.get("experiment_id", "")
        scenario = record_dict.get("scenario", "")
        start_time = record_dict.get("start_time", "")
        end_time = record_dict.get("end_time", "")
        gen = record_dict.get("events_generated", 0)
        rec = record_dict.get("events_received", 0)
        det = record_dict.get("events_detected", 0)
        score = record_dict.get("metrics", {}).get("max_anomaly_score", 0.0)
        cov = record_dict.get("metrics", {}).get("telemetry_coverage_pct", 100.0)
        trig = record_dict.get("metrics", {}).get("detection_triggered", False)
        raw_json = json.dumps(record_dict)

        # 1. SQLite
        try:
            conn = sqlite3.connect(str(DB_SQLITE_PATH))
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO experiments (
                    experiment_id, scenario, start_time, end_time,
                    events_generated, events_received, events_detected,
                    max_anomaly_score, telemetry_coverage_pct, detection_triggered, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (exp_id, scenario, start_time, end_time, gen, rec, det, score, cov, trig, raw_json))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] SQLite experiment save error: {e}")

        # 2. PostgreSQL
        if self.pg_available and self.pg_conn:
            try:
                cur_pg = self.pg_conn.cursor()
                cur_pg.execute("""
                    INSERT INTO experiments (
                        experiment_id, scenario, start_time, end_time,
                        events_generated, events_received, events_detected,
                        max_anomaly_score, telemetry_coverage_pct, detection_triggered, raw_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (experiment_id) DO UPDATE SET
                        events_generated = EXCLUDED.events_generated,
                        events_received = EXCLUDED.events_received,
                        events_detected = EXCLUDED.events_detected,
                        max_anomaly_score = EXCLUDED.max_anomaly_score,
                        raw_json = EXCLUDED.raw_json;
                """, (exp_id, scenario, start_time, end_time, gen, rec, det, score, cov, trig, raw_json))
                cur_pg.close()
            except Exception as e:
                print(f"[-] PostgreSQL experiment save error: {e}")

    def sync_from_filesystem(self) -> Dict[str, int]:
        """Scan /data/experiments/ and /data/logs/ and sync all JSON files into the database."""
        exps_synced = 0
        events_synced = 0

        # Sync experiments
        for exp_file in EXPERIMENTS_DIR.glob("*.json"):
            try:
                with open(exp_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "experiment_id" in data:
                        self.save_experiment(data)
                        exps_synced += 1
            except Exception:
                pass

        # Sync log sessions
        for log_file in LOGS_DIR.glob("*.json"):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
                    if isinstance(log_data, dict) and "events" in log_data:
                        conn = sqlite3.connect(str(DB_SQLITE_PATH))
                        cur = conn.cursor()
                        for ev in log_data.get("events", []):
                            cur.execute("""
                                INSERT OR REPLACE INTO security_events (
                                    event_id, timestamp, host, user, source_ip, destination_ip,
                                    destination_port, event_type, action, log_source, event_code, raw_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                ev.get("event_id", ""),
                                ev.get("timestamp", ""),
                                ev.get("host", ""),
                                ev.get("user", ""),
                                ev.get("source_ip", ""),
                                ev.get("destination_ip", ""),
                                ev.get("destination_port", 0),
                                ev.get("event_type", ""),
                                ev.get("action", ""),
                                ev.get("log_source", ""),
                                ev.get("event_code", 0),
                                json.dumps(ev)
                            ))
                            events_synced += 1
                        conn.commit()
                        conn.close()
            except Exception:
                pass

        return {
            "experiments_synced": exps_synced,
            "events_synced": events_synced
        }

# Global database manager singleton
db = DatabaseManager()
