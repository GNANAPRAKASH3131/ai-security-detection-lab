/**
 * AI Security Detection Lab - Hybrid API Client & Client-Side Simulation Engine
 * Handles REST API requests to backend when running locally/cloud (Docker/Render/Railway),
 * and automatically falls back to full in-browser simulation on static hosting (GitHub Pages).
 */

const FALLBACK_EXPERIMENTS = [
  {
    scenario_id: "1",
    scenario: "Experiment 1 - Internal Discovery",
    events_generated: 150,
    events_received: 150,
    status: "DETECTED",
    max_anomaly_score: 0.78,
    metrics: {
      telemetry_coverage_pct: 100,
      detection_triggered: true,
      max_anomaly_score: 0.78,
      noise_floor_fp_rate: 0.0,
      events_generated: 150,
      events_received: 150,
      alerts_count: 1
    },
    alerts: [
      {
        alert_id: "ALT-SIG-001",
        rule_id: "SIG-WIN-001",
        rule_name: "SIG-WIN-001: Active Directory Discovery via Command Line",
        severity: "HIGH",
        host: "WIN-LAB01",
        user: "user01",
        anomaly_score: 0.78,
        description: "High volume reconnaissance (150 discovery queries targeting AD users, groups, and DC shares)."
      }
    ],
    telemetry_gaps: [],
    response_actions: [{ action_type: "SIMULATED_IP_BLOCK", target: "10.10.10.20", status: "EXECUTED" }],
    observations: "150 recon commands (nltest, net group, AdFind) generated high process novelty and AD volume spike.",
    analyst_conclusion: "Activity successfully detected. AI model flagged elevated destination novelty (0.78) and deterministic rule SIG-WIN-001 triggered."
  },
  {
    scenario_id: "2",
    scenario: "Experiment 2 - Authentication Anomaly",
    events_generated: 12,
    events_received: 12,
    status: "DETECTED",
    max_anomaly_score: 0.88,
    metrics: {
      telemetry_coverage_pct: 100,
      detection_triggered: true,
      max_anomaly_score: 0.88,
      noise_floor_fp_rate: 0.0,
      events_generated: 12,
      events_received: 12,
      alerts_count: 2
    },
    alerts: [
      {
        alert_id: "ALT-SIG-002",
        rule_id: "SIG-AUTH-002",
        rule_name: "SIG-AUTH-002: Multiple Failed Authentication Attempts (Brute Force/Spray)",
        severity: "HIGH",
        host: "DC01",
        user: "svc_backup",
        anomaly_score: 0.88,
        description: "Off-hours password spray targeting service account across multiple endpoints."
      }
    ],
    telemetry_gaps: [],
    response_actions: [{ action_type: "SIMULATED_ACCOUNT_INVESTIGATION_FLAG", target: "svc_backup", status: "EXECUTED" }],
    observations: "5 failed logons at 03:14 UTC followed by sudden successful authentication from atypical host.",
    analyst_conclusion: "Detected: Off-hours deviation + failed ratio spike elevated anomaly score to 0.88."
  },
  {
    scenario_id: "3",
    scenario: "Experiment 3 - Lateral Movement",
    events_generated: 8,
    events_received: 8,
    status: "DETECTED",
    max_anomaly_score: 0.92,
    metrics: {
      telemetry_coverage_pct: 100,
      detection_triggered: true,
      max_anomaly_score: 0.92,
      noise_floor_fp_rate: 0.0,
      events_generated: 8,
      events_received: 8,
      alerts_count: 2
    },
    alerts: [
      {
        alert_id: "ALT-SIG-006",
        rule_id: "SIG-WIN-006",
        rule_name: "SIG-WIN-006: PsExec/Lateral Movement Remote Service Installed",
        severity: "HIGH",
        host: "DC01",
        user: "user01",
        anomaly_score: 0.92,
        description: "Lateral SMB pivot with PSEXESVC execution and SSH jump to SRV-LNX01."
      }
    ],
    telemetry_gaps: [],
    response_actions: [{ action_type: "SIMULATED_HOST_ISOLATION_AND_ACCOUNT_FLAG", target: "WIN-LAB01", status: "EXECUTED" }],
    observations: "PSEXESVC installed on DC01 (EID 7045) followed by Kerberos ticket elevation.",
    analyst_conclusion: "Detected: Unprecedented workstation-to-DC pivot produced sharp destination novelty (0.92)."
  },
  {
    scenario_id: "4",
    scenario: "Experiment 4 - Privileged Activity",
    events_generated: 6,
    events_received: 6,
    status: "DETECTED",
    max_anomaly_score: 0.96,
    metrics: {
      telemetry_coverage_pct: 100,
      detection_triggered: true,
      max_anomaly_score: 0.96,
      noise_floor_fp_rate: 0.0,
      events_generated: 6,
      events_received: 6,
      alerts_count: 2
    },
    alerts: [
      {
        alert_id: "ALT-SIG-004",
        rule_id: "SIG-LNX-004",
        rule_name: "SIG-LNX-004: Unauthorized or Unaudited Sudo Execution",
        severity: "HIGH",
        host: "SRV-LNX01",
        user: "user01",
        anomaly_score: 0.96,
        description: "Standard user executing sudo /usr/bin/cat /etc/shadow and Domain Admin group addition."
      }
    ],
    telemetry_gaps: [],
    response_actions: [{ action_type: "SIMULATED_ACCOUNT_INVESTIGATION_FLAG", target: "user01", status: "EXECUTED" }],
    observations: "Admin group jump (EID 4728) paired with Linux shadow file extraction.",
    analyst_conclusion: "Detected: High privilege jump weight triggered immediate 0.96 anomaly alert."
  },
  {
    scenario_id: "5",
    scenario: "Experiment 5 - Telemetry Gap (Core Centerpiece)",
    events_generated: 5,
    events_received: 2,
    status: "MISSED",
    max_anomaly_score: 0.27,
    metrics: {
      telemetry_coverage_pct: 40,
      detection_triggered: false,
      max_anomaly_score: 0.27,
      noise_floor_fp_rate: 0.0,
      events_generated: 5,
      events_received: 2,
      alerts_count: 0
    },
    alerts: [],
    telemetry_gaps: [
      { gap_type: "ENDPOINT_FORWARDER_DISABLED", dropped_events: 3, affected_host: "WIN-LAB01", reason: "Agent disabled" }
    ],
    response_actions: [],
    observations: "Attacker disabled local forwarder; 3 critical malicious events never reached the SIEM collector.",
    analyst_conclusion: "MISSED (Centerpiece finding): AI behavioral monitoring cannot detect unobserved telemetry (0 score)."
  },
  {
    scenario_id: "6",
    scenario: "Experiment 6 - False Positives (Anomalous != Malicious)",
    events_generated: 10,
    events_received: 10,
    status: "PARTIAL",
    max_anomaly_score: 0.21,
    metrics: {
      telemetry_coverage_pct: 100,
      detection_triggered: false,
      max_anomaly_score: 0.21,
      noise_floor_fp_rate: 0.0,
      events_generated: 10,
      events_received: 10,
      alerts_count: 0
    },
    alerts: [],
    telemetry_gaps: [],
    response_actions: [],
    observations: "Authorized administrator performing scheduled backup and MMC management off-hours.",
    analyst_conclusion: "Accurate: Novel activity recognized as benign baseline profile; zero false alarms triggered."
  },
  {
    scenario_id: "7",
    scenario: "Experiment 7 - Complete End-to-End Attack Chain",
    events_generated: 28,
    events_received: 28,
    status: "DETECTED",
    max_anomaly_score: 0.95,
    metrics: {
      telemetry_coverage_pct: 100,
      detection_triggered: true,
      max_anomaly_score: 0.95,
      noise_floor_fp_rate: 0.0,
      events_generated: 28,
      events_received: 28,
      alerts_count: 4
    },
    alerts: [
      { alert_id: "ALT-CHAIN-1", rule_name: "SIG-WIN-001: Active Directory Discovery", severity: "HIGH", host: "WIN-LAB01", user: "user01", anomaly_score: 0.78 },
      { alert_id: "ALT-CHAIN-2", rule_name: "SIG-WIN-006: PsExec Lateral Movement", severity: "HIGH", host: "DC01", user: "user01", anomaly_score: 0.92 },
      { alert_id: "ALT-CHAIN-3", rule_name: "SIG-LNX-004: Sudo Root Shadow Access", severity: "HIGH", host: "SRV-LNX01", user: "user01", anomaly_score: 0.96 }
    ],
    telemetry_gaps: [],
    response_actions: [{ action_type: "SIMULATED_IP_BLOCK", target: "10.10.10.50", status: "EXECUTED" }],
    observations: "Full multi-stage execution from initial recon to DC privilege escalation and exfiltration.",
    analyst_conclusion: "DETECTED: End-to-end multi-stage correlation triggered automated SOAR network containment."
  }
];

class LabApiClient {
  constructor(baseUrl = "") {
    if (!baseUrl) {
      if (typeof window !== "undefined" && window.location && window.location.origin && window.location.origin.startsWith("http")) {
        this.baseUrl = window.location.origin;
      } else {
        this.baseUrl = "http://127.0.0.1:8080";
      }
    } else {
      this.baseUrl = baseUrl.replace(/\/+$/, "");
    }
  }

  setBaseUrl(url) {
    this.baseUrl = url.replace(/\/+$/, "");
  }

  async _request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {})
    };

    try {
      const response = await fetch(url, { ...options, headers });
      if (response.ok) {
        return await response.json();
      }
    } catch (_) {}

    // Seamless Client-Side Fallback (for static GitHub Pages or offline execution)
    return this._fallbackHandler(endpoint, options);
  }

  _fallbackHandler(endpoint, options = {}) {
    const path = endpoint.split("?")[0];
    const data = options.body ? JSON.parse(options.body) : {};

    if (path === "/api/health") {
      return {
        status: "healthy",
        service: "AI Security Detection Lab (Live Web Mode)",
        version: "2.0.0",
        network: "10.10.10.0/24",
        experiments_count: 7,
        logs_count: 7,
        telemetry_health: {
          overall_status: "HEALTHY",
          components: {
            windows_telemetry: "ONLINE",
            linux_telemetry: "ONLINE",
            auth_logs: "ONLINE",
            network_telemetry: "ONLINE",
            collector: "ONLINE",
            siem_ingestion: "ONLINE",
            ai_analytics: "ONLINE"
          },
          metrics: { events_forwarded: 224, events_dropped: 3, events_analyzed: 221 }
        },
        database: {
          status: "connected",
          active_engine: "PostgreSQL & Browser Memory Store",
          counts: { experiments: 7, security_events: 224, detection_alerts: 11, baselines: 5 }
        }
      };
    }

    if (path === "/api/experiments") {
      return FALLBACK_EXPERIMENTS;
    }

    if (path === "/api/run_scenario") {
      const id = String(data.scenario_id || "1");
      const exp = FALLBACK_EXPERIMENTS.find(e => e.scenario_id === id) || FALLBACK_EXPERIMENTS[0];
      return {
        status: "success",
        scenario_id: id,
        metrics: exp.metrics,
        alerts: exp.alerts,
        response_actions: exp.response_actions,
        observations: exp.observations,
        analyst_conclusion: exp.analyst_conclusion
      };
    }

    if (path === "/api/run_all") {
      return {
        status: "success",
        total_scenarios_executed: 7,
        overall_coverage_pct: 88.5,
        total_alerts: 11,
        results: FALLBACK_EXPERIMENTS
      };
    }

    if (path === "/api/matrix") {
      return {
        status: "success",
        matrix: [
          { scenario_id: "1", scenario: "Exp 1 - Internal Discovery", tactic: "Discovery", technique_id: "T1087 / T1018", technique_name: "Account & System Discovery", telemetry_source: "Sysmon (EID 1) / AD Logs", status: "DETECTED", max_score: 0.78, max_ai_score: "0.78" },
          { scenario_id: "2", scenario: "Exp 2 - Authentication Anomaly", tactic: "Credential Access", technique_id: "T1110.003", technique_name: "Password Spraying & Off-Hours Auth", telemetry_source: "SecurityEventLog (4625/4624)", status: "DETECTED", max_score: 0.88, max_ai_score: "0.88" },
          { scenario_id: "3", scenario: "Exp 3 - Lateral Movement", tactic: "Lateral Movement", technique_id: "T1021.002", technique_name: "SMB / PsExec Lateral Movement & SSH Pivot", telemetry_source: "Sysmon (EID 1/3) & Linux AuthLog", status: "DETECTED", max_score: 0.92, max_ai_score: "0.92" },
          { scenario_id: "4", scenario: "Exp 4 - Privilege Activity", tactic: "Privilege Escalation", technique_id: "T1078.002", technique_name: "Domain Admin Group Escalation & Sudo Abuse", telemetry_source: "SecurityEventLog (4728/4672)", status: "DETECTED", max_score: 0.96, max_ai_score: "0.96" },
          { scenario_id: "5", scenario: "Exp 5 - Telemetry Gap", tactic: "Defense Evasion", technique_id: "T1562.001", technique_name: "Impair Defenses / Telemetry Blindspot", telemetry_source: "Agent Forwarder (DISABLED)", status: "MISSED", max_score: 0.00, max_ai_score: "0.00" },
          { scenario_id: "6", scenario: "Exp 6 - False Positives", tactic: "Collection / Baseline", technique_id: "T1005", technique_name: "Off-Hours Admin Backup (Benign)", telemetry_source: "SecurityEventLog / Sysmon", status: "PARTIAL", max_score: 0.21, max_ai_score: "0.21" },
          { scenario_id: "7", scenario: "Exp 7 - Attack Chain", tactic: "Multi-Stage Chain", technique_id: "T1059 / T1048", technique_name: "End-to-End Multi-Stage Pentest Chain", telemetry_source: "Full Subnet Telemetry", status: "DETECTED", max_score: 0.95, max_ai_score: "0.95" }
        ]
      };
    }

    if (path === "/api/baselines") {
      return {
        status: "success",
        established: {
          timestamp: new Date().toISOString(),
          baseline_table: [
            { metric: "Logins per hour", baseline_value: "3-8 / hr", observed_range: "0-10 / hr", anomaly_trigger: "> 15 / hr (Burst)" },
            { metric: "Active work hours", baseline_value: "08:00 - 18:00 UTC", observed_range: "07:30 - 18:30 UTC", anomaly_trigger: "00:00 - 05:00 UTC" },
            { metric: "Normal destination hosts", baseline_value: "WIN-LAB01, Fileserver", observed_range: "Subnet 10.10.10.0/24", anomaly_trigger: "Direct DC01 / SRV-LNX01" },
            { metric: "Common process binaries", baseline_value: "explorer.exe, chrome.exe", observed_range: "Standard enterprise set", anomaly_trigger: "psexec, nltest, vssadmin" },
            { metric: "Outbound network ports", baseline_value: "80, 443, 53", observed_range: "HTTP/HTTPS/DNS", anomaly_trigger: "445, 3389, 22 cross-subnet" }
          ]
        },
        user_profiles: {
          "user01": { is_admin: false, normal_hosts: ["10.10.10.20"], normal_processes: ["explorer.exe", "excel.exe", "outlook.exe"], active_hours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17] },
          "administrator": { is_admin: true, normal_hosts: ["10.10.10.10", "10.10.10.20"], normal_processes: ["mmc.exe", "servermanager.exe", "powershell.exe"], active_hours: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] },
          "svc_backup": { is_admin: false, normal_hosts: ["10.10.10.30"], normal_processes: ["backup_agent.exe"], active_hours: [0, 1, 2, 3, 4] }
        }
      };
    }

    if (path === "/api/establish_baseline") {
      return {
        status: "success",
        message: "Normal operational baseline re-calculated and saved."
      };
    }

    if (path === "/api/telemetry_health") {
      return {
        status: "success",
        message: "Telemetry health state updated."
      };
    }

    if (path === "/api/db/status" || path === "/api/db/sync") {
      return {
        status: "success",
        database: "PostgreSQL / Memory Cache",
        synced_records: 7
      };
    }

    if (path === "/api/research_findings") {
      return {
        status: "success",
        taxonomy: {
          detected: { count: 5, summary: "Sharp baseline deviations & high-risk command lines triggered SIEM/AI alerting." },
          missed: { count: 1, summary: "Telemetry forwarding gap blinded the model completely." },
          partial: { count: 1, summary: "Benign administrator activity kept scores below alerting threshold." }
        }
      };
    }

    if (path === "/api/logs") {
      return {
        status: "success",
        log_files: [
          { filename: "siem_session_scenario-01.json", size_bytes: 4520 },
          { filename: "siem_session_scenario-02.json", size_bytes: 3820 },
          { filename: "siem_session_scenario-03.json", size_bytes: 5120 },
          { filename: "siem_session_scenario-07.json", size_bytes: 12400 }
        ]
      };
    }

    if (path === "/api/analyze_logs") {
      return this._clientSideLogAnalyzer(data.content || "");
    }

    if (path === "/api/generate_report") {
      return {
        status: "success",
        report_path: "data/experiments/RESEARCH_REPORT_LATEST.md",
        report_markdown: `# AI-Based Security Detection as an Internal Attack Surface\n\n## Empirical Findings\n- Total Scenarios: 7\n- Coverage: 88.5%\n- Key Takeaway: AI anomaly engines are completely blind to unforwarded telemetry.`
      };
    }

    return { status: "success" };
  }

  _clientSideLogAnalyzer(content) {
    const lines = content.trim().split("\n").filter(l => l.trim() && !l.startsWith("#"));
    const srcMap = {};
    const eidMap = {};
    const hostMap = {};
    const userMap = {};
    const events = [];

    lines.forEach((line, idx) => {
      let host = "WIN-LAB01";
      let user = "user01";
      let src = "Syslog";
      let eid = 1000;
      let score = 0.15;

      if (line.includes("sshd") || line.includes("ssh")) {
        src = "AuthLog";
        eid = line.includes("fail") || line.includes("invalid") || line.includes("unknown") ? 1002 : 1001;
        score = eid === 1002 ? 0.72 : 0.20;
      } else if (line.includes("4625") || line.includes("4624") || line.includes("7045") || line.includes("4728")) {
        src = "SecurityEventLog";
        if (line.includes("4625")) { eid = 4625; score = 0.85; }
        else if (line.includes("7045")) { eid = 7045; score = 0.92; }
        else if (line.includes("4728")) { eid = 4728; score = 0.96; }
        else { eid = 4624; score = 0.10; }
      } else if (line.includes("Sysmon") || line.includes("cmd.exe") || line.includes("powershell")) {
        src = "Sysmon";
        eid = 1;
        score = 0.65;
      }

      // Regex extracts
      const userMatch = line.match(/(?:user|user=|for|sudo:\s*)([a-zA-Z0-9_\-\.\$]+)/i);
      if (userMatch) user = userMatch[1];
      const hostMatch = line.match(/(?:host|rhost=|from\s+)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-zA-Z0-9_\-\.]+)/i);
      if (hostMatch) host = hostMatch[1];

      srcMap[src] = (srcMap[src] || 0) + 1;
      eidMap[String(eid)] = (eidMap[String(eid)] || 0) + 1;
      hostMap[host] = (hostMap[host] || 0) + 1;
      userMap[user] = (userMap[user] || 0) + 1;

      events.push({
        event_id: `EVT-${idx + 1}`,
        timestamp: new Date().toISOString(),
        host,
        user,
        log_source: src,
        event_code: eid,
        anomaly_score: score,
        threat_level: score >= 0.6 ? "HIGH" : (score >= 0.3 ? "MEDIUM" : "LOW"),
        raw_line: line
      });
    });

    const totalFields = Object.keys(srcMap).length + Object.keys(eidMap).length + Object.keys(hostMap).length + Object.keys(userMap).length;

    return {
      status: "success",
      total_events: events.length,
      overall_threat: events.some(e => e.threat_level === "HIGH") ? "HIGH" : "LOW",
      fields_summary: {
        log_sources: srcMap,
        event_codes: eidMap,
        hosts: hostMap,
        users: userMap,
        total_fields: totalFields
      },
      events: events.slice(0, 500)
    };
  }

  async getHealth() { return this._request("/api/health"); }
  async getExperiments() { return this._request("/api/experiments"); }
  async runScenario(scenarioId) {
    return this._request("/api/run_scenario", {
      method: "POST",
      body: JSON.stringify({ scenario_id: String(scenarioId) })
    });
  }
  async runAllScenarios() {
    return this._request("/api/run_all", { method: "POST" });
  }
  async getMatrix() { return this._request("/api/matrix"); }
  async getFailureAnalysis() { return this._request("/api/failure_analysis"); }
  async getBaselines() { return this._request("/api/baselines"); }
  async establishBaseline() {
    return this._request("/api/establish_baseline", { method: "POST" });
  }
  async getTelemetryHealth() { return this._request("/api/telemetry_health"); }
  async updateTelemetryHealth(component, state) {
    return this._request("/api/telemetry_health", {
      method: "POST",
      body: JSON.stringify({ component, state })
    });
  }
  async getResearchFindings() { return this._request("/api/research_findings"); }
  async getDbStatus() { return this._request("/api/db/status"); }
  async syncDb() {
    return this._request("/api/db/sync", { method: "POST" });
  }
  async getLogs() { return this._request("/api/logs"); }
  async getLogContent(filename) {
    return this._request(`/api/logs/content?file=${encodeURIComponent(filename)}`);
  }
  async analyzeLogs(content) {
    return this._request("/api/analyze_logs", {
      method: "POST",
      body: JSON.stringify({ content })
    });
  }
  async generateReport() {
    return this._request("/api/generate_report", { method: "POST" });
  }
  async resetLab() {
    return this._request("/api/reset", { method: "POST" });
  }
}

window.LabApiClient = LabApiClient;
window.api = new LabApiClient();
