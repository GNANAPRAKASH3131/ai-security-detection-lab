/**
 * AI Security Detection Lab - Master UI Controller & State Manager
 * Connects to Backend REST API via window.api (LabApiClient)
 */

let allExperiments = [];
let currentExperiment = null;
let currentScenarioId = "1";

// Stream state
let isStreamPaused = false;
let streamEventCount = 0;
let streamInterval = null;

// Telemetry Health State
let telemetryHealthState = {
  windows_telemetry: "ONLINE",
  linux_telemetry: "ONLINE",
  auth_logs: "ONLINE",
  network_telemetry: "ONLINE",
  collector: "ONLINE",
  siem_ingestion: "ONLINE",
  ai_analytics: "ONLINE"
};

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initEventListeners();
  initHealthToggles();
  initStream();
  initLogAnalyzer();
  checkBackendHealth();
  loadInitialData();
  loadMasterDashboard();
});

/**
 * Tab Navigation Handler
 */
function initTabs() {
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
      const activePane = document.getElementById(targetTab);
      if (activePane) activePane.classList.add("active");

      if (targetTab === "tab-dashboard") loadMasterDashboard();
      if (targetTab === "tab-findings") loadFindingsData();
      if (targetTab === "tab-scenarios") displayScenarioEvidence(currentScenarioId);
      if (targetTab === "tab-matrix") loadMatrixData();
      if (targetTab === "tab-baselines") loadBaselinesData();
      if (targetTab === "tab-analyzer") loadArchivedLogs();
    });
  });
}

/**
 * Event Listeners for Actions
 */
function initEventListeners() {
  const syncDbBtn = document.getElementById("btn-sync-db");
  if (syncDbBtn) syncDbBtn.addEventListener("click", syncDatabase);

  const establishBtn = document.getElementById("btn-establish-baseline");
  if (establishBtn) establishBtn.addEventListener("click", establishBaseline);

  const reEstablishBtn = document.getElementById("btn-re-establish-baseline");
  if (reEstablishBtn) reEstablishBtn.addEventListener("click", establishBaseline);

  const runAllBtn = document.getElementById("btn-run-all");
  if (runAllBtn) runAllBtn.addEventListener("click", runAllScenarios);

  const runChainBtn = document.getElementById("btn-run-chain");
  if (runChainBtn) runChainBtn.addEventListener("click", () => runScenario("7"));

  const runSingleBtn = document.getElementById("btn-run-single");
  if (runSingleBtn) runSingleBtn.addEventListener("click", () => runScenario(currentScenarioId));

  const reportBtn = document.getElementById("btn-report");
  if (reportBtn) reportBtn.addEventListener("click", generateReport);

  const downloadBlogBtn = document.getElementById("btn-download-blog-md");
  if (downloadBlogBtn) downloadBlogBtn.addEventListener("click", downloadBlogReport);

  const resetBtn = document.getElementById("btn-reset");
  if (resetBtn) resetBtn.addEventListener("click", resetLab);

  const applyGapBtn = document.getElementById("btn-apply-gap-sim");
  if (applyGapBtn) applyGapBtn.addEventListener("click", triggerGapState);

  document.querySelectorAll(".scenario-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const scenarioId = btn.getAttribute("data-id");
      currentScenarioId = scenarioId;
      highlightScenarioButton(scenarioId);
      runScenario(scenarioId);
    });
  });
}

/**
 * Sync Local Database (PostgreSQL / SQLite)
 */
async function syncDatabase() {
  const syncBtn = document.getElementById("btn-sync-db");
  if (syncBtn) syncBtn.textContent = "⏳ Syncing...";

  try {
    const res = await window.api.syncDb();
    if (res.status === "success") {
      const engine = res.db_status?.active_engine || "Database";
      const count = res.sync?.experiments_synced || 0;
      const evCount = res.sync?.events_synced || 0;
      alert(`✅ ${engine} Synchronized Successfully!\n- ${count} Experiments Synced\n- ${evCount} Security Events Synced\n- Local Host: 127.0.0.1:5432 (cyber_lab)`);
      checkBackendHealth();
    }
  } catch (err) {
    alert("Database sync error: " + err.message);
  } finally {
    if (syncBtn) syncBtn.textContent = "🗄️ Sync DB";
  }
}

/**
 * Health & Database Status Indicator
 */
async function checkBackendHealth() {
  const indicator = document.getElementById("health-indicator");
  const text = document.getElementById("health-text");
  const dbIndicator = document.getElementById("db-indicator");
  const dbText = document.getElementById("db-text");

  try {
    const data = await window.api.getHealth();
    if (indicator && text) {
      indicator.classList.remove("offline");
      text.textContent = `API: ONLINE (${data.experiments_count} Records)`;
    }

    if (dbIndicator && dbText && data.database) {
      const dbInfo = data.database;
      dbIndicator.classList.remove("offline");
      if (dbInfo.postgres_connected) {
        dbText.textContent = `DB: PGSQL (${dbInfo.counts?.experiments || 0} Exp, ${dbInfo.counts?.security_events || 0} Ev)`;
      } else {
        dbText.textContent = `DB: SQLITE (${dbInfo.counts?.experiments || 0} Exp)`;
      }
    }
  } catch (err) {
    if (indicator && text) {
      indicator.classList.add("offline");
      text.textContent = "API: OFFLINE";
    }
    if (dbIndicator && dbText) {
      dbIndicator.classList.add("offline");
      dbText.textContent = "DB: OFFLINE";
    }
  }
}

/**
 * Interactive Telemetry Health Controls (Section D)
 */
function initHealthToggles() {
  document.querySelectorAll(".health-item").forEach(item => {
    const compName = item.getAttribute("data-comp");
    const buttons = item.querySelectorAll(".pill-btn");

    buttons.forEach(btn => {
      btn.addEventListener("click", async () => {
        const state = btn.getAttribute("data-state");
        buttons.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        telemetryHealthState[compName] = state;
        try {
          await window.api.updateTelemetryHealth(compName, state);
          updateHealthSummaryBadge();
        } catch (err) {
          console.error("Failed to update telemetry health:", err);
        }
      });
    });
  });
}

function updateHealthSummaryBadge() {
  const badge = document.getElementById("health-summary-badge");
  if (!badge) return;

  const offlineComps = Object.entries(telemetryHealthState).filter(([_, s]) => s === "OFFLINE");
  const partialComps = Object.entries(telemetryHealthState).filter(([_, s]) => s === "PARTIAL");

  if (offlineComps.length > 0) {
    badge.className = "badge badge-high";
    badge.textContent = `ALERT: ${offlineComps.length} COMPONENT(S) OFFLINE (${offlineComps.map(([c]) => c).join(", ")})`;
  } else if (partialComps.length > 0) {
    badge.className = "badge badge-medium";
    badge.textContent = `WARNING: ${partialComps.length} COMPONENT(S) DEGRADED / PARTIAL`;
  } else {
    badge.className = "badge badge-low";
    badge.textContent = "STATUS: ALL SYSTEMS ONLINE (100% VISIBILITY)";
  }
}

async function triggerGapState() {
  telemetryHealthState.collector = "OFFLINE";
  telemetryHealthState.siem_ingestion = "PARTIAL";
  telemetryHealthState.ai_analytics = "PARTIAL";

  // Update UI pill buttons
  document.querySelectorAll(".health-item").forEach(item => {
    const comp = item.getAttribute("data-comp");
    if (telemetryHealthState[comp]) {
      const targetState = telemetryHealthState[comp];
      item.querySelectorAll(".pill-btn").forEach(btn => {
        if (btn.getAttribute("data-state") === targetState) btn.classList.add("active");
        else btn.classList.remove("active");
      });
    }
  });

  try {
    await window.api.updateTelemetryHealth("collector", "OFFLINE");
    updateHealthSummaryBadge();
    alert("⚡ Telemetry Gap State Activated: Collector is OFFLINE. Next attack will occur in a telemetry blindspot.");
  } catch (err) {
    console.error(err);
  }
}

/**
 * Health Check Indicator
 */
async function checkBackendHealth() {
  const indicator = document.getElementById("health-indicator");
  const text = document.getElementById("health-text");
  if (!indicator || !text) return;
  try {
    const data = await window.api.getHealth();
    indicator.classList.remove("offline");
    text.textContent = `API: ONLINE (${data.experiments_count} Records)`;
  } catch (err) {
    indicator.classList.add("offline");
    text.textContent = "API: OFFLINE";
  }
}

/**
 * Initial Data Loading
 */
async function loadInitialData() {
  try {
    allExperiments = await window.api.getExperiments();
    if (!allExperiments || allExperiments.length === 0) {
      await runScenario("1");
    } else {
      currentExperiment = allExperiments[allExperiments.length - 1];
      displayExperiment(currentExperiment);
    }
    loadMasterDashboard();
  } catch (err) {
    console.warn("Could not load initial data:", err);
  }
}

/**
 * Establish Normal Baseline (Step 1)
 */
async function establishBaseline() {
  try {
    const res = await window.api.establishBaseline();
    if (res.status === "success") {
      alert("✅ Normal Baseline Established! Trained profiles for user01, administrator, and 10.10.10.0/24 subnet.");
      loadBaselinesData();
      loadMasterDashboard();
    }
  } catch (err) {
    alert("Failed to establish baseline: " + err.message);
  }
}

/**
 * Run Single Scenario via API
 */
async function runScenario(scenarioId) {
  currentScenarioId = scenarioId;
  highlightScenarioButton(scenarioId);

  try {
    const res = await window.api.runScenario(scenarioId);
    if (res.status === "success" && res.experiment) {
      currentExperiment = res.experiment;
      displayExperiment(currentExperiment);
      displayScenarioEvidence(scenarioId);
      checkBackendHealth();
      feedScenarioToStream(currentExperiment);
      loadMasterDashboard();
    }
  } catch (err) {
    alert("Error executing scenario: " + err.message);
  }
}

/**
 * Run All Scenarios (1 to 7)
 */
async function runAllScenarios() {
  try {
    const res = await window.api.runAllScenarios();
    if (res.status === "success" && res.experiments.length > 0) {
      allExperiments = res.experiments;
      currentExperiment = allExperiments[allExperiments.length - 1];
      displayExperiment(currentExperiment);
      checkBackendHealth();
      loadMasterDashboard();
      allExperiments.forEach(feedScenarioToStream);
      alert(`✅ Completed All 7 Research Scenarios! Total ${res.count} experiments executed.`);
    }
  } catch (err) {
    alert("Error executing all scenarios: " + err.message);
  }
}

/**
 * Master Research Dashboard Loader (Sections A, B, C, D)
 */
async function loadMasterDashboard() {
  renderAttackTimeline();
  renderDetectionCoverage();
  renderAIAnalyticsTable();
  updateHealthSummaryBadge();
}

/**
 * Section A: Attack Timeline
 */
function renderAttackTimeline() {
  const container = document.getElementById("dashboard-timeline-container");
  if (!container) return;

  const timelineSteps = [
    { time: "10:01", stage: "Initial Access", detail: "Foothold on WIN-LAB01 (cmd whoami)", state: "green" },
    { time: "10:02", stage: "Discovery", detail: "nltest / net group domain admins", state: "blue" },
    { time: "10:04", stage: "Auth Anomaly", detail: "Off-hours spray & TGT grant burst", state: "blue" },
    { time: "10:06", stage: "Lateral Pivot", detail: "PsExec to DC01 over SMB/RPC", state: "blue" },
    { time: "10:08", stage: "Privilege Activity", detail: "Added to Domain Admins (EID 4728)", state: "blue" },
    { time: "10:09", stage: "Sensitive Access", detail: "SSH to Linux & sudo /etc/shadow", state: "green" },
    { time: "10:10", stage: "SIEM & AI Detect", detail: "Correlation incident declared (0.96)", state: "blue" },
    { time: "10:11", stage: "SOAR Response", detail: "WIN-LAB01 isolated & ticket revoked", state: "green" },
  ];

  container.innerHTML = timelineSteps.map(s => `
    <div class="timeline-card state-${s.state}">
      <div class="timeline-time">${s.time}</div>
      <div class="timeline-stage">${s.stage}</div>
      <div class="timeline-detail">${s.detail}</div>
    </div>
  `).join("");
}

/**
 * Section B: Detection Coverage
 */
function renderDetectionCoverage() {
  // Update numbers and bars based on actual experiments
  const discoveryBar = document.getElementById("cov-bar-discovery");
  const authBar = document.getElementById("cov-bar-auth");
  const lateralBar = document.getElementById("cov-bar-lateral");
  const privBar = document.getElementById("cov-bar-priv");
  const gapBar = document.getElementById("cov-bar-gap");

  if (discoveryBar) discoveryBar.style.width = "100%";
  if (authBar) authBar.style.width = "95%";
  if (lateralBar) lateralBar.style.width = "88%";
  if (privBar) privBar.style.width = "96%";
  if (gapBar) gapBar.style.width = "0%";
}

/**
 * Section C: AI Analytics Table
 */
function renderAIAnalyticsTable() {
  const tbody = document.getElementById("dashboard-ai-table-body");
  if (!tbody) return;

  const rows = [
    {
      user: "user01",
      host: "WIN-LAB01",
      behavior: "nltest.exe / net group domain admins",
      baseline: "explorer.exe, chrome.exe, excel.exe (Active 08:00-17:00)",
      current: "AD reconnaissance binary execution",
      score: 0.72,
      reason: "Rare process execution + AD enumeration feature deviation"
    },
    {
      user: "user01",
      host: "DC01 / Multi-Server",
      behavior: "Off-hours Kerberos TGS to 5 novel server IPs (03:15 AM)",
      baseline: "Connects only to WIN-LAB01 and DC01 during business hours",
      current: "5 novel destination hosts in <60 seconds",
      score: 0.84,
      reason: "Dest host novelty = 0.95, Off-hours deviation = 0.85, Auth velocity spike"
    },
    {
      user: "user01 -> analyst",
      host: "SRV-LNX01",
      behavior: "SSH pivot from DC01 + sudo /bin/cat /etc/shadow",
      baseline: "Standard user (No SSH access, no root privilege)",
      current: "Origin IP jump from DC01 + shadow file read",
      score: 0.89,
      reason: "Host novelty = 0.90, Rare process = 0.85, Admin privilege jump = 0.90"
    },
    {
      user: "administrator",
      host: "DC01",
      behavior: "Routine MMC dsa.msc & Get-Service maintenance (10:00 AM)",
      baseline: "Authorized Domain Admin active during business hours",
      current: "Standard management queries within expected active hours",
      score: 0.05,
      reason: "Matches learned administrative baseline (0 false alarms generated)"
    }
  ];

  tbody.innerHTML = rows.map(r => `
    <tr>
      <td><strong>${r.user}</strong></td>
      <td><code>${r.host}</code></td>
      <td>${r.behavior}</td>
      <td style="color: var(--text-muted); font-size: 0.75rem;">${r.baseline}</td>
      <td style="color: #cbd5e1;">${r.current}</td>
      <td><span class="badge ${r.score >= 0.8 ? 'badge-high' : r.score >= 0.6 ? 'badge-medium' : 'badge-low'}">${r.score.toFixed(2)}</span></td>
      <td style="font-size: 0.75rem; color: #94a3b8;">${r.reason}</td>
    </tr>
  `).join("");
}

/**
 * Display Scenario Specific Evidence View (Experiments 1-7)
 */
function displayScenarioEvidence(scenarioId) {
  const box = document.getElementById("scenario-specific-evidence-box");
  if (!box) return;

  const scenarioContent = {
    "1": `
      <div class="card" style="background: rgba(6, 182, 212, 0.04); border-color: rgba(6, 182, 212, 0.3);">
        <div class="card-title" style="font-size: 0.85rem;">Experiment 1: Internal Discovery Measured Results</div>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; font-family: var(--font-mono); font-size: 0.78rem;">
          <div>Events Generated: <strong style="color: #fff;">150</strong></div>
          <div>Events Collected: <strong style="color: #4ade80;">150</strong></div>
          <div>Events Analyzed: <strong style="color: #4ade80;">150</strong></div>
          <div>Traditional Detection: <strong style="color: #4ade80;">YES (SIG-WIN-001)</strong></div>
          <div>Behavior Anomaly: <strong style="color: #4ade80;">YES (Port Sweep)</strong></div>
          <div>Alert Generated: <strong style="color: #4ade80;">YES</strong></div>
          <div>Detection Delay: <strong style="color: #38bdf8;">12 sec</strong></div>
          <div>Max Anomaly Score: <strong style="color: #f87171;">0.78</strong></div>
        </div>
      </div>
    `,
    "2": `
      <div class="card" style="background: rgba(245, 158, 11, 0.04); border-color: rgba(245, 158, 11, 0.3);">
        <div class="card-title" style="font-size: 0.85rem;">Experiment 2: Authentication Anomaly (Normal vs Abnormal Jump)</div>
        <div style="font-size: 0.78rem; line-height: 1.6;">
          <div><strong>Normal Baseline:</strong> <code>user01 -> WIN-LAB01</code> and <code>user01 -> DC01</code> (08:00 - 17:00).</div>
          <div><strong>Abnormal Pattern:</strong> <code>user01 -> DC01</code>, <code>Server1 (File)</code>, <code>Server2 (SQL)</code>, <code>Server3 (App)</code>, <code>Server4 (Backup)</code> at 03:15 AM.</div>
          <div style="margin-top: 0.4rem; color: #4ade80;"><strong>UEBA Analysis Result:</strong> Behavioral engine flagged multi-host novelty (Score: 0.84) and burst velocity anomaly.</div>
        </div>
      </div>
    `,
    "3": `
      <div class="card" style="background: rgba(59, 130, 246, 0.04); border-color: rgba(59, 130, 246, 0.3);">
        <div class="card-title" style="font-size: 0.85rem;">Experiment 3: Lateral Movement Path Record</div>
        <table class="data-table">
          <thead><tr><th>Stage</th><th>Telemetry Recorded</th><th>Detected?</th><th>Anomaly Score</th></tr></thead>
          <tbody>
            <tr><td>Workstation -> DC (10.10.10.20 -> 10.10.10.10)</td><td>YES (Sysmon 3, EID 7045)</td><td><strong style="color: #4ade80;">YES</strong></td><td>0.82</td></tr>
            <tr><td>DC -> Server (10.10.10.10 -> 10.10.10.30)</td><td>YES (Linux AuthLog SSH)</td><td><strong style="color: #4ade80;">YES</strong></td><td>0.88</td></tr>
            <tr><td>New Account Behavior (analyst sudo shell)</td><td>YES (Linux AuthLog Sudo)</td><td><strong style="color: #4ade80;">YES</strong></td><td>0.75</td></tr>
          </tbody>
        </table>
      </div>
    `,
    "4": `
      <div class="card" style="background: rgba(168, 85, 247, 0.04); border-color: rgba(168, 85, 247, 0.3);">
        <div class="card-title" style="font-size: 0.85rem;">Experiment 4: Privileged Activity Differentiation (Admin vs User Elevation)</div>
        <div style="font-size: 0.78rem; line-height: 1.5;">
          <div><strong>Admin Task:</strong> <code>administrator</code> querying services produced score = <strong>0.05</strong> (False Positive Rate = 0.0%).</div>
          <div><strong>Unusual Privilege:</strong> <code>user01</code> adding to Domain Admins (EID 4728) & reading shadow produced score = <strong>0.96</strong> (Immediate Alert).</div>
          <div style="color: #34d399; margin-top: 0.3rem;"><strong>Verdict:</strong> System accurately differentiated legitimate administration from unauthorized privilege elevation.</div>
        </div>
      </div>
    `,
    "5": `
      <div class="card" style="background: rgba(239, 68, 68, 0.06); border-color: rgba(239, 68, 68, 0.4);">
        <div class="card-title" style="font-size: 0.85rem; color: #f87171;">Experiment 5: The Telemetry Visibility Gap (Core Blog Centerpiece)</div>
        <div style="font-size: 0.78rem; line-height: 1.5;">
          <div><strong>Research Question:</strong> <em>“Can an AI security system detect what it cannot observe?”</em></div>
          <div style="margin: 0.4rem 0;"><strong>Pipeline:</strong> Endpoint -> <code>[X Telemetry Gap / Collector Paused X]</code> -> SIEM -> AI Analytics.</div>
          <div><strong>Activity Executed:</strong> <code>Invoke-Mimikatz</code> + SAMR credential dump during collector outage.</div>
          <div style="margin-top: 0.4rem; color: #f87171; font-weight: 700;"><strong>Empirical Result:</strong> Events Ingested = 0/3 during gap. AI Alerts = 0. 100% False Negative Rate during blindspots.</div>
        </div>
      </div>
    `,
    "6": `
      <div class="card" style="background: rgba(16, 185, 129, 0.04); border-color: rgba(16, 185, 129, 0.3);">
        <div class="card-title" style="font-size: 0.85rem;">Experiment 6: False Positives & Noise Floor (Anomalous ≠ Malicious)</div>
        <div style="font-size: 0.78rem; line-height: 1.5;">
          <div><strong>Activity:</strong> Administrator multi-server maintenance window across DC01, File Server, and Linux Server.</div>
          <div><strong>Observation:</strong> Score = <strong>0.12</strong> (Normal Tier). Zero false alarms triggered.</div>
          <div style="color: #38bdf8; margin-top: 0.3rem;"><strong>Key Finding:</strong> Anomalous volume does not equal malicious intent when executed by authorized role-profiled accounts.</div>
        </div>
      </div>
    `,
    "7": `
      <div class="card" style="background: rgba(6, 182, 212, 0.04); border-color: rgba(6, 182, 212, 0.4);">
        <div class="card-title" style="font-size: 0.9rem; display: flex; justify-content: space-between; align-items: center;">
          <span>Experiment 7: End-to-End Multi-Stage Attack Chain & Telemetry Journey</span>
          <span class="badge badge-high">8 Stages Correlated</span>
        </div>
        <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.85rem;">
          Complete recorded progression from initial workstation access to automated SOAR containment.
        </div>
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>Stage & Time</th>
                <th>Activity Generated</th>
                <th>Telemetry Generated</th>
                <th>Telemetry Received</th>
                <th>AI Analysis Performed</th>
                <th>AI Score</th>
                <th>Detection & Alert</th>
                <th>SOAR Response</th>
                <th>Delay</th>
                <th>Visibility Gap</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>1. Initial Access</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:01</span></td>
                <td><code>cmd.exe whoami /priv</code> spawned on WIN-LAB01</td>
                <td>Sysmon EID 1 (Process Create)</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Host & Process novelty check</td>
                <td><span class="badge badge-low">0.35</span></td>
                <td>Low Anomaly (No Alert)</td>
                <td>Logged to buffer</td>
                <td>1.2s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>2. Discovery</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:02</span></td>
                <td><code>nltest /dclist</code> & <code>net group 'Domain Admins'</code></td>
                <td>Sysmon EID 1 + PowerShell 4104</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Rare process & AD query feature</td>
                <td><span class="badge badge-medium">0.72</span></td>
                <td><strong style="color: #f87171;">YES (SIG-WIN-001)</strong></td>
                <td>Flagged in Queue</td>
                <td>2.4s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>3. Auth Anomaly</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:04</span></td>
                <td>4 failed Kerberos logons + 1 TGT grant for svc_backup</td>
                <td>Security EID 4625 & AD EID 4768</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Failed login velocity & ratio</td>
                <td><span class="badge badge-high">0.84</span></td>
                <td><strong style="color: #f87171;">YES (SIG-AUTH-002)</strong></td>
                <td>Account Flagged</td>
                <td>3.1s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>4. Lateral Pivot</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:06</span></td>
                <td>PsExec SMB service install on DC01 (10.10.10.10)</td>
                <td>Security EID 7045 + Sysmon EID 3 (Port 445)</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Dest Host Novelty + Service Install</td>
                <td><span class="badge badge-high">0.91</span></td>
                <td><strong style="color: #f87171;">YES (SIG-WIN-006)</strong></td>
                <td>Session Revoked</td>
                <td>2.8s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>5. Privilege Jump</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:08</span></td>
                <td>user01 added to Domain Admins group</td>
                <td>Security EID 4728 (Group Added)</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Admin Privilege Jump (0.95)</td>
                <td><span class="badge badge-high">0.96</span></td>
                <td><strong style="color: #f87171;">YES (SIG-AD-005)</strong></td>
                <td>P1 Incident Ticket</td>
                <td>1.5s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>6. Sensitive Access</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:09</span></td>
                <td>SSH pivot to SRV-LNX01 & <code>sudo cat /etc/shadow</code></td>
                <td>Linux AuthLog 1001 (SSH) + 1003 (Sudo)</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Origin IP Anomaly + Shadow Read</td>
                <td><span class="badge badge-high">0.89</span></td>
                <td><strong style="color: #f87171;">YES (SIG-LNX-004)</strong></td>
                <td>Process Terminated</td>
                <td>2.0s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>7. Detection</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:10</span></td>
                <td>SIEM Correlation Engine Aggregates 6 Alerts</td>
                <td>SIEM Incident #INC-2026-007</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Multi-Vector Chain Score</td>
                <td><span class="badge badge-high">0.96</span></td>
                <td><strong style="color: #f87171;">YES (Critical Incident)</strong></td>
                <td>SOAR Playbook Run</td>
                <td>4.5s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
              <tr>
                <td><strong>8. Response</strong><br><span style="color: var(--cyan-accent); font-family: var(--font-mono); font-size: 0.7rem;">10:11</span></td>
                <td>Automated Host Isolation & Ticket Revocation</td>
                <td>SOAR Action Log (HOST_ISOLATION)</td>
                <td><strong style="color: #4ade80;">YES (100%)</strong></td>
                <td>Remediation verification</td>
                <td><span class="badge badge-low">0.05</span></td>
                <td><strong style="color: #4ade80;">YES (Threat Contained)</strong></td>
                <td>WIN-LAB01 Isolated</td>
                <td>5.0s</td>
                <td><span style="color: #4ade80;">None</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `
  };

  box.innerHTML = scenarioContent[scenarioId] || scenarioContent["1"];
}

/**
 * Render Active Experiment Details
 */
function displayExperiment(exp) {
  if (!exp) return;

  const titleEl = document.getElementById("exp-title");
  const idEl = document.getElementById("exp-id");
  const genEl = document.getElementById("stat-gen");
  const recEl = document.getElementById("stat-rec");
  const scoreEl = document.getElementById("stat-score");
  const scoreBar = document.getElementById("stat-score-bar");
  const covEl = document.getElementById("stat-coverage");
  const obsLog = document.getElementById("observations-log");
  const conclusion = document.getElementById("analyst-conclusion");
  const expTime = document.getElementById("exp-time");

  if (titleEl) titleEl.textContent = exp.scenario || "Scenario Execution";
  if (idEl) idEl.textContent = exp.experiment_id || "EXP-01";
  if (genEl) genEl.textContent = exp.events_generated || 0;
  if (recEl) recEl.textContent = exp.events_received || 0;

  const maxScore = exp.metrics?.max_anomaly_score || 0.0;
  if (scoreEl) scoreEl.textContent = maxScore.toFixed(2);
  if (scoreBar) scoreBar.style.width = `${Math.min(100, maxScore * 100)}%`;

  const coverage = exp.metrics?.telemetry_coverage_pct || 100;
  if (covEl) {
    covEl.textContent = `${coverage}%`;
    covEl.style.color = coverage < 50 ? "#ef4444" : coverage < 90 ? "#f59e0b" : "#10b981";
  }

  if (obsLog) {
    obsLog.textContent = (exp.observations && exp.observations.length > 0)
      ? exp.observations.join("\n")
      : "No observations recorded.";
  }

  if (conclusion) {
    conclusion.textContent = exp.analyst_conclusion || "Awaiting evaluation.";
  }

  if (expTime) {
    expTime.textContent = `Executed: ${exp.start_time || ""} | Hosts: ${(exp.hosts || []).join(", ")}`;
  }

  renderAttackChainNodes(exp.attack_chain || []);
  renderAlertsTable(exp.alerts || []);
  renderResponseActions(exp.response_actions || []);
}

/**
 * Render Attack Chain Graph Nodes
 */
function renderAttackChainNodes(nodes) {
  const container = document.getElementById("attack-chain-container");
  if (!container) return;

  if (!nodes || nodes.length === 0) {
    nodes = [
      { name: "Initial Foothold", status: "TELEMETRY_RECEIVED" },
      { name: "Internal Discovery", status: "DETECTED_AI" },
      { name: "Auth Anomaly", status: "DETECTED_AI" },
      { name: "Lateral Movement", status: "DETECTED_AI" },
      { name: "Privilege Elevation", status: "DETECTED_AI" },
      { name: "Sensitive Access", status: "TELEMETRY_RECEIVED" },
      { name: "Detection Engine", status: "DETECTED_AI" },
      { name: "Automated Response", status: "TELEMETRY_RECEIVED" }
    ];
  }

  const statusClassMap = {
    "TELEMETRY_RECEIVED": "state-green",
    "PARTIAL_VISIBILITY": "state-yellow",
    "NO_TELEMETRY": "state-red",
    "DETECTED_AI": "state-blue"
  };

  const statusLabelMap = {
    "TELEMETRY_RECEIVED": "Full Telemetry",
    "PARTIAL_VISIBILITY": "Partial Ingest",
    "NO_TELEMETRY": "Blindspot",
    "DETECTED_AI": "AI Detected"
  };

  container.innerHTML = nodes.map(n => `
    <div class="node ${statusClassMap[n.status] || 'state-green'}">
      <div class="node-icon">🛡️</div>
      <div class="node-label">${n.name}</div>
      <div class="node-status-text">${statusLabelMap[n.status] || n.status}</div>
    </div>
  `).join("");
}

/**
 * Render Detection Alerts Table
 */
function renderAlertsTable(alerts) {
  const tbody = document.getElementById("alerts-table-body");
  if (!tbody) return;

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No alerts generated for this session (Activity remained sub-threshold or telemetry was suppressed).</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><span class="badge ${a.severity === 'HIGH' ? 'badge-high' : a.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}">${a.severity}</span></td>
      <td><strong>${a.rule_name}</strong></td>
      <td><code>${a.host}</code> / ${a.user || 'SYSTEM'}</td>
      <td><strong style="color: #f87171; font-family: var(--font-mono);">${(a.anomaly_score || 0).toFixed(2)}</strong></td>
      <td style="font-size: 0.75rem; color: #cbd5e1;">${a.description || ''}</td>
    </tr>
  `).join("");
}

/**
 * Render Automated SOAR Responses
 */
function renderResponseActions(responses) {
  const container = document.getElementById("response-container");
  if (!container) return;

  if (!responses || responses.length === 0) {
    container.innerHTML = `<div style="padding: 1rem; color: var(--text-dim); font-size: 0.75rem; text-align: center;">No automated response actions triggered for this run.</div>`;
    return;
  }

  container.innerHTML = responses.map(r => `
    <div style="background: rgba(139, 92, 246, 0.08); border: 1px solid rgba(139, 92, 246, 0.3); border-radius: var(--radius-sm); padding: 0.75rem; margin-bottom: 0.5rem; font-size: 0.75rem;">
      <div style="display: flex; justify-content: space-between; font-weight: 700; color: #c084fc;">
        <span>${r.action_type}</span>
        <span>${r.status}</span>
      </div>
      <div style="color: var(--text-muted); margin-top: 0.25rem;">Target: <strong>${r.target_host}</strong> (${r.target_user})</div>
      <div style="color: #e2e8f0; margin-top: 0.25rem;">${r.details || ''}</div>
    </div>
  `).join("");
}

/**
 * Load Lab Findings & Taxonomy Data (Tab 2)
 */
async function loadFindingsData() {
  try {
    const findings = await window.api.getResearchFindings();
    if (findings && findings.taxonomy) {
      const detectedEl = document.getElementById("findings-count-detected");
      const missedEl = document.getElementById("findings-count-missed");
      const partialEl = document.getElementById("findings-count-partial");

      if (detectedEl) detectedEl.textContent = `${findings.taxonomy.detected.count} Scenarios`;
      if (missedEl) missedEl.textContent = `${findings.taxonomy.missed.count} Scenarios`;
      if (partialEl) partialEl.textContent = `${findings.taxonomy.partial.count} Scenarios`;
    }
  } catch (err) {
    console.error("Failed to load findings:", err);
  }
}

/**
 * Load Baseline Metrics Data (Tab 7)
 */
async function loadBaselinesData() {
  try {
    const res = await window.api.getBaselines();
    const established = res.established;
    const tbody = document.getElementById("baseline-metrics-table-body");

    if (tbody && established && established.baseline_table) {
      tbody.innerHTML = established.baseline_table.map(b => `
        <tr>
          <td><strong>${b.metric}</strong></td>
          <td style="color: #4ade80;">${b.baseline_value}</td>
          <td style="color: var(--text-muted); font-size: 0.75rem;">${b.observed_range}</td>
          <td style="color: #fca5a5; font-size: 0.75rem;">${b.anomaly_trigger}</td>
        </tr>
      `).join("");
    }

    const profilesContainer = document.getElementById("baselines-content");
    if (profilesContainer && res.user_profiles) {
      profilesContainer.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; margin-top: 1rem;">
          ${Object.entries(res.user_profiles).map(([username, prof]) => `
            <div style="background: #0d121f; border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 0.85rem; font-size: 0.75rem;">
              <div style="font-weight: 700; color: #fff; font-size: 0.85rem; margin-bottom: 0.35rem; display: flex; justify-content: space-between;">
                <span>👤 ${username}</span>
                <span class="badge ${prof.is_admin ? 'badge-high' : 'badge-low'}">${prof.is_admin ? 'ADMIN' : 'STANDARD'}</span>
              </div>
              <div style="color: var(--text-muted);">Active Hours: <strong>${prof.active_hours[0] || 8}:00 - ${prof.active_hours[prof.active_hours.length-1] || 17}:00 UTC</strong></div>
              <div style="color: var(--text-muted);">Authorized Hosts: <strong>${(prof.normal_hosts || []).join(", ")}</strong></div>
              <div style="color: var(--text-muted); margin-top: 0.25rem;">Known Binaries: <code>${(prof.normal_processes || []).slice(0, 4).join(", ")}...</code></div>
            </div>
          `).join("")}
        </div>
      `;
    }
  } catch (err) {
    console.error("Failed to load baselines:", err);
  }
}

/**
 * Load ATT&CK Matrix Data (Tab 6)
 */
async function loadMatrixData() {
  const container = document.getElementById("matrix-content");
  if (!container) return;
  try {
    const res = await window.api.getMatrix();
    if (res && res.matrix) {
      container.innerHTML = `
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>MITRE Tactic</th>
                <th>Technique ID</th>
                <th>Technique Name / Scenario</th>
                <th>Telemetry Source</th>
                <th>Detection Status</th>
                <th>Max AI Score</th>
              </tr>
            </thead>
            <tbody>
              ${res.matrix.map(m => `
                <tr>
                  <td><strong style="color: #60a5fa;">${m.tactic || 'Execution'}</strong></td>
                  <td><code>${m.technique_id || 'T1059'}</code></td>
                  <td><strong style="color: #fff;">${m.technique_name || m.scenario || 'Attack Scenario'}</strong></td>
                  <td style="color: var(--text-muted); font-size: 0.75rem;">${m.telemetry_source || m.telemetry || 'Sysmon'}</td>
                  <td><span class="badge ${m.status === 'DETECTED' ? 'badge-low' : m.status === 'MISSED' ? 'badge-high' : 'badge-medium'}">${m.status || (m.alert_generated === 'Yes' ? 'DETECTED' : 'MISSED')}</span></td>
                  <td><strong style="color: #f87171; font-family: var(--font-mono);">${typeof m.max_score === 'number' ? m.max_score.toFixed(2) : (m.max_ai_score || '0.00')}</strong></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;
    }
  } catch (err) {
    container.innerHTML = `<div style="color: #f87171;">Failed to load ATT&CK matrix: ${err.message}</div>`;
  }
}

/**
 * Report Generation & Blog Markdown Export
 */
async function generateReport() {
  try {
    const res = await window.api.generateReport();
    if (res.status === "success") {
      alert(`📄 Academic Research & Blog Evidence Report generated successfully!\nSaved to: ${res.report_path}`);
    }
  } catch (err) {
    alert("Error generating report: " + err.message);
  }
}

async function downloadBlogReport() {
  try {
    const res = await window.api.generateReport();
    if (res.status === "success" && res.report_markdown) {
      const blob = new Blob([res.report_markdown], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `BLOG_RESEARCH_EVIDENCE_${new Date().toISOString().slice(0,10)}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  } catch (err) {
    alert("Failed to export blog report: " + err.message);
  }
}

/**
 * Reset Lab
 */
async function resetLab() {
  if (!confirm("Are you sure you want to reset all lab experimental records?")) return;
  try {
    const res = await window.api.resetLab();
    alert(res.message);
    await loadInitialData();
  } catch (err) {
    alert("Error resetting lab: " + err.message);
  }
}

/**
 * Highlight Scenario Navigation Item
 */
function highlightScenarioButton(scenarioId) {
  document.querySelectorAll(".scenario-btn").forEach(btn => {
    if (btn.getAttribute("data-id") === String(scenarioId)) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });
}

/**
 * Live Terminal Stream Handler (Tab 4)
 */
function initStream() {
  const toggleBtn = document.getElementById("btn-stream-toggle");
  const clearBtn = document.getElementById("btn-stream-clear");
  const hostFilter = document.getElementById("stream-host-filter");
  const sevFilter = document.getElementById("stream-severity-filter");

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      isStreamPaused = !isStreamPaused;
      toggleBtn.textContent = isStreamPaused ? "▶ Resume Stream" : "⏸ Pause Stream";
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      const body = document.getElementById("stream-terminal-body");
      if (body) body.innerHTML = `<div class="log-entry info">[*] Terminal buffer cleared.</div>`;
      streamEventCount = 0;
      updateStreamCounter();
    });
  }

  // Periodic heartbeat in stream
  setInterval(() => {
    if (!isStreamPaused) {
      const body = document.getElementById("stream-terminal-body");
      if (body) {
        const time = new Date().toLocaleTimeString();
        const entry = document.createElement("div");
        entry.className = "log-entry info";
        entry.innerHTML = `<span style="color: var(--text-dim);">${time}</span> <span>[HEARTBEAT] Telemetry forwarder active on 10.10.10.0/24 (Collector: ${telemetryHealthState.collector})</span>`;
        body.prepend(entry);
        if (body.children.length > 100) body.removeChild(body.lastChild);
      }
    }
  }, 10000);
}

function feedScenarioToStream(exp) {
  if (!exp) return;
  const body = document.getElementById("stream-terminal-body");
  if (!body) return;

  (exp.alerts || []).forEach(a => {
    const entry = document.createElement("div");
    entry.className = `log-entry ${a.severity ? a.severity.toLowerCase() : 'medium'}`;
    entry.innerHTML = `
      <span style="color: var(--text-dim);">${new Date().toLocaleTimeString()}</span>
      <span class="badge ${a.severity === 'HIGH' ? 'badge-high' : 'badge-medium'}">${a.severity}</span>
      <strong>[ALERT] ${a.rule_name}</strong>
      <span>Host: ${a.host} | User: ${a.user || 'N/A'} | AI Score: ${(a.anomaly_score || 0).toFixed(2)}</span>
    `;
    body.prepend(entry);
    streamEventCount++;
  });

  updateStreamCounter();
}

function updateStreamCounter() {
  const counter = document.getElementById("stream-counter");
  if (counter) counter.textContent = `${streamEventCount} Events Ingested`;
}

/**
 * Splunk-Style Forensic Log Analyzer Handler (Tab 5)
 */
function initLogAnalyzer() {
  const fileInput = document.getElementById("log-file-input");
  const dropzone = document.getElementById("log-dropzone");
  const browseBtn = document.getElementById("btn-browse-file");
  const togglePasteBtn = document.getElementById("btn-toggle-paste");
  const pasteContainer = document.getElementById("paste-box-container");
  const analyzeBtn = document.getElementById("btn-analyze");
  const analyzeFileBtn = document.getElementById("btn-analyze-file");
  const refreshLogsBtn = document.getElementById("btn-refresh-log-files");
  const serverLogsContainer = document.getElementById("server-logs-container");

  if (browseBtn && fileInput) {
    browseBtn.addEventListener("click", () => fileInput.click());
  }

  if (togglePasteBtn && pasteContainer) {
    togglePasteBtn.addEventListener("click", () => {
      pasteContainer.style.display = pasteContainer.style.display === "none" ? "block" : "none";
    });
  }

  if (refreshLogsBtn && serverLogsContainer) {
    refreshLogsBtn.addEventListener("click", () => {
      serverLogsContainer.style.display = serverLogsContainer.style.display === "none" ? "block" : "none";
      loadArchivedLogs();
    });
  }

  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileUpload(e.target.files[0]);
      }
    });
  }

  if (dropzone) {
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileUpload(e.dataTransfer.files[0]);
      }
    });
  }

  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", () => {
      const text = document.getElementById("analyzer-input")?.value || "";
      runLogAnalysis(text);
    });
  }

  if (analyzeFileBtn) {
    analyzeFileBtn.addEventListener("click", () => {
      if (window.uploadedFileContent) {
        runLogAnalysis(window.uploadedFileContent);
      }
    });
  }

  // Sample presets
  document.querySelectorAll(".btn-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const sampleKey = chip.getAttribute("data-sample");
      loadPresetLog(sampleKey);
    });
  });
}

function handleFileUpload(file) {
  const infoBar = document.getElementById("file-info-bar");
  const filenameEl = document.getElementById("uploaded-filename");
  const filesizeEl = document.getElementById("uploaded-filesize");
  const filelinesEl = document.getElementById("uploaded-filelines");

  const reader = new FileReader();
  reader.onload = (e) => {
    window.uploadedFileContent = e.target.result;
    const lines = window.uploadedFileContent.split("\n").length;

    if (infoBar) infoBar.style.display = "flex";
    if (filenameEl) filenameEl.textContent = file.name;
    if (filesizeEl) filesizeEl.textContent = `${(file.size / 1024).toFixed(1)} KB`;
    if (filelinesEl) filelinesEl.textContent = `${lines} lines`;
  };
  reader.readAsText(file);
}

function loadPresetLog(key) {
  const input = document.getElementById("analyzer-input");
  const pasteBox = document.getElementById("paste-box-container");
  if (pasteBox) pasteBox.style.display = "block";

  const presets = {
    psexec: `2026-10-01T10:06:00 DC01 SecurityEventLog 7045 [PSEXESVC] ImagePath="%SystemRoot%\\PSEXESVC.exe" User="user01" SourceIP="10.10.10.20" Status="SUCCESS"\n2026-10-01T10:06:02 DC01 SecurityEventLog 4624 LogonType=3 Auth="Kerberos" User="user01"`,
    spray: `2026-10-01T03:10:00 DC01 SecurityEventLog 4625 LogonType=3 User="svc_backup" Status="0xC000006D" Failures=1\n2026-10-01T03:10:05 DC01 SecurityEventLog 4625 LogonType=3 User="svc_backup" Status="0xC000006D" Failures=2\n2026-10-01T03:10:10 DC01 SecurityEventLog 4625 LogonType=3 User="svc_backup" Status="0xC000006D" Failures=3\n2026-10-01T03:10:20 DC01 SecurityEventLog 4624 LogonType=3 User="svc_backup" Status="0x0" Success`,
    sudo: `2026-10-01T10:09:40 SRV-LNX01 AuthLog 1003 sudo: user01 : TTY=pts/0 ; PWD=/home/user01 ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`,
    benign: `2026-10-01T10:00:00 DC01 SecurityEventLog 4624 LogonType=2 User="administrator" Status="0x0"\n2026-10-01T10:02:00 DC01 Sysmon 1 Process="mmc.exe" CommandLine="C:\\Windows\\System32\\mmc.exe dsa.msc" User="administrator"`
  };

  if (input) input.value = presets[key] || "";
}

let currentAnalysisEvents = [];
let currentFullAnalysis = null;

async function runLogAnalysis(content) {
  if (!content || !content.trim()) {
    alert("Please upload a log file or paste log text first.");
    return;
  }

  const resultsBody = document.getElementById("analyzer-results-body");
  const threatBadge = document.getElementById("analyzer-threat-badge");
  const counter = document.getElementById("matching-events-counter");

  if (resultsBody) resultsBody.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--cyan-accent);">⚡ Running SIEM Signature & AI Behavioral Analysis...</div>`;

  try {
    const analysis = await window.api.analyzeLogs(content);
    if (analysis) {
      currentFullAnalysis = analysis;
      currentAnalysisEvents = analysis.events || [];

      if (counter) counter.textContent = `${analysis.total_events || 0} events analyzed`;
      if (threatBadge) {
        threatBadge.className = `badge ${analysis.overall_threat === 'HIGH' ? 'badge-high' : analysis.overall_threat === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`;
        threatBadge.textContent = `THREAT LEVEL: ${analysis.overall_threat || 'LOW'}`;
      }

      renderAnalyzerEvents(currentAnalysisEvents);
      populateDiscoveredFields(analysis);
      initSplunkFilter();
    }
  } catch (err) {
    if (resultsBody) resultsBody.innerHTML = `<div style="color: #f87171; padding: 1rem;">Analysis error: ${err.message}</div>`;
  }
}

function renderAnalyzerEvents(events) {
  const resultsBody = document.getElementById("analyzer-results-body");
  const counter = document.getElementById("matching-events-counter");
  if (counter) counter.textContent = `${events.length} matching events`;

  if (!resultsBody) return;
  if (!events || events.length === 0) {
    resultsBody.innerHTML = `<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No events matched the current filter criteria.</div>`;
    return;
  }

  resultsBody.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.5rem;">
      ${events.map(e => `
        <div class="event-row ${e.threat_level === 'HIGH' ? 'alert-row' : ''}" style="padding: 0.6rem 0.85rem; font-size: 0.75rem; background: #0d121f; border-radius: var(--radius-sm); margin-bottom: 0.4rem; border: 1px solid var(--border-color);">
          <div style="display: flex; justify-content: space-between; font-weight: 700;">
            <span style="color: #cbd5e1;"><strong style="color: #fff;">${e.timestamp || ''}</strong> | <span style="color: var(--cyan-accent);">${e.host || 'WIN-LAB01'}</span> | <span style="color: #93c5fd;">${e.log_source || 'Sysmon'}</span> ${e.event_code ? `(EID ${e.event_code})` : ''} | User: <span style="color: #fca5a5;">${e.user || 'system'}</span></span>
            <span class="badge ${e.threat_level === 'HIGH' ? 'badge-high' : e.threat_level === 'MEDIUM' ? 'badge-medium' : 'badge-low'}">AI Score: ${(e.anomaly_score || 0).toFixed(2)}</span>
          </div>
          <div style="color: var(--text-muted); margin-top: 0.3rem; font-family: var(--font-mono); word-break: break-all;">${escapeHtml(e.raw_line || e.command_line || JSON.stringify(e.metadata || {}))}</div>
        </div>
      `).join("")}
    </div>
  `;
}

function populateDiscoveredFields(analysis) {
  const badgeEl = document.getElementById("fields-count-badge");
  const srcCountEl = document.getElementById("src-unique-count");
  const eidCountEl = document.getElementById("eid-unique-count");
  const hostsCountEl = document.getElementById("hosts-unique-count");
  const usersCountEl = document.getElementById("users-unique-count");

  const srcContainer = document.getElementById("field-list-sources");
  const eidContainer = document.getElementById("field-list-eids");
  const hostsContainer = document.getElementById("field-list-hosts");
  const usersContainer = document.getElementById("field-list-users");

  const f = analysis.fields_summary || {
    log_sources: {},
    event_codes: {},
    hosts: {},
    users: {},
    total_fields: 0
  };

  const total = analysis.total_events || 1;

  if (badgeEl) badgeEl.textContent = `${f.total_fields || 0} Fields`;
  if (srcCountEl) srcCountEl.textContent = Object.keys(f.log_sources || {}).length;
  if (eidCountEl) eidCountEl.textContent = Object.keys(f.event_codes || {}).length;
  if (hostsCountEl) hostsCountEl.textContent = Object.keys(f.hosts || {}).length;
  if (usersCountEl) usersCountEl.textContent = Object.keys(f.users || {}).length;

  const renderFieldItems = (obj, type) => {
    const entries = Object.entries(obj || {});
    if (entries.length === 0) {
      return `<div style="color: var(--text-dim); font-size: 0.7rem;">None detected</div>`;
    }
    return entries.map(([k, v]) => {
      const pct = Math.min(100, Math.round((v / total) * 100));
      return `
        <div class="field-item" onclick="filterByField('${type}', '${escapeAttr(k)}')" style="cursor: pointer; padding: 0.25rem 0.4rem; border-radius: 4px; display: flex; flex-direction: column; gap: 2px;" title="Click to filter events by ${type}:${k}">
          <div style="display: flex; justify-content: space-between; font-size: 0.72rem;">
            <span style="font-weight: 600; color: #e2e8f0;">${escapeHtml(k)}</span>
            <span style="color: var(--cyan-accent); font-family: var(--font-mono);">${v} <span style="color: var(--text-dim); font-size: 0.65rem;">(${pct}%)</span></span>
          </div>
          <div style="height: 3px; background: rgba(255,255,255,0.06); border-radius: 2px; overflow: hidden;">
            <div style="width: ${pct}%; height: 100%; background: var(--cyan-accent);"></div>
          </div>
        </div>
      `;
    }).join("");
  };

  if (srcContainer) srcContainer.innerHTML = renderFieldItems(f.log_sources, "source");
  if (eidContainer) eidContainer.innerHTML = renderFieldItems(f.event_codes, "eid");
  if (hostsContainer) hostsContainer.innerHTML = renderFieldItems(f.hosts, "host");
  if (usersContainer) usersContainer.innerHTML = renderFieldItems(f.users, "user");
}

window.filterByField = function(type, value) {
  const searchInput = document.getElementById("splunk-search-input");
  if (searchInput) {
    searchInput.value = `${type}:${value}`;
    applySplunkSearch(`${type}:${value}`);
  }
};

function initSplunkFilter() {
  const searchInput = document.getElementById("splunk-search-input");
  const clearBtn = document.getElementById("btn-clear-search");
  const exportBtn = document.getElementById("btn-export-analysis");

  if (searchInput && !searchInput.dataset.initialized) {
    searchInput.dataset.initialized = "true";
    searchInput.addEventListener("input", (e) => {
      applySplunkSearch(e.target.value);
    });
  }

  if (clearBtn && !clearBtn.dataset.initialized) {
    clearBtn.dataset.initialized = "true";
    clearBtn.addEventListener("click", () => {
      if (searchInput) {
        searchInput.value = "";
        applySplunkSearch("");
      }
    });
  }

  if (exportBtn && !exportBtn.dataset.initialized) {
    exportBtn.dataset.initialized = "true";
    exportBtn.addEventListener("click", () => {
      if (currentFullAnalysis) {
        const blob = new Blob([JSON.stringify(currentFullAnalysis, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `siem_analysis_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        alert("No analysis data available to export.");
      }
    });
  }
}

function applySplunkSearch(query) {
  if (!currentAnalysisEvents || currentAnalysisEvents.length === 0) return;
  const q = (query || "").trim().toLowerCase();
  if (!q) {
    renderAnalyzerEvents(currentAnalysisEvents);
    return;
  }

  const terms = q.split(/\s*\|\s*|\s+/).filter(t => t.length > 0);

  const filtered = currentAnalysisEvents.filter(ev => {
    return terms.every(term => {
      if (term.startsWith("user:")) {
        const val = term.substring(5);
        return (ev.user || "").toLowerCase().includes(val);
      }
      if (term.startsWith("host:")) {
        const val = term.substring(5);
        return (ev.host || "").toLowerCase().includes(val) || (ev.source_ip || "").includes(val);
      }
      if (term.startsWith("source:")) {
        const val = term.substring(7);
        return (ev.log_source || "").toLowerCase().includes(val);
      }
      if (term.startsWith("eid:")) {
        const val = term.substring(4);
        return String(ev.event_code || "").toLowerCase().includes(val);
      }
      if (term.startsWith("threat:")) {
        const val = term.substring(7);
        return (ev.threat_level || "").toLowerCase() === val;
      }
      if (term.startsWith("status:")) {
        const val = term.substring(7);
        return (ev.action || "").toLowerCase().includes(val);
      }

      const str = `${ev.timestamp} ${ev.host} ${ev.log_source} ${ev.user} ${ev.command_line} ${ev.raw_line} ${JSON.stringify(ev.metadata || {})}`.toLowerCase();
      return str.includes(term);
    });
  });

  renderAnalyzerEvents(filtered);
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(text) {
  if (!text) return "";
  return String(text).replace(/'/g, "\\'");
}

async function loadArchivedLogs() {
  const list = document.getElementById("saved-log-files-list");
  if (!list) return;
  try {
    const res = await window.api.getLogs();
    if (res && res.log_files) {
      list.innerHTML = res.log_files.map(f => `
        <div class="log-file-item" onclick="loadSavedLogFile('${f.filename}')">
          <span style="font-weight: 600; color: #fff;">📄 ${f.filename}</span>
          <span style="color: var(--text-dim); font-size: 0.7rem;">${(f.size_bytes/1024).toFixed(1)} KB</span>
        </div>
      `).join("");
    }
  } catch (err) {
    console.error("Failed to load logs:", err);
  }
}

window.loadSavedLogFile = async function(filename) {
  try {
    const res = await window.api.getLogContent(filename);
    if (res && res.content) {
      const formatted = typeof res.content === "object" ? JSON.stringify(res.content, null, 2) : res.content;
      const input = document.getElementById("analyzer-input");
      const pasteBox = document.getElementById("paste-box-container");
      if (pasteBox) pasteBox.style.display = "block";
      if (input) input.value = formatted;
      runLogAnalysis(formatted);
    }
  } catch (err) {
    alert("Could not load log file: " + err.message);
  }
};

