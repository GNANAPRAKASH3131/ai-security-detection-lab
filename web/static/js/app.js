/**
 * Cyber Research Lab - Interactive Frontend Engine
 */

let currentExperiment = null;
let allExperiments = [];

document.addEventListener("DOMContentLoaded", () => {
  initEventListeners();
  loadInitialData();
});

function initEventListeners() {
  document.getElementById("btn-run-all").addEventListener("click", runAllExperiments);
  document.getElementById("btn-report").addEventListener("click", generateReport);
  document.getElementById("btn-refresh").addEventListener("click", loadInitialData);

  document.querySelectorAll(".scenario-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const scenarioId = btn.getAttribute("data-id");
      runSingleScenario(scenarioId);
    });
  });
}

async function loadInitialData() {
  try {
    const res = await fetch("/api/experiments");
    allExperiments = await res.json();
    if (allExperiments.length > 0) {
      displayExperiment(allExperiments[allExperiments.length - 1]);
    } else {
      // Auto-trigger scenario 1 if empty
      runSingleScenario("1");
    }
  } catch (err) {
    console.error("Error loading experiments:", err);
  }
}

async function runSingleScenario(scenarioId) {
  highlightScenarioButton(scenarioId);
  setLoadingState(true);

  try {
    const res = await fetch("/api/run_scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario_id: scenarioId })
    });
    const data = await res.json();
    if (data.status === "success") {
      currentExperiment = data.experiment;
      displayExperiment(currentExperiment);
    }
  } catch (err) {
    alert("Error executing scenario: " + err.message);
  } finally {
    setLoadingState(false);
  }
}

async function runAllExperiments() {
  setLoadingState(true);
  try {
    const res = await fetch("/api/run_all", { method: "POST" });
    const data = await res.json();
    if (data.status === "success" && data.experiments.length > 0) {
      allExperiments = data.experiments;
      displayExperiment(allExperiments[0]);
    }
  } catch (err) {
    alert("Error executing all scenarios: " + err.message);
  } finally {
    setLoadingState(false);
  }
}

async function generateReport() {
  try {
    const res = await fetch("/api/generate_report", { method: "POST" });
    const data = await res.json();
    if (data.status === "success") {
      alert("Research Report Generated Successfully!\nPath: " + data.report_path);
    }
  } catch (err) {
    alert("Error generating report: " + err.message);
  }
}

function displayExperiment(exp) {
  if (!exp) return;
  currentExperiment = exp;

  // Title & ID
  document.getElementById("exp-title").textContent = exp.scenario || "Scenario Execution";
  document.getElementById("exp-id").textContent = exp.experiment_id || "EXP-000";
  document.getElementById("exp-time").textContent = `${exp.start_time} -> ${exp.end_time}`;

  // Metrics
  document.getElementById("stat-gen").textContent = exp.events_generated || 0;
  document.getElementById("stat-rec").textContent = exp.events_received || 0;
  
  const score = (exp.metrics && exp.metrics.max_anomaly_score) ? exp.metrics.max_anomaly_score : 0.0;
  document.getElementById("stat-score").textContent = score.toFixed(2);
  document.getElementById("stat-score-bar").style.width = `${Math.min(100, score * 100)}%`;

  const cov = (exp.metrics && exp.metrics.telemetry_coverage_pct) ? exp.metrics.telemetry_coverage_pct : 100;
  document.getElementById("stat-coverage").textContent = `${cov}%`;

  // Attack Chain Nodes
  renderAttackChain(exp.attack_chain || []);

  // Alerts Table
  renderAlerts(exp.alerts || []);

  // Response Actions
  renderResponses(exp.response_actions || []);

  // Analyst Notes
  document.getElementById("analyst-conclusion").textContent = exp.analyst_conclusion || "No conclusion recorded.";
  document.getElementById("observations-log").textContent = (exp.observations || []).join("\n");
}

function renderAttackChain(chain) {
  const container = document.getElementById("attack-chain-container");
  container.innerHTML = "";

  const defaultChain = [
    { name: "Initial Access", status: "TELEMETRY_RECEIVED", icon: "🔑" },
    { name: "Discovery", status: "TELEMETRY_RECEIVED", icon: "🔍" },
    { name: "Authentication", status: "DETECTED_AI", icon: "🛡️" },
    { name: "Lateral Move", status: "NO_TELEMETRY", icon: "⛓️" },
    { name: "Privilege Escalation", status: "NO_TELEMETRY", icon: "⚡" },
    { name: "Sensitive Access", status: "NO_TELEMETRY", icon: "📁" },
    { name: "Detection Engine", status: "DETECTED_AI", icon: "🤖" },
    { name: "SOAR Response", status: "DETECTED_AI", icon: "🚨" }
  ];

  const nodes = chain.length > 0 ? chain : defaultChain;

  nodes.forEach(node => {
    let stateClass = "state-red";
    if (node.status === "TELEMETRY_RECEIVED") stateClass = "state-green";
    else if (node.status === "PARTIAL_VISIBILITY") stateClass = "state-yellow";
    else if (node.status === "DETECTED_AI") stateClass = "state-blue";

    const div = document.createElement("div");
    div.className = `node ${stateClass}`;
    div.innerHTML = `
      <div class="node-icon">${getNodeIcon(node.name)}</div>
      <div class="node-label">${node.name}</div>
    `;
    container.appendChild(div);
  });
}

function getNodeIcon(name) {
  if (name.includes("Access")) return "🔑";
  if (name.includes("Discovery") || name.includes("Recon")) return "🔍";
  if (name.includes("Auth")) return "🔐";
  if (name.includes("Lateral")) return "⛓️";
  if (name.includes("Privilege")) return "⚡";
  if (name.includes("Sensitive")) return "📂";
  if (name.includes("Detection")) return "🤖";
  if (name.includes("Response")) return "🚨";
  return "●";
}

function renderAlerts(alerts) {
  const tbody = document.getElementById("alerts-table-body");
  tbody.innerHTML = "";

  if (alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-dim);">No alerts triggered (Benign activity or Blindspot)</td></tr>`;
    return;
  }

  alerts.forEach(a => {
    const tr = document.createElement("tr");
    const sevBadge = a.severity === "HIGH" ? "badge-high" : (a.severity === "MEDIUM" ? "badge-medium" : "badge-low");
    tr.innerHTML = `
      <td><span class="badge ${sevBadge}">${a.severity}</span></td>
      <td><strong>${a.rule_name}</strong></td>
      <td>${a.host} / ${a.user}</td>
      <td><code>${a.anomaly_score ? a.anomaly_score.toFixed(2) : '0.00'}</code></td>
      <td style="color: var(--text-muted); font-size: 0.72rem;">${a.description}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderResponses(responses) {
  const container = document.getElementById("response-container");
  container.innerHTML = "";

  if (responses.length === 0) {
    container.innerHTML = `<p style="color: var(--text-dim); font-size: 0.8rem;">No active containment responses triggered.</p>`;
    return;
  }

  responses.forEach(r => {
    const div = document.createElement("div");
    div.style = "background: rgba(168, 85, 247, 0.1); border-left: 3px solid var(--purple-soar); padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; border-radius: 0 4px 4px 0;";
    div.innerHTML = `
      <div style="font-weight: 700; font-size: 0.78rem; color: #c084fc;">${r.action_type} [${r.status}]</div>
      <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;">${r.details}</div>
    `;
    container.appendChild(div);
  });
}

function highlightScenarioButton(id) {
  document.querySelectorAll(".scenario-btn").forEach(b => {
    if (b.getAttribute("data-id") === id) b.classList.add("active");
    else b.classList.remove("active");
  });
}

function setLoadingState(loading) {
  document.body.style.cursor = loading ? "wait" : "default";
}
