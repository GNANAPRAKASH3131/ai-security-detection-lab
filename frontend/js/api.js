/**
 * AI Security Detection Lab - API Client SDK
 * Handles all network requests to the Backend REST API.
 */

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
      if (!response.ok) {
        let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
        try {
          const errData = await response.json();
          if (errData.message) errorMsg = errData.message;
        } catch (_) {}
        throw new Error(errorMsg);
      }
      return await response.json();
    } catch (err) {
      console.error(`[API Error] ${options.method || "GET"} ${url} failed:`, err);
      throw err;
    }
  }

  async getHealth() {
    return this._request("/api/health");
  }

  async getExperiments() {
    return this._request("/api/experiments");
  }

  async runScenario(scenarioId) {
    return this._request("/api/run_scenario", {
      method: "POST",
      body: JSON.stringify({ scenario_id: String(scenarioId) })
    });
  }

  async runAllScenarios() {
    return this._request("/api/run_all", {
      method: "POST"
    });
  }

  async getMatrix() {
    return this._request("/api/matrix");
  }

  async getFailureAnalysis() {
    return this._request("/api/failure_analysis");
  }

  async getBaselines() {
    return this._request("/api/baselines");
  }

  async establishBaseline() {
    return this._request("/api/establish_baseline", {
      method: "POST"
    });
  }

  async getTelemetryHealth() {
    return this._request("/api/telemetry_health");
  }

  async updateTelemetryHealth(component, state) {
    return this._request("/api/telemetry_health", {
      method: "POST",
      body: JSON.stringify({ component, state })
    });
  }

  async getResearchFindings() {
    return this._request("/api/research_findings");
  }

  async getDbStatus() {
    return this._request("/api/db/status");
  }

  async syncDb() {
    return this._request("/api/db/sync", {
      method: "POST"
    });
  }

  async getLogs() {
    return this._request("/api/logs");
  }

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
    return this._request("/api/generate_report", {
      method: "POST"
    });
  }

  async resetLab() {
    return this._request("/api/reset", {
      method: "POST"
    });
  }
}

// Export singleton instance and class
window.LabApiClient = LabApiClient;
window.api = new LabApiClient();
