import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://localhost:8000";

function App() {
  const [summary, setSummary] = useState(null);
  const [riskOverview, setRiskOverview] = useState(null);
  const [recentFindings, setRecentFindings] = useState([]);
  const [severityDistribution, setSeverityDistribution] = useState([]);
  const [statusDistribution, setStatusDistribution] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);

        const responses = await Promise.all([
          fetch(`${API_BASE_URL}/api/v1/dashboard/summary`),
          fetch(`${API_BASE_URL}/api/v1/dashboard/risk-overview`),
          fetch(`${API_BASE_URL}/api/v1/dashboard/recent-findings`),
          fetch(`${API_BASE_URL}/api/v1/dashboard/severity-distribution`),
          fetch(`${API_BASE_URL}/api/v1/dashboard/status-distribution`),
        ]);

        if (responses.some((response) => !response.ok)) {
          throw new Error("Dashboard API request failed");
        }

        const [
          summaryData,
          riskData,
          findingsData,
          severityData,
          statusData,
        ] = await Promise.all(responses.map((response) => response.json()));

        setSummary(summaryData);
        setRiskOverview(riskData);
        setRecentFindings(findingsData.findings || []);
        setSeverityDistribution(severityData.distribution || []);
        setStatusDistribution(statusData.distribution || []);
        setError("");
      } catch (err) {
        console.error(err);
        setError("Unable to connect to VulnWatch backend.");
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, []);

  const severityClass = (severity) =>
    severity?.toLowerCase() || "unknown";

  const statusClass = (status) =>
    status?.toLowerCase().replace("_", "-") || "unknown";

  return (
    <div className="app-shell">

      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">V</div>

          <div>
            <div className="brand-name">VulnWatch</div>
            <div className="brand-version">Security Platform</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">MONITORING</div>

          <div className="nav-item active">
            <span className="nav-icon">▦</span>
            Dashboard
          </div>

          <div className="nav-item">
            <span className="nav-icon">◉</span>
            Assets
          </div>

          <div className="nav-item">
            <span className="nav-icon">⌘</span>
            Services
          </div>

          <div className="nav-section">SECURITY</div>

          <div className="nav-item">
            <span className="nav-icon">△</span>
            Vulnerabilities
          </div>

          <div className="nav-item">
            <span className="nav-icon">!</span>
            Findings
          </div>

          <div className="nav-item">
            <span className="nav-icon">◫</span>
            Scans
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="system-status">
            <span className="online-dot"></span>
            System Operational
          </div>

          <div className="sidebar-footer-text">
            VulnWatch v0.1.0
          </div>
        </div>
      </aside>

      {/* MAIN */}
      <div className="main-area">

        {/* TOPBAR */}
        <header className="topbar">
          <div className="breadcrumb">
            <span>Security</span>
            <b>/</b>
            Dashboard
          </div>

          <div className="topbar-right">
            <div className="last-scan">
              Last scan data available
            </div>

            <div className="backend-status">
              <span className="online-dot"></span>
              Backend Connected
            </div>

            <div className="user-avatar">
              V
            </div>
          </div>
        </header>

        <main className="dashboard-content">

          {/* HERO */}
          <section className="hero-section">
            <div>
              <div className="eyebrow">SECURITY OVERVIEW</div>

              <h1>Security Dashboard</h1>

              <p>
                Monitor assets, vulnerabilities, findings and security
                risk from one centralized view.
              </p>
            </div>

            <div className="hero-decoration">
              <div className="scan-ring ring-one"></div>
              <div className="scan-ring ring-two"></div>
              <div className="scan-core">V</div>
            </div>
          </section>

          {/* ERROR */}
          {error && (
            <div className="error-banner">
              <strong>Connection Error</strong>
              <span>{error}</span>
            </div>
          )}

          {/* STATS */}
          <section className="stats-grid">

            <div className="stat-card">
              <div className="stat-top">
                <span className="stat-icon blue">◉</span>
                <span className="stat-category">INFRASTRUCTURE</span>
              </div>

              <div className="stat-value">
                {loading ? "—" : summary?.assets?.total ?? 0}
              </div>

              <div className="stat-name">Total Assets</div>

              <div className="stat-line">
                Discovered infrastructure assets
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span className="stat-icon purple">⌘</span>
                <span className="stat-category">NETWORK</span>
              </div>

              <div className="stat-value">
                {loading ? "—" : summary?.services?.total ?? 0}
              </div>

              <div className="stat-name">Services</div>

              <div className="stat-line">
                Network services discovered
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-top">
                <span className="stat-icon orange">△</span>
                <span className="stat-category">THREATS</span>
              </div>

              <div className="stat-value">
                {loading ? "—" : summary?.vulnerabilities?.total ?? 0}
              </div>

              <div className="stat-name">Vulnerabilities</div>

              <div className="stat-line">
                Known vulnerabilities mapped
              </div>
            </div>

            <div className="stat-card critical-card">
              <div className="stat-top">
                <span className="stat-icon red">!</span>
                <span className="stat-category">FINDINGS</span>
              </div>

              <div className="stat-value">
                {loading ? "—" : summary?.findings?.total ?? 0}
              </div>

              <div className="stat-name">Security Findings</div>

              <div className="stat-line">
                Findings tracked by VulnWatch
              </div>
            </div>

          </section>

          {/* ANALYTICS */}
          {!loading && !error && (
            <section className="analytics-grid">

              {/* RISK */}
              <div className="dashboard-card risk-card">
                <div className="card-heading">
                  <div>
                    <span className="card-label">RISK ANALYSIS</span>
                    <h2>Risk Overview</h2>
                  </div>

                  <span className="card-menu">•••</span>
                </div>

                <div className="risk-main">
                  <div className="risk-circle">
                    <div className="risk-circle-inner">
                      <strong>
                        {riskOverview?.risk?.open ?? 0}
                      </strong>
                      <span>OPEN RISK</span>
                    </div>
                  </div>

                  <div className="risk-metrics">

                    <div className="metric">
                      <span>Open Findings</span>
                      <strong>
                        {riskOverview?.findings?.open ?? 0}
                      </strong>
                    </div>

                    <div className="metric">
                      <span>Total Findings</span>
                      <strong>
                        {riskOverview?.findings?.total ?? 0}
                      </strong>
                    </div>

                    <div className="metric">
                      <span>Average Risk</span>
                      <strong>
                        {riskOverview?.risk?.average_open ?? 0}
                      </strong>
                    </div>

                    <div className="metric">
                      <span>Highest Risk</span>
                      <strong>
                        {riskOverview?.risk?.highest_open ?? 0}
                      </strong>
                    </div>

                  </div>
                </div>
              </div>

              {/* SEVERITY */}
              <div className="dashboard-card">
                <div className="card-heading">
                  <div>
                    <span className="card-label">THREAT LEVEL</span>
                    <h2>Severity Distribution</h2>
                  </div>
                </div>

                <div className="distribution">

                  {severityDistribution.map((item) => (
                    <div
                      className="distribution-item"
                      key={item.severity}
                    >
                      <div className="distribution-title">
                        <span
                          className={`severity-dot ${severityClass(
                            item.severity
                          )}`}
                        ></span>

                        <span>{item.severity}</span>

                        <strong>{item.count}</strong>
                      </div>

                      <div className="progress-track">
                        <div
                          className={`progress-fill ${severityClass(
                            item.severity
                          )}`}
                          style={{
                            width: `${
                              (item.count /
                                Math.max(
                                  summary?.findings?.total || 1,
                                  1
                                )) *
                              100
                            }%`,
                          }}
                        ></div>
                      </div>
                    </div>
                  ))}

                </div>
              </div>

              {/* STATUS */}
              <div className="dashboard-card">
                <div className="card-heading">
                  <div>
                    <span className="card-label">WORKFLOW</span>
                    <h2>Finding Status</h2>
                  </div>
                </div>

                <div className="status-list">

                  {statusDistribution.map((item) => (
                    <div
                      className="status-row"
                      key={item.status}
                    >
                      <div>
                        <span
                          className={`status-dot ${statusClass(
                            item.status
                          )}`}
                        ></span>

                        <span>
                          {item.status.replace("_", " ")}
                        </span>
                      </div>

                      <strong>{item.count}</strong>
                    </div>
                  ))}

                </div>
              </div>

            </section>
          )}

          {/* FINDINGS */}
          {!loading && !error && (
            <section className="dashboard-card findings-card">

              <div className="card-heading">
                <div>
                  <span className="card-label">SECURITY EVENTS</span>
                  <h2>Recent Findings</h2>
                </div>

                <div className="finding-total">
                  {recentFindings.length} findings
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Finding</th>
                      <th>CVE</th>
                      <th>Target</th>
                      <th>Port</th>
                      <th>Severity</th>
                      <th>Risk</th>
                      <th>Status</th>
                    </tr>
                  </thead>

                  <tbody>
                    {recentFindings.map((finding) => (
                      <tr key={finding.id}>

                        <td>
                          <div className="finding-name">
                            {finding.title}
                          </div>

                          <div className="finding-sub">
                            {finding.hostname || "metasploitable"}
                          </div>
                        </td>

                        <td>
                          <span className="cve-code">
                            {finding.cve_id || "N/A"}
                          </span>
                        </td>

                        <td>
                          {finding.target_ip || "N/A"}
                        </td>

                        <td>
                          {finding.port
                            ? `${finding.port}/${finding.protocol || ""}`
                            : "N/A"}
                        </td>

                        <td>
                          <span
                            className={`severity-badge ${severityClass(
                              finding.severity
                            )}`}
                          >
                            {finding.severity}
                          </span>
                        </td>

                        <td>
                          <strong className="risk-number-small">
                            {finding.risk_score}
                          </strong>
                        </td>

                        <td>
                          <span
                            className={`status-badge ${statusClass(
                              finding.status
                            )}`}
                          >
                            {finding.status?.replace("_", " ")}
                          </span>
                        </td>

                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

            </section>
          )}

        </main>
      </div>
    </div>
  );
}

export default App;