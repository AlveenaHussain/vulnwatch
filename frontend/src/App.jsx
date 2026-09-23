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

  const [activePage, setActivePage] = useState("Dashboard");

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
        ] = await Promise.all(
          responses.map((response) => response.json())
        );

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

  const handleNavigation = (page) => {
    setActivePage(page);
  };

  const renderPlaceholderPage = () => {
    const pageConfig = {
      Assets: {
        icon: "◉",
        section: "MONITORING",
        title: "Assets",
        description:
          "View and manage infrastructure assets discovered by VulnWatch.",
      },
      Services: {
        icon: "⌘",
        section: "MONITORING",
        title: "Services",
        description:
          "Review network services discovered across monitored assets.",
      },
      Vulnerabilities: {
        icon: "△",
        section: "SECURITY",
        title: "Vulnerabilities",
        description:
          "Review vulnerabilities identified and mapped to discovered services.",
      },
      Findings: {
        icon: "!",
        section: "SECURITY",
        title: "Findings",
        description:
          "Track security findings, risk scores, severity and remediation status.",
      },
      Scans: {
        icon: "◫",
        section: "SECURITY",
        title: "Scans",
        description:
          "View scan activity and import security scan results into VulnWatch.",
      },
    };

    const page = pageConfig[activePage];

    if (!page) {
      return null;
    }

    return (
      <main className="dashboard-content">
        <section className="hero-section">
          <div>
            <div className="eyebrow">{page.section}</div>

            <h1>{page.title}</h1>

            <p>{page.description}</p>
          </div>

          <div className="hero-decoration">
            <div className="scan-ring ring-one"></div>
            <div className="scan-ring ring-two"></div>
            <div className="scan-core">{page.icon}</div>
          </div>
        </section>

        <section className="dashboard-card">
          <div className="card-heading">
            <div>
              <span className="card-label">VULNWATCH MODULE</span>
              <h2>{page.title} Management</h2>
            </div>

            <span className="card-menu">•••</span>
          </div>

          <div
            style={{
              padding: "30px 0",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: "42px",
                marginBottom: "16px",
                opacity: 0.8,
              }}
            >
              {page.icon}
            </div>

            <h3
              style={{
                margin: "0 0 10px",
                fontSize: "20px",
              }}
            >
              {page.title} module
            </h3>

            <p
              style={{
                margin: 0,
                opacity: 0.65,
              }}
            >
              This module is ready for the next implementation phase.
            </p>
          </div>
        </section>
      </main>
    );
  };

  const renderDashboard = () => {
    return (
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
                          ? `${finding.port}/${
                              finding.protocol || ""
                            }`
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
    );
  };

  return (
    <div className="app-shell">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">V</div>

          <div>
            <div className="brand-name">VulnWatch</div>
            <div className="brand-version">
              Security Platform
            </div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">MONITORING</div>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Dashboard" ? "active" : ""
            }`}
            onClick={() => handleNavigation("Dashboard")}
          >
            <span className="nav-icon">▦</span>
            Dashboard
          </button>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Assets" ? "active" : ""
            }`}
            onClick={() => handleNavigation("Assets")}
          >
            <span className="nav-icon">◉</span>
            Assets
          </button>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Services" ? "active" : ""
            }`}
            onClick={() => handleNavigation("Services")}
          >
            <span className="nav-icon">⌘</span>
            Services
          </button>

          <div className="nav-section">SECURITY</div>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Vulnerabilities"
                ? "active"
                : ""
            }`}
            onClick={() => handleNavigation("Vulnerabilities")}
          >
            <span className="nav-icon">△</span>
            Vulnerabilities
          </button>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Findings" ? "active" : ""
            }`}
            onClick={() => handleNavigation("Findings")}
          >
            <span className="nav-icon">!</span>
            Findings
          </button>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Scans" ? "active" : ""
            }`}
            onClick={() => handleNavigation("Scans")}
          >
            <span className="nav-icon">◫</span>
            Scans
          </button>
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
            {activePage}
          </div>

          <div className="topbar-right">
            <div className="last-scan">
              Last scan data available
            </div>

            <div className="backend-status">
              <span className="online-dot"></span>
              Backend Connected
            </div>

            <div className="user-avatar">V</div>
          </div>
        </header>

        {activePage === "Dashboard"
          ? renderDashboard()
          : renderPlaceholderPage()}
      </div>
    </div>
  );
}

export default App;