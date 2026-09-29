import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://localhost:8000";

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [refreshKey, setRefreshKey] = useState(0);
  const [refreshing, setRefreshing] = useState(false);

  const [summary, setSummary] = useState(null);
  const [riskOverview, setRiskOverview] = useState(null);
  const [recentFindings, setRecentFindings] = useState([]);
  const [severityDistribution, setSeverityDistribution] = useState([]);
  const [statusDistribution, setStatusDistribution] = useState([]);

  const [assets, setAssets] = useState([]);
  const [services, setServices] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);

  const [alerts, setAlerts] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);

  const [investigation, setInvestigation] = useState(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const severityClass = (severity) =>
    severity?.toLowerCase() || "unknown";

  const statusClass = (status) =>
    status?.toLowerCase().replaceAll("_", "-") || "unknown";

  const formatDate = (value) => {
    if (!value) {
      return "N/A";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString();
  };

  const normalizeList = (data, key) => {
    if (Array.isArray(data)) {
      return data;
    }

    if (Array.isArray(data?.[key])) {
      return data[key];
    }

    if (Array.isArray(data?.items)) {
      return data.items;
    }

    return [];
  };

  useEffect(() => {
    async function loadAllData() {
      try {
        setLoading(true);

        const endpoints = {
          summary: "/api/v1/dashboard/summary",
          risk: "/api/v1/dashboard/risk-overview",
          recent: "/api/v1/dashboard/recent-findings",
          severity: "/api/v1/dashboard/severity-distribution",
          status: "/api/v1/dashboard/status-distribution",
          assets: "/api/v1/assets",
          services: "/api/v1/services",
          vulnerabilities: "/api/v1/vulnerabilities",
          findings: "/api/v1/findings",
          scans: "/api/v1/scans",
          alerts: "/api/v1/alerts",
          correlations: "/api/v1/correlations",
          events: "/api/v1/security-events",
        };

        const entries = await Promise.all(
          Object.entries(endpoints).map(async ([name, endpoint]) => {
            const response = await fetch(`${API_BASE_URL}${endpoint}`);

            if (!response.ok) {
              throw new Error(`${name} API request failed`);
            }

            return [name, await response.json()];
          })
        );

        const data = Object.fromEntries(entries);

        setSummary(data.summary);
        setRiskOverview(data.risk);
        setRecentFindings(data.recent?.findings || []);
        setSeverityDistribution(data.severity?.distribution || []);
        setStatusDistribution(data.status?.distribution || []);

        setAssets(normalizeList(data.assets, "assets"));
        setServices(normalizeList(data.services, "services"));
        setVulnerabilities(
          normalizeList(data.vulnerabilities, "vulnerabilities")
        );
        setFindings(normalizeList(data.findings, "findings"));
        setScans(normalizeList(data.scans, "scans"));
        setAlerts(normalizeList(data.alerts, "alerts"));
        setCorrelations(
          normalizeList(data.correlations, "correlations")
        );
        setSecurityEvents(
          normalizeList(data.events, "events")
        );

        setError("");
      } catch (err) {
        console.error(err);
        setError("Unable to connect to VulnWatch backend.");
      } finally {
        setLoading(false);
      }
    }

    loadAllData();
  }, [refreshKey]);

  const handleRefresh = () => {
    setRefreshing(true);
    setRefreshKey((value) => value + 1);

    window.setTimeout(() => {
      setRefreshing(false);
    }, 700);
  };

  const loadInvestigation = async (correlationId) => {
    try {
      setInvestigationLoading(true);
      setInvestigationError("");
      setInvestigation(null);

      const response = await fetch(
        `${API_BASE_URL}/api/v1/investigations/${correlationId}`
      );

      if (!response.ok) {
        throw new Error("Investigation API request failed");
      }

      const data = await response.json();

      setInvestigation(data);
      setActivePage("investigation-detail");
    } catch (err) {
      console.error(err);
      setInvestigationError(
        "Unable to load investigation details."
      );
    } finally {
      setInvestigationLoading(false);
    }
  };

  const handleNavigation = (page) => {
    setActivePage(page);

    if (page !== "investigation-detail") {
      setInvestigation(null);
      setInvestigationError("");
    }
  };

  const renderDashboard = () => (
    <>
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

      {!loading && !error && (
        <section className="analytics-grid">
          <div className="dashboard-card risk-card">
            <div className="card-heading">
              <div>
                <span className="card-label">RISK ANALYSIS</span>
                <h2>Risk Overview</h2>
              </div>
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
                      {item.status?.replaceAll("_", " ")}
                    </span>
                  </div>

                  <strong>{item.count}</strong>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

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
                        {finding.hostname || "N/A"}
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
                        {finding.status?.replaceAll("_", " ")}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );

  const renderAssets = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="INFRASTRUCTURE"
        title="Assets"
        count={assets.length}
      />

      <DataTable
        columns={[
          "IP Address",
          "Hostname",
          "OS",
          "MAC Address",
          "First Seen",
          "Last Seen",
        ]}
        rows={assets.map((asset) => [
          asset.ip_address,
          asset.hostname || "N/A",
          asset.os_name || "N/A",
          asset.mac_address || "N/A",
          formatDate(asset.first_seen),
          formatDate(asset.last_seen),
        ])}
      />
    </section>
  );

  const renderServices = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="NETWORK"
        title="Services"
        count={services.length}
      />

      <DataTable
        columns={[
          "Target",
          "Port",
          "Protocol",
          "Service",
          "Product",
          "Version",
          "State",
        ]}
        rows={services.map((service) => [
          service.target_ip,
          service.port,
          service.protocol,
          service.service_name || "N/A",
          service.product || "N/A",
          service.version || "N/A",
          service.state || "N/A",
        ])}
      />
    </section>
  );

  const renderVulnerabilities = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="VULNERABILITY MANAGEMENT"
        title="Vulnerabilities"
        count={vulnerabilities.length}
      />

      <DataTable
        columns={[
          "CVE",
          "Title",
          "Severity",
          "CVSS",
          "CWE",
        ]}
        rows={vulnerabilities.map((item) => [
          item.cve_id || "N/A",
          item.title || "N/A",
          item.severity || "N/A",
          item.cvss_score ?? "N/A",
          item.cwe_id || "N/A",
        ])}
      />
    </section>
  );

  const renderFindings = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="RISK MANAGEMENT"
        title="Findings"
        count={findings.length}
      />

      <DataTable
        columns={[
          "Finding",
          "CVE",
          "Severity",
          "Risk",
          "Status",
          "Last Seen",
        ]}
        rows={findings.map((item) => [
          item.title || "N/A",
          item.cve_id || "N/A",
          item.severity || "N/A",
          item.risk_score ?? "N/A",
          item.status || "N/A",
          formatDate(item.last_seen),
        ])}
      />
    </section>
  );

  const renderScans = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="DISCOVERY"
        title="Scans"
        count={scans.length}
      />

      <DataTable
        columns={[
          "Asset",
          "Scanner",
          "Scan Type",
          "Started",
          "Completed",
          "Status",
        ]}
        rows={scans.map((scan) => [
          scan.asset_id,
          scan.scanner_ip || "N/A",
          scan.scan_type || "N/A",
          formatDate(scan.started_at),
          formatDate(scan.completed_at),
          scan.status || "N/A",
        ])}
      />
    </section>
  );

  const renderAlerts = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="SOC MONITORING"
        title="Security Alerts"
        count={alerts.length}
      />

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Alert</th>
              <th>Type</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Severity</th>
              <th>Events</th>
              <th>Status</th>
            </tr>
          </thead>

          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>
                  <div className="finding-name">
                    {alert.title || "Security Alert"}
                  </div>
                  <div className="finding-sub">
                    Alert #{alert.id}
                  </div>
                </td>

                <td>{alert.alert_type}</td>
                <td>{alert.source_ip || "N/A"}</td>
                <td>{alert.destination_ip || "N/A"}</td>

                <td>
                  <span
                    className={`severity-badge ${severityClass(
                      alert.severity
                    )}`}
                  >
                    {alert.severity}
                  </span>
                </td>

                <td>{alert.event_count ?? 0}</td>

                <td>
                  <span
                    className={`status-badge ${statusClass(
                      alert.status
                    )}`}
                  >
                    {alert.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );

  const renderCorrelations = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="CORRELATION ENGINE"
        title="Correlations"
        count={correlations.length}
      />

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Correlation</th>
              <th>Asset</th>
              <th>Alert</th>
              <th>CVE</th>
              <th>Priority</th>
              <th>Finding</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {correlations.map((correlation) => (
              <tr key={correlation.id}>
                <td>
                  <div className="finding-name">
                    {correlation.title}
                  </div>

                  <div className="finding-sub">
                    Correlation #{correlation.id}
                  </div>
                </td>

                <td>
                  {correlation.target_ip || "N/A"}
                </td>

                <td>
                  {correlation.alert_type || "N/A"}
                </td>

                <td>
                  <span className="cve-code">
                    {correlation.cve_id || "N/A"}
                  </span>
                </td>

                <td>
                  <span
                    className={`severity-badge ${severityClass(
                      correlation.priority
                    )}`}
                  >
                    {correlation.priority}
                  </span>
                </td>

                <td>
                  #{correlation.finding_id ?? "N/A"}
                </td>

                <td>
                  <button
                    className="action-button"
                    onClick={() =>
                      loadInvestigation(correlation.id)
                    }
                  >
                    Investigate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );

  const renderInvestigations = () => (
    <section className="dashboard-card page-card">
      <PageHeader
        label="SOC INVESTIGATION"
        title="Investigations"
        count={correlations.length}
      />

      <div className="investigation-list">
        {correlations.map((correlation) => (
          <div
            className="investigation-card"
            key={correlation.id}
          >
            <div className="investigation-card-main">
              <div>
                <span className="card-label">
                  CORRELATION #{correlation.id}
                </span>

                <h3>{correlation.title}</h3>

                <p>
                  {correlation.target_ip || "Unknown asset"}{" "}
                  ·{" "}
                  {correlation.alert_type || "Security alert"}{" "}
                  ·{" "}
                  {correlation.cve_id || "No CVE"}
                </p>
              </div>

              <span
                className={`severity-badge ${severityClass(
                  correlation.priority
                )}`}
              >
                {correlation.priority}
              </span>
            </div>

            <button
              className="action-button"
              onClick={() =>
                loadInvestigation(correlation.id)
              }
            >
              Open Investigation
            </button>
          </div>
        ))}
      </div>
    </section>
  );

  const renderInvestigationDetail = () => {
    if (investigationLoading) {
      return (
        <section className="dashboard-card page-card">
          <div className="empty-state">
            Loading investigation...
          </div>
        </section>
      );
    }

    if (investigationError) {
      return (
        <section className="dashboard-card page-card">
          <div className="error-banner">
            <strong>Investigation Error</strong>
            <span>{investigationError}</span>
          </div>
        </section>
      );
    }

    if (!investigation) {
      return (
        <section className="dashboard-card page-card">
          <div className="empty-state">
            Select a correlation to start an investigation.
          </div>
        </section>
      );
    }

    const {
      correlation,
      asset,
      alert,
      vulnerability,
      finding,
      services: investigationServices,
      events,
      evidence,
    } = investigation;

    return (
      <>
        <div className="investigation-back">
          <button
            className="action-button secondary"
            onClick={() =>
              handleNavigation("investigations")
            }
          >
            ← Back to Investigations
          </button>
        </div>

        <section className="investigation-hero">
          <div>
            <span className="eyebrow">
              INVESTIGATION #{correlation.id}
            </span>

            <h1>{correlation.title}</h1>

            <p>{correlation.description}</p>
          </div>

          <span
            className={`severity-badge large ${severityClass(
              correlation.priority
            )}`}
          >
            {correlation.priority}
          </span>
        </section>

        <section className="investigation-grid">
          <div className="dashboard-card investigation-panel">
            <div className="card-heading">
              <div>
                <span className="card-label">AFFECTED ASSET</span>
                <h2>Asset Details</h2>
              </div>
            </div>

            <div className="detail-list">
              <Detail label="IP Address" value={asset?.ip_address} />
              <Detail label="Hostname" value={asset?.hostname} />
              <Detail label="OS" value={asset?.os_name} />
              <Detail label="MAC" value={asset?.mac_address} />
            </div>
          </div>

          <div className="dashboard-card investigation-panel">
            <div className="card-heading">
              <div>
                <span className="card-label">SOC ALERT</span>
                <h2>Alert Details</h2>
              </div>
            </div>

            <div className="detail-list">
              <Detail label="Type" value={alert?.alert_type} />
              <Detail label="Source IP" value={alert?.source_ip} />
              <Detail
                label="Destination IP"
                value={alert?.destination_ip}
              />
              <Detail
                label="Event Count"
                value={alert?.event_count}
              />
              <Detail label="Status" value={alert?.status} />
            </div>
          </div>

          <div className="dashboard-card investigation-panel">
            <div className="card-heading">
              <div>
                <span className="card-label">VULNERABILITY</span>
                <h2>Vulnerability Details</h2>
              </div>
            </div>

            <div className="detail-list">
              <Detail
                label="CVE"
                value={vulnerability?.cve_id}
              />
              <Detail
                label="Title"
                value={vulnerability?.title}
              />
              <Detail
                label="CVSS"
                value={vulnerability?.cvss_score}
              />
              <Detail
                label="Severity"
                value={vulnerability?.severity}
              />
              <Detail
                label="CWE"
                value={vulnerability?.cwe_id}
              />
            </div>
          </div>

          <div className="dashboard-card investigation-panel">
            <div className="card-heading">
              <div>
                <span className="card-label">RISK FINDING</span>
                <h2>Finding Details</h2>
              </div>
            </div>

            <div className="detail-list">
              <Detail label="Finding ID" value={finding?.id} />
              <Detail label="Risk Score" value={finding?.risk_score} />
              <Detail label="Severity" value={finding?.severity} />
              <Detail label="Status" value={finding?.status} />
              <Detail
                label="Resolved At"
                value={formatDate(finding?.resolved_at)}
              />
            </div>
          </div>
        </section>

        <section className="dashboard-card page-card">
          <div className="card-heading">
            <div>
              <span className="card-label">ATTACK SURFACE</span>
              <h2>Related Services</h2>
            </div>

            <div className="finding-total">
              {investigationServices?.length || 0} services
            </div>
          </div>

          <DataTable
            columns={[
              "Port",
              "Protocol",
              "Service",
              "Product",
              "Version",
              "State",
            ]}
            rows={(investigationServices || []).map((service) => [
              service.port,
              service.protocol,
              service.service_name || "N/A",
              service.product || "N/A",
              service.version || "N/A",
              service.state || "N/A",
            ])}
          />
        </section>

        <section className="dashboard-card page-card">
          <div className="card-heading">
            <div>
              <span className="card-label">SOC TIMELINE</span>
              <h2>Security Events</h2>
            </div>

            <div className="finding-total">
              {events?.length || 0} events
            </div>
          </div>

          <div className="timeline">
            {(events || []).map((event) => (
              <div className="timeline-item" key={event.id}>
                <div className="timeline-marker"></div>

                <div className="timeline-content">
                  <div className="timeline-top">
                    <strong>{event.event_type}</strong>

                    <span
                      className={`severity-badge ${severityClass(
                        event.severity
                      )}`}
                    >
                      {event.severity}
                    </span>
                  </div>

                  <div className="timeline-meta">
                    {formatDate(event.event_time)}
                    {" · "}
                    {event.source_ip || "N/A"}
                    {" → "}
                    {event.destination_ip || "N/A"}
                  </div>

                  {event.raw_log && (
                    <pre className="evidence-code">
                      {event.raw_log}
                    </pre>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="dashboard-card page-card">
          <div className="card-heading">
            <div>
              <span className="card-label">EVIDENCE</span>
              <h2>Investigation Evidence</h2>
            </div>

            <div className="finding-total">
              {evidence?.length || 0} records
            </div>
          </div>

          <div className="evidence-list">
            {(evidence || []).map((item) => (
              <div
                className="evidence-item"
                key={`${item.event_id}-${item.event_time}`}
              >
                <div>
                  <strong>{item.event_type}</strong>
                  <span>
                    {item.source || "Unknown source"} ·{" "}
                    {formatDate(item.event_time)}
                  </span>
                </div>

                <pre className="evidence-code">
                  {item.raw_log}
                </pre>
              </div>
            ))}
          </div>
        </section>
      </>
    );
  };

  const renderPage = () => {
    switch (activePage) {
      case "dashboard":
        return renderDashboard();

      case "assets":
        return renderAssets();

      case "services":
        return renderServices();

      case "vulnerabilities":
        return renderVulnerabilities();

      case "findings":
        return renderFindings();

      case "scans":
        return renderScans();

      case "alerts":
        return renderAlerts();

      case "correlations":
        return renderCorrelations();

      case "investigations":
        return renderInvestigations();

      case "investigation-detail":
        return renderInvestigationDetail();

      default:
        return renderDashboard();
    }
  };

  const pageTitle = {
    dashboard: "Dashboard",
    assets: "Assets",
    services: "Services",
    vulnerabilities: "Vulnerabilities",
    findings: "Findings",
    scans: "Scans",
    alerts: "Alerts",
    correlations: "Correlations",
    investigations: "Investigations",
    "investigation-detail": "Investigation Detail",
  };

  return (
    <div className="app-shell">
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

          <NavButton
            active={activePage === "dashboard"}
            icon="▦"
            label="Dashboard"
            onClick={() => handleNavigation("dashboard")}
          />

          <NavButton
            active={activePage === "assets"}
            icon="◉"
            label="Assets"
            onClick={() => handleNavigation("assets")}
          />

          <NavButton
            active={activePage === "services"}
            icon="⌘"
            label="Services"
            onClick={() => handleNavigation("services")}
          />

          <div className="nav-section">SECURITY</div>

          <NavButton
            active={activePage === "vulnerabilities"}
            icon="△"
            label="Vulnerabilities"
            onClick={() =>
              handleNavigation("vulnerabilities")
            }
          />

          <NavButton
            active={activePage === "findings"}
            icon="!"
            label="Findings"
            onClick={() => handleNavigation("findings")}
          />

          <NavButton
            active={activePage === "scans"}
            icon="◫"
            label="Scans"
            onClick={() => handleNavigation("scans")}
          />

          <div className="nav-section">SOC</div>

          <NavButton
            active={activePage === "alerts"}
            icon="⚠"
            label="Alerts"
            onClick={() => handleNavigation("alerts")}
          />

          <NavButton
            active={activePage === "correlations"}
            icon="↔"
            label="Correlations"
            onClick={() => handleNavigation("correlations")}
          />

          <NavButton
            active={
              activePage === "investigations" ||
              activePage === "investigation-detail"
            }
            icon="⌕"
            label="Investigations"
            onClick={() =>
              handleNavigation("investigations")
            }
          />
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

      <div className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Security</span>
            <b>/</b>
            {pageTitle[activePage]}
          </div>

          <div className="topbar-right">
            <div className="last-scan">
              Security monitoring active
            </div>

            <button
              className={`refresh-button ${
                refreshing ? "refreshing" : ""
              }`}
              onClick={handleRefresh}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing..." : "Refresh Data"}
            </button>

            <div className="backend-status">
              <span className="online-dot"></span>
              Backend Connected
            </div>

            <div className="user-avatar">V</div>
          </div>
        </header>

        <main className="dashboard-content">
          {error && (
            <div className="error-banner">
              <strong>Connection Error</strong>
              <span>{error}</span>
            </div>
          )}

          {renderPage()}
        </main>
      </div>
    </div>
  );
}


function NavButton({ active, icon, label, onClick }) {
  return (
    <button
      type="button"
      className={`nav-item ${active ? "active" : ""}`}
      onClick={onClick}
    >
      <span className="nav-icon">{icon}</span>
      {label}
    </button>
  );
}


function PageHeader({ label, title, count }) {
  return (
    <div className="card-heading">
      <div>
        <span className="card-label">{label}</span>
        <h2>{title}</h2>
      </div>

      <div className="finding-total">
        {count} records
      </div>
    </div>
  );
}


function DataTable({ columns, rows }) {
  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>

        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="empty-table"
              >
                No records available.
              </td>
            </tr>
          ) : (
            rows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {row.map((value, columnIndex) => (
                  <td key={columnIndex}>
                    {value ?? "N/A"}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}


function Detail({ label, value }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value ?? "N/A"}</strong>
    </div>
  );
}


export default App;