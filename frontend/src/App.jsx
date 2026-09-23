import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://localhost:8000";

function App() {
  // =========================================================
  // DASHBOARD STATE
  // =========================================================
  const [summary, setSummary] = useState(null);
  const [riskOverview, setRiskOverview] = useState(null);
  const [recentFindings, setRecentFindings] = useState([]);
  const [severityDistribution, setSeverityDistribution] = useState([]);
  const [statusDistribution, setStatusDistribution] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // =========================================================
  // PAGE STATE
  // =========================================================
  const [activePage, setActivePage] = useState("Dashboard");

  // =========================================================
  // ASSETS STATE
  // =========================================================
  const [assets, setAssets] = useState([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetsError, setAssetsError] = useState("");

  // =========================================================
  // SERVICES STATE
  // =========================================================
  const [services, setServices] = useState([]);
  const [servicesLoading, setServicesLoading] = useState(false);
  const [servicesError, setServicesError] = useState("");

  // =========================================================
  // VULNERABILITIES STATE
  // =========================================================
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] =
    useState(false);
  const [vulnerabilitiesError, setVulnerabilitiesError] =
    useState("");

  // =========================================================
  // FINDINGS STATE
  // =========================================================
  const [findings, setFindings] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState("");

  // =========================================================
  // SCANS STATE
  // =========================================================
  const [scans, setScans] = useState([]);
  const [scansLoading, setScansLoading] = useState(false);
  const [scansError, setScansError] = useState("");

  // =========================================================
  // DASHBOARD API
  // =========================================================
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
        setSeverityDistribution(
          severityData.distribution || []
        );
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

  // =========================================================
  // ASSETS API
  // =========================================================
  useEffect(() => {
    async function loadAssets() {
      try {
        setAssetsLoading(true);
        setAssetsError("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/assets`
        );

        if (!response.ok) {
          throw new Error("Assets API request failed");
        }

        const data = await response.json();

        let normalizedAssets = [];

        if (Array.isArray(data)) {
          normalizedAssets = data;
        } else if (Array.isArray(data?.assets)) {
          normalizedAssets = data.assets;
        } else if (Array.isArray(data?.items)) {
          normalizedAssets = data.items;
        }

        setAssets(normalizedAssets);
      } catch (err) {
        console.error(err);
        setAssetsError("Unable to load assets.");
        setAssets([]);
      } finally {
        setAssetsLoading(false);
      }
    }

    loadAssets();
  }, []);

  // =========================================================
  // SERVICES API
  // =========================================================
  useEffect(() => {
    async function loadServices() {
      try {
        setServicesLoading(true);
        setServicesError("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/services`
        );

        if (!response.ok) {
          throw new Error("Services API request failed");
        }

        const data = await response.json();

        let normalizedServices = [];

        if (Array.isArray(data)) {
          normalizedServices = data;
        } else if (Array.isArray(data?.services)) {
          normalizedServices = data.services;
        } else if (Array.isArray(data?.items)) {
          normalizedServices = data.items;
        }

        setServices(normalizedServices);
      } catch (err) {
        console.error(err);
        setServicesError("Unable to load services.");
        setServices([]);
      } finally {
        setServicesLoading(false);
      }
    }

    loadServices();
  }, []);

  // =========================================================
  // VULNERABILITIES API
  // =========================================================
  useEffect(() => {
    async function loadVulnerabilities() {
      try {
        setVulnerabilitiesLoading(true);
        setVulnerabilitiesError("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/vulnerabilities`
        );

        if (!response.ok) {
          throw new Error(
            "Vulnerabilities API request failed"
          );
        }

        const data = await response.json();

        let normalizedVulnerabilities = [];

        if (Array.isArray(data)) {
          normalizedVulnerabilities = data;
        } else if (Array.isArray(data?.vulnerabilities)) {
          normalizedVulnerabilities = data.vulnerabilities;
        } else if (Array.isArray(data?.items)) {
          normalizedVulnerabilities = data.items;
        }

        setVulnerabilities(normalizedVulnerabilities);
      } catch (err) {
        console.error(err);
        setVulnerabilitiesError(
          "Unable to load vulnerabilities."
        );
        setVulnerabilities([]);
      } finally {
        setVulnerabilitiesLoading(false);
      }
    }

    loadVulnerabilities();
  }, []);

  // =========================================================
  // FINDINGS API
  // =========================================================
  useEffect(() => {
    async function loadFindings() {
      try {
        setFindingsLoading(true);
        setFindingsError("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/findings`
        );

        if (!response.ok) {
          throw new Error("Findings API request failed");
        }

        const data = await response.json();

        let normalizedFindings = [];

        if (Array.isArray(data)) {
          normalizedFindings = data;
        } else if (Array.isArray(data?.findings)) {
          normalizedFindings = data.findings;
        } else if (Array.isArray(data?.items)) {
          normalizedFindings = data.items;
        }

        setFindings(normalizedFindings);
      } catch (err) {
        console.error(err);
        setFindingsError("Unable to load findings.");
        setFindings([]);
      } finally {
        setFindingsLoading(false);
      }
    }

    loadFindings();
  }, []);

  // =========================================================
  // SCANS API
  // =========================================================
  useEffect(() => {
    async function loadScans() {
      try {
        setScansLoading(true);
        setScansError("");

        const response = await fetch(
          `${API_BASE_URL}/api/v1/scans`
        );

        if (!response.ok) {
          throw new Error("Scans API request failed");
        }

        const data = await response.json();

        let normalizedScans = [];

        if (Array.isArray(data)) {
          normalizedScans = data;
        } else if (Array.isArray(data?.scans)) {
          normalizedScans = data.scans;
        } else if (Array.isArray(data?.items)) {
          normalizedScans = data.items;
        }

        setScans(normalizedScans);
      } catch (err) {
        console.error(err);
        setScansError("Unable to load scans.");
        setScans([]);
      } finally {
        setScansLoading(false);
      }
    }

    loadScans();
  }, []);

  // =========================================================
  // HELPERS
  // =========================================================
  const severityClass = (severity) =>
    severity?.toLowerCase() || "unknown";

  const statusClass = (status) =>
    status?.toLowerCase().replace("_", "-") || "unknown";

  const formatDate = (value) => {
    if (!value) return "N/A";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return date.toLocaleString();
  };

  const handleNavigation = (page) => {
    setActivePage(page);
  };

  // =========================================================
  // ASSET HELPERS
  // =========================================================
  const getUniqueAssets = () => {
    const map = new Map();

    assets.forEach((item) => {
      const key =
        item.asset_id ??
        item.id ??
        item.target_ip ??
        `asset-${map.size}`;

      if (!map.has(key)) {
        map.set(key, item);
      }
    });

    return Array.from(map.values());
  };

  // =========================================================
  // DASHBOARD
  // =========================================================
  const renderDashboard = () => (
    <>
      <section className="hero-section">
        <div>
          <div className="eyebrow">SECURITY OVERVIEW</div>

          <h1>Security Dashboard</h1>

          <p>
            Monitor assets, vulnerabilities, findings and
            security risk from one centralized view.
          </p>
        </div>

        <div className="hero-decoration">
          <div className="scan-ring ring-one"></div>
          <div className="scan-ring ring-two"></div>
          <div className="scan-core">V</div>
        </div>
      </section>

      {error && (
        <div className="error-banner">
          <strong>Connection Error</strong>
          <span>{error}</span>
        </div>
      )}

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-top">
            <span className="stat-icon blue">◉</span>
            <span className="stat-category">
              INFRASTRUCTURE
            </span>
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
            {loading
              ? "—"
              : summary?.vulnerabilities?.total ?? 0}
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
                <span className="card-label">
                  RISK ANALYSIS
                </span>
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

          <div className="dashboard-card">
            <div className="card-heading">
              <div>
                <span className="card-label">
                  THREAT LEVEL
                </span>
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
                <span className="card-label">
                  WORKFLOW
                </span>
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

      {!loading && !error && (
        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                SECURITY EVENTS
              </span>
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
                        {finding.service_name || "Security finding"}
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
                        {finding.risk_score ?? "N/A"}
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
    </>
  );

  // =========================================================
  // ASSETS PAGE
  // =========================================================
  const renderAssets = () => {
    const uniqueAssets = getUniqueAssets();

    const totalServices = assets.length;

    const totalVulnerabilities = new Set(
      assets
        .map((item) => item.vulnerability_id)
        .filter(Boolean)
    ).size;

    return (
      <>
        <section className="hero-section">
          <div>
            <div className="eyebrow">ASSET MANAGEMENT</div>

            <h1>Assets</h1>

            <p>
              Review discovered infrastructure and the
              services associated with each asset.
            </p>
          </div>

          <div className="hero-decoration">
            <div className="scan-ring ring-one"></div>
            <div className="scan-ring ring-two"></div>
            <div className="scan-core">◉</div>
          </div>
        </section>

        {assetsError && (
          <div className="error-banner">
            <strong>Assets Error</strong>
            <span>{assetsError}</span>
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon blue">◉</span>
              <span className="stat-category">
                INFRASTRUCTURE
              </span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : uniqueAssets.length}
            </div>

            <div className="stat-name">Total Assets</div>

            <div className="stat-line">
              Unique discovered assets
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">◫</span>
              <span className="stat-category">DISCOVERY</span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : uniqueAssets.length}
            </div>

            <div className="stat-name">Discovered</div>

            <div className="stat-line">
              Assets identified by scanning
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">⌘</span>
              <span className="stat-category">SERVICES</span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : totalServices}
            </div>

            <div className="stat-name">Services</div>

            <div className="stat-line">
              Services associated with assets
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">!</span>
              <span className="stat-category">
                VULNERABILITIES
              </span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : totalVulnerabilities}
            </div>

            <div className="stat-name">Vulnerabilities</div>

            <div className="stat-line">
              Vulnerabilities mapped to services
            </div>
          </div>
        </section>

        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                ASSET INVENTORY
              </span>

              <h2>Discovered Assets</h2>
            </div>

            <div className="finding-total">
              {uniqueAssets.length} assets
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Hostname</th>
                  <th>OS</th>
                  <th>Services</th>
                  <th>Vulnerabilities</th>
                </tr>
              </thead>

              <tbody>
                {uniqueAssets.map((asset, index) => (
                  <tr
                    key={
                      asset.asset_id ??
                      asset.id ??
                      asset.target_ip ??
                      index
                    }
                  >
                    <td>
                      #{asset.asset_id ?? asset.id ?? index + 1}
                    </td>

                    <td>
                      <strong>
                        {asset.target_ip || "N/A"}
                      </strong>
                    </td>

                    <td>
                      {asset.hostname || "N/A"}
                    </td>

                    <td>
                      {asset.os || asset.operating_system || "Linux"}
                    </td>

                    <td>
                      {asset.service_count ??
                        (asset.port ? 1 : 0)}
                    </td>

                    <td>
                      {asset.vulnerability_id ? 1 : 0}
                    </td>
                  </tr>
                ))}

                {!assetsLoading && uniqueAssets.length === 0 && (
                  <tr>
                    <td colSpan="6">
                      No assets found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="dashboard-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                ASSET DETAILS
              </span>

              <h2>Latest Asset Data</h2>
            </div>
          </div>

          <div className="status-list">
            {uniqueAssets.map((asset, index) => (
              <div
                className="status-row"
                key={`detail-${asset.asset_id ?? index}`}
              >
                <div>
                  <span className="status-dot resolved"></span>
                  <span>
                    {asset.hostname ||
                      asset.target_ip ||
                      "Asset"}
                  </span>
                </div>

                <strong>
                  {asset.target_ip || "N/A"}
                </strong>
              </div>
            ))}

            {!assetsLoading && uniqueAssets.length === 0 && (
              <div className="status-row">
                <div>
                  <span>No asset details available.</span>
                </div>
              </div>
            )}
          </div>
        </section>
      </>
    );
  };

  // =========================================================
  // SERVICES PAGE
  // =========================================================
  const renderServices = () => {
    const uniqueTargets = new Set(
      services.map((item) => item.target_ip).filter(Boolean)
    ).size;

    const vulnerableServices = new Set(
      services
        .map((item) => item.vulnerability_id)
        .filter(Boolean)
    ).size;

    const criticalServices = services.filter(
      (item) => item.severity === "CRITICAL"
    ).length;

    return (
      <>
        <section className="hero-section">
          <div>
            <div className="eyebrow">SERVICE INVENTORY</div>

            <h1>Services</h1>

            <p>
              Review network services discovered by VulnWatch
              through Nmap-based asset discovery.
            </p>
          </div>

          <div className="hero-decoration">
            <div className="scan-ring ring-one"></div>
            <div className="scan-ring ring-two"></div>
            <div className="scan-core">⌘</div>
          </div>
        </section>

        {servicesError && (
          <div className="error-banner">
            <strong>Services Error</strong>
            <span>{servicesError}</span>
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">⌘</span>
              <span className="stat-category">
                SERVICES
              </span>
            </div>

            <div className="stat-value">
              {servicesLoading ? "—" : services.length}
            </div>

            <div className="stat-name">Total Services</div>

            <div className="stat-line">
              Services returned by VulnWatch
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon blue">◉</span>
              <span className="stat-category">
                TARGETS
              </span>
            </div>

            <div className="stat-value">
              {servicesLoading ? "—" : uniqueTargets}
            </div>

            <div className="stat-name">Assets Associated</div>

            <div className="stat-line">
              Assets associated with discovered services
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">△</span>
              <span className="stat-category">
                VULNERABILITIES
              </span>
            </div>

            <div className="stat-value">
              {servicesLoading ? "—" : vulnerableServices}
            </div>

            <div className="stat-name">Mapped Vulnerabilities</div>

            <div className="stat-line">
              Services mapped to vulnerabilities
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">!</span>
              <span className="stat-category">
                CRITICAL
              </span>
            </div>

            <div className="stat-value">
              {servicesLoading ? "—" : criticalServices}
            </div>

            <div className="stat-name">Critical Services</div>

            <div className="stat-line">
              Services with critical severity
            </div>
          </div>
        </section>

        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                SERVICE INVENTORY
              </span>

              <h2>Discovered Network Services</h2>
            </div>

            <div className="finding-total">
              {services.length} services
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                </tr>
              </thead>

              <tbody>
                {services.map((item, index) => (
                  <tr
                    key={
                      item.id ??
                      `${item.service_id}-${item.port}-${index}`
                    }
                  >
                    <td>
                      <strong>
                        {item.target_ip || "N/A"}
                      </strong>
                    </td>

                    <td>{item.port ?? "N/A"}</td>

                    <td>{item.protocol || "N/A"}</td>

                    <td>
                      <strong>
                        {item.service_name || "N/A"}
                      </strong>
                    </td>

                    <td>{item.product || "N/A"}</td>

                    <td>{item.version || "N/A"}</td>

                    <td>
                      <span className="cve-code">
                        {item.cve_id || "N/A"}
                      </span>
                    </td>

                    <td>
                      {item.severity ? (
                        <span
                          className={`severity-badge ${severityClass(
                            item.severity
                          )}`}
                        >
                          {item.severity}
                        </span>
                      ) : (
                        "N/A"
                      )}
                    </td>

                    <td>
                      <strong>
                        {item.cvss_score ?? "N/A"}
                      </strong>
                    </td>
                  </tr>
                ))}

                {!servicesLoading && services.length === 0 && (
                  <tr>
                    <td colSpan="9">
                      No services found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </>
    );
  };

  // =========================================================
  // VULNERABILITIES PAGE
  // =========================================================
  const renderVulnerabilities = () => {
    const critical = vulnerabilities.filter(
      (item) => item.severity === "CRITICAL"
    ).length;

    const high = vulnerabilities.filter(
      (item) => item.severity === "HIGH"
    ).length;

    const averageCvss =
      vulnerabilities.length > 0
        ? (
            vulnerabilities.reduce(
              (sum, item) =>
                sum + Number(item.cvss_score || 0),
              0
            ) / vulnerabilities.length
          ).toFixed(1)
        : "0.0";

    return (
      <>
        <section className="hero-section">
          <div>
            <div className="eyebrow">
              VULNERABILITY MANAGEMENT
            </div>

            <h1>Vulnerabilities</h1>

            <p>
              Review CVEs, severity, CVSS scores and
              vulnerability metadata collected by VulnWatch.
            </p>
          </div>

          <div className="hero-decoration">
            <div className="scan-ring ring-one"></div>
            <div className="scan-ring ring-two"></div>
            <div className="scan-core">△</div>
          </div>
        </section>

        {vulnerabilitiesError && (
          <div className="error-banner">
            <strong>Vulnerability Error</strong>
            <span>{vulnerabilitiesError}</span>
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon blue">△</span>
              <span className="stat-category">THREATS</span>
            </div>

            <div className="stat-value">
              {vulnerabilitiesLoading
                ? "—"
                : vulnerabilities.length}
            </div>

            <div className="stat-name">
              Total Vulnerabilities
            </div>

            <div className="stat-line">
              Vulnerabilities stored in VulnWatch
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">!</span>
              <span className="stat-category">
                CRITICAL
              </span>
            </div>

            <div className="stat-value">
              {vulnerabilitiesLoading ? "—" : critical}
            </div>

            <div className="stat-name">Critical</div>

            <div className="stat-line">
              Critical severity vulnerabilities
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">▲</span>
              <span className="stat-category">HIGH</span>
            </div>

            <div className="stat-value">
              {vulnerabilitiesLoading ? "—" : high}
            </div>

            <div className="stat-name">High Severity</div>

            <div className="stat-line">
              High severity vulnerabilities
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">◇</span>
              <span className="stat-category">CVSS</span>
            </div>

            <div className="stat-value">
              {vulnerabilitiesLoading
                ? "—"
                : averageCvss}
            </div>

            <div className="stat-name">Average CVSS</div>

            <div className="stat-line">
              Average CVSS score across vulnerabilities
            </div>
          </div>
        </section>

        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                VULNERABILITY DATABASE
              </span>

              <h2>Known Vulnerabilities</h2>
            </div>

            <div className="finding-total">
              {vulnerabilities.length} vulnerabilities
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Description</th>
                  <th>CVSS</th>
                  <th>Severity</th>
                  <th>CWE</th>
                  <th>Published</th>
                  <th>Last Modified</th>
                </tr>
              </thead>

              <tbody>
                {vulnerabilities.map((item) => (
                  <tr key={item.id ?? item.cve_id}>
                    <td>
                      <span className="cve-code">
                        {item.cve_id || "N/A"}
                      </span>
                    </td>

                    <td>
                      <strong>
                        {item.description || "N/A"}
                      </strong>
                    </td>

                    <td>
                      <strong>
                        {item.cvss_score ?? "N/A"}
                      </strong>
                    </td>

                    <td>
                      <span
                        className={`severity-badge ${severityClass(
                          item.severity
                        )}`}
                      >
                        {item.severity || "UNKNOWN"}
                      </span>
                    </td>

                    <td>
                      {item.cwe || "N/A"}
                    </td>

                    <td>
                      {formatDate(item.published)}
                    </td>

                    <td>
                      {formatDate(item.last_modified)}
                    </td>
                  </tr>
                ))}

                {!vulnerabilitiesLoading &&
                  vulnerabilities.length === 0 && (
                    <tr>
                      <td colSpan="7">
                        No vulnerabilities found.
                      </td>
                    </tr>
                  )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="dashboard-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                VULNERABILITY DETAILS
              </span>

              <h2>CVSS & Classification</h2>
            </div>
          </div>

          <div className="status-list">
            {vulnerabilities.map((item) => (
              <div
                className="status-row"
                key={`classification-${item.id}`}
              >
                <div>
                  <span
                    className={`status-dot ${severityClass(
                      item.severity
                    )}`}
                  ></span>

                  <span>{item.cve_id}</span>
                </div>

                <strong>
                  CVSS {item.cvss_score ?? "N/A"} ·{" "}
                  {item.cvss_version || "N/A"}
                </strong>
              </div>
            ))}
          </div>
        </section>
      </>
    );
  };

  // =========================================================
  // FINDINGS PAGE
  // =========================================================
  const renderFindings = () => {
    const critical = findings.filter(
      (item) => item.severity === "CRITICAL"
    ).length;

    const open = findings.filter(
      (item) => item.status === "OPEN"
    ).length;

    const resolved = findings.filter(
      (item) => item.status === "RESOLVED"
    ).length;

    const totalRisk = findings.reduce(
      (sum, item) => sum + Number(item.risk_score || 0),
      0
    );

    const highestRisk =
      findings.length > 0
        ? Math.max(
            ...findings.map((item) =>
              Number(item.risk_score || 0)
            )
          )
        : 0;

    return (
      <>
        <section className="hero-section">
          <div>
            <div className="eyebrow">RISK MANAGEMENT</div>

            <h1>Findings</h1>

            <p>
              Track security findings, risk scores, remediation
              status and resolution lifecycle.
            </p>
          </div>

          <div className="hero-decoration">
            <div className="scan-ring ring-one"></div>
            <div className="scan-ring ring-two"></div>
            <div className="scan-core">!</div>
          </div>
        </section>

        {findingsError && (
          <div className="error-banner">
            <strong>Findings Error</strong>
            <span>{findingsError}</span>
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon blue">!</span>
              <span className="stat-category">
                FINDINGS
              </span>
            </div>

            <div className="stat-value">
              {findingsLoading ? "—" : findings.length}
            </div>

            <div className="stat-name">Total Findings</div>

            <div className="stat-line">
              Security findings tracked by VulnWatch
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">!</span>
              <span className="stat-category">
                CRITICAL
              </span>
            </div>

            <div className="stat-value">
              {findingsLoading ? "—" : critical}
            </div>

            <div className="stat-name">Critical Findings</div>

            <div className="stat-line">
              Findings with critical severity
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">◷</span>
              <span className="stat-category">
                WORKFLOW
              </span>
            </div>

            <div className="stat-value">
              {findingsLoading ? "—" : open}
            </div>

            <div className="stat-name">Open Findings</div>

            <div className="stat-line">
              Findings requiring active remediation
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">✓</span>
              <span className="stat-category">
                RESOLUTION
              </span>
            </div>

            <div className="stat-value">
              {findingsLoading ? "—" : resolved}
            </div>

            <div className="stat-name">Resolved</div>

            <div className="stat-line">
              Findings marked as resolved
            </div>
          </div>
        </section>

        <section className="analytics-grid">
          <div className="dashboard-card risk-card">
            <div className="card-heading">
              <div>
                <span className="card-label">
                  RISK MANAGEMENT
                </span>

                <h2>Finding Risk Summary</h2>
              </div>
            </div>

            <div className="risk-metrics">
              <div className="metric">
                <span>Total Risk Score</span>
                <strong>{totalRisk}</strong>
              </div>

              <div className="metric">
                <span>Highest Risk</span>
                <strong>{highestRisk}</strong>
              </div>

              <div className="metric">
                <span>Open Risk</span>
                <strong>
                  {findings
                    .filter(
                      (item) => item.status !== "RESOLVED"
                    )
                    .reduce(
                      (sum, item) =>
                        sum +
                        Number(item.risk_score || 0),
                      0
                    )}
                </strong>
              </div>

              <div className="metric">
                <span>Resolved Risk</span>
                <strong>
                  {findings
                    .filter(
                      (item) => item.status === "RESOLVED"
                    )
                    .reduce(
                      (sum, item) =>
                        sum +
                        Number(item.risk_score || 0),
                      0
                    )}
                </strong>
              </div>
            </div>
          </div>

          <div className="dashboard-card">
            <div className="card-heading">
              <div>
                <span className="card-label">
                  STATUS OVERVIEW
                </span>

                <h2>Finding Status</h2>
              </div>
            </div>

            <div className="status-list">
              <div className="status-row">
                <div>
                  <span className="status-dot open"></span>
                  <span>OPEN</span>
                </div>

                <strong>{open}</strong>
              </div>

              <div className="status-row">
                <div>
                  <span className="status-dot in-progress"></span>
                  <span>IN PROGRESS</span>
                </div>

                <strong>
                  {
                    findings.filter(
                      (item) =>
                        item.status === "IN_PROGRESS"
                    ).length
                  }
                </strong>
              </div>

              <div className="status-row">
                <div>
                  <span className="status-dot resolved"></span>
                  <span>RESOLVED</span>
                </div>

                <strong>{resolved}</strong>
              </div>
            </div>
          </div>
        </section>

        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                SECURITY FINDINGS
              </span>

              <h2>Finding Inventory</h2>
            </div>

            <div className="finding-total">
              {findings.length} findings
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Finding</th>
                  <th>Target</th>
                  <th>Service</th>
                  <th>CVE</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {findings.map((finding) => (
                  <tr key={finding.id}>
                    <td>#{finding.id}</td>

                    <td>
                      <div className="finding-name">
                        {finding.title || "Security Finding"}
                      </div>

                      <div className="finding-sub">
                        {finding.description || "N/A"}
                      </div>
                    </td>

                    <td>
                      {finding.target_ip || "N/A"}
                    </td>

                    <td>
                      {finding.service_name
                        ? `${finding.service_name}${
                            finding.port
                              ? `:${finding.port}`
                              : ""
                          }`
                        : "N/A"}
                    </td>

                    <td>
                      <span className="cve-code">
                        {finding.cve_id || "N/A"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`severity-badge ${severityClass(
                          finding.severity
                        )}`}
                      >
                        {finding.severity || "UNKNOWN"}
                      </span>
                    </td>

                    <td>
                      <strong className="risk-number-small">
                        {finding.risk_score ?? "N/A"}
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

                {!findingsLoading && findings.length === 0 && (
                  <tr>
                    <td colSpan="8">
                      No findings found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </>
    );
  };

  // =========================================================
  // SCANS PAGE
  // =========================================================
  const renderScans = () => {
    const uniqueTargets = new Set(
      scans.map((scan) => scan.target).filter(Boolean)
    ).size;

    const uniqueScanners = new Set(
      scans.map((scan) => scan.scanner_ip).filter(Boolean)
    ).size;

    const latestScan =
      scans.length > 0
        ? [...scans].sort(
            (a, b) =>
              new Date(b.created_at || 0) -
              new Date(a.created_at || 0)
          )[0]
        : null;

    return (
      <>
        <section className="hero-section">
          <div>
            <div className="eyebrow">SCAN MANAGEMENT</div>

            <h1>Scans</h1>

            <p>
              Review Nmap scan history, targets, scanner
              information and commands used by VulnWatch.
            </p>
          </div>

          <div className="hero-decoration">
            <div className="scan-ring ring-one"></div>
            <div className="scan-ring ring-two"></div>
            <div className="scan-core">◫</div>
          </div>
        </section>

        {scansError && (
          <div className="error-banner">
            <strong>Scans Error</strong>
            <span>{scansError}</span>
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">◫</span>
              <span className="stat-category">
                SCANS
              </span>
            </div>

            <div className="stat-value">
              {scansLoading ? "—" : scans.length}
            </div>

            <div className="stat-name">Total Scans</div>

            <div className="stat-line">
              Scan records stored in VulnWatch
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon blue">◉</span>
              <span className="stat-category">
                TARGETS
              </span>
            </div>

            <div className="stat-value">
              {scansLoading ? "—" : uniqueTargets}
            </div>

            <div className="stat-name">Unique Targets</div>

            <div className="stat-line">
              Targets covered by scan history
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">⌘</span>
              <span className="stat-category">
                SCANNERS
              </span>
            </div>

            <div className="stat-value">
              {scansLoading ? "—" : uniqueScanners}
            </div>

            <div className="stat-name">Scanner Nodes</div>

            <div className="stat-line">
              Scanner IPs recorded in scan history
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">✓</span>
              <span className="stat-category">
                LATEST
              </span>
            </div>

            <div className="stat-value">
              {scansLoading
                ? "—"
                : latestScan?.id ?? "N/A"}
            </div>

            <div className="stat-name">Latest Scan</div>

            <div className="stat-line">
              Most recently created scan record
            </div>
          </div>
        </section>

        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                SCAN INVENTORY
              </span>

              <h2>Scan History</h2>
            </div>

            <div className="finding-total">
              {scans.length} scans
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Scanner</th>
                  <th>Started</th>
                  <th>Created</th>
                  <th>Nmap Command</th>
                </tr>
              </thead>

              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <strong>#{scan.id}</strong>
                    </td>

                    <td>
                      <strong>
                        {scan.target || "N/A"}
                      </strong>
                    </td>

                    <td>
                      {scan.scanner_ip || "N/A"}
                    </td>

                    <td>
                      {formatDate(scan.started_at)}
                    </td>

                    <td>
                      {formatDate(scan.created_at)}
                    </td>

                    <td>
                      <code
                        style={{
                          fontSize: "12px",
                          wordBreak: "break-word",
                        }}
                      >
                        {scan.nmap_command || "N/A"}
                      </code>
                    </td>
                  </tr>
                ))}

                {!scansLoading && scans.length === 0 && (
                  <tr>
                    <td colSpan="6">
                      No scans found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {latestScan && (
          <section className="dashboard-card">
            <div className="card-heading">
              <div>
                <span className="card-label">
                  LATEST SCAN
                </span>

                <h2>Scan Details</h2>
              </div>
            </div>

            <div className="status-list">
              <div className="status-row">
                <div>
                  <span className="status-dot resolved"></span>
                  <span>Scan ID</span>
                </div>

                <strong>#{latestScan.id}</strong>
              </div>

              <div className="status-row">
                <div>
                  <span className="status-dot resolved"></span>
                  <span>Target</span>
                </div>

                <strong>
                  {latestScan.target || "N/A"}
                </strong>
              </div>

              <div className="status-row">
                <div>
                  <span className="status-dot resolved"></span>
                  <span>Scanner</span>
                </div>

                <strong>
                  {latestScan.scanner_ip || "N/A"}
                </strong>
              </div>

              <div className="status-row">
                <div>
                  <span className="status-dot resolved"></span>
                  <span>Nmap Command</span>
                </div>

                <strong>
                  {latestScan.nmap_command || "N/A"}
                </strong>
              </div>
            </div>
          </section>
        )}
      </>
    );
  };

  // =========================================================
  // SIDEBAR
  // =========================================================
  const navigationItems = [
    {
      section: "MONITORING",
      items: [
        { name: "Dashboard", icon: "▦" },
        { name: "Assets", icon: "◉" },
        { name: "Services", icon: "⌘" },
      ],
    },
    {
      section: "SECURITY",
      items: [
        { name: "Vulnerabilities", icon: "△" },
        { name: "Findings", icon: "!" },
        { name: "Scans", icon: "◫" },
      ],
    },
  ];

  // =========================================================
  // MAIN CONTENT
  // =========================================================
  const renderCurrentPage = () => {
    if (activePage === "Dashboard") {
      return renderDashboard();
    }

    if (activePage === "Assets") {
      return renderAssets();
    }

    if (activePage === "Services") {
      return renderServices();
    }

    if (activePage === "Vulnerabilities") {
      return renderVulnerabilities();
    }

    if (activePage === "Findings") {
      return renderFindings();
    }

    if (activePage === "Scans") {
      return renderScans();
    }

    return renderDashboard();
  };

  return (
    <div className="app-shell">

      {/* =====================================================
          SIDEBAR
      ====================================================== */}
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
          {navigationItems.map((group) => (
            <div key={group.section}>
              <div className="nav-section">
                {group.section}
              </div>

              {group.items.map((item) => (
                <button
                  key={item.name}
                  type="button"
                  className={`nav-item ${
                    activePage === item.name ? "active" : ""
                  }`}
                  onClick={() =>
                    handleNavigation(item.name)
                  }
                >
                  <span className="nav-icon">
                    {item.icon}
                  </span>

                  {item.name}
                </button>
              ))}
            </div>
          ))}
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

      {/* =====================================================
          MAIN AREA
      ====================================================== */}
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

            <div className="user-avatar">
              V
            </div>
          </div>
        </header>

        {/* PAGE CONTENT */}
        <main className="dashboard-content">
          {renderCurrentPage()}
        </main>
      </div>
    </div>
  );
}

export default App;