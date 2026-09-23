import { useEffect, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://localhost:8000";

function App() {
  const [summary, setSummary] = useState(null);
  const [riskOverview, setRiskOverview] = useState(null);
  const [recentFindings, setRecentFindings] = useState([]);
  const [severityDistribution, setSeverityDistribution] = useState([]);
  const [statusDistribution, setStatusDistribution] = useState([]);

  const [assets, setAssets] = useState([]);
  const [services, setServices] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  const [loading, setLoading] = useState(true);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [servicesLoading, setServicesLoading] = useState(false);
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] =
    useState(false);

  const [error, setError] = useState("");
  const [assetsError, setAssetsError] = useState("");
  const [servicesError, setServicesError] = useState("");
  const [vulnerabilitiesError, setVulnerabilitiesError] =
    useState("");

  const [activePage, setActivePage] = useState("Dashboard");

  useEffect(() => {
    async function loadDashboard() {
      try {
        setLoading(true);

        const responses = await Promise.all([
          fetch(`${API_BASE_URL}/api/v1/dashboard/summary`),
          fetch(`${API_BASE_URL}/api/v1/dashboard/risk-overview`),
          fetch(
            `${API_BASE_URL}/api/v1/dashboard/recent-findings`
          ),
          fetch(
            `${API_BASE_URL}/api/v1/dashboard/severity-distribution`
          ),
          fetch(
            `${API_BASE_URL}/api/v1/dashboard/status-distribution`
          ),
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
        setAssets([]);
        setAssetsError(
          "Unable to load assets from VulnWatch backend."
        );
      } finally {
        setAssetsLoading(false);
      }
    }

    loadAssets();
  }, []);

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
        setServices([]);
        setServicesError(
          "Unable to load services from VulnWatch backend."
        );
      } finally {
        setServicesLoading(false);
      }
    }

    loadServices();
  }, []);

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
        setVulnerabilities([]);
        setVulnerabilitiesError(
          "Unable to load vulnerabilities from VulnWatch backend."
        );
      } finally {
        setVulnerabilitiesLoading(false);
      }
    }

    loadVulnerabilities();
  }, []);

  const severityClass = (severity) =>
    severity?.toLowerCase() || "unknown";

  const statusClass = (status) =>
    status?.toLowerCase().replace("_", "-") || "unknown";

  const handleNavigation = (page) => {
    setActivePage(page);
  };

  const getUniqueAssets = () => {
    const assetMap = new Map();

    assets.forEach((item) => {
      if (!assetMap.has(item.asset_id)) {
        assetMap.set(item.asset_id, {
          asset_id: item.asset_id,
          target_ip: item.target_ip,
          hostname: item.hostname,
          os: item.os || "Linux",
          services: 0,
          vulnerabilities: 0,
        });
      }

      const asset = assetMap.get(item.asset_id);

      if (item.service_id) {
        asset.services += 1;
      }

      if (item.vulnerability_id) {
        asset.vulnerabilities += 1;
      }
    });

    return Array.from(assetMap.values());
  };

  const renderAssets = () => {
    const uniqueAssets = getUniqueAssets();

    const totalServices = assets.filter(
      (item) => item.service_id
    ).length;

    const totalVulnerabilities = new Set(
      assets
        .filter((item) => item.vulnerability_id)
        .map((item) => item.vulnerability_id)
    ).size;

    return (
      <main className="dashboard-content">
        <section className="hero-section">
          <div>
            <div className="eyebrow">MONITORING</div>

            <h1>Assets</h1>

            <p>
              View and manage infrastructure assets discovered by
              VulnWatch.
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
            <strong>Connection Error</strong>
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
              Assets currently stored in VulnWatch
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">⌁</span>
              <span className="stat-category">DISCOVERY</span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : uniqueAssets.length}
            </div>

            <div className="stat-name">Discovered</div>

            <div className="stat-line">
              Infrastructure discovered through scanning
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">✓</span>
              <span className="stat-category">SERVICES</span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : totalServices}
            </div>

            <div className="stat-name">Services</div>

            <div className="stat-line">
              Services mapped to discovered assets
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">!</span>
              <span className="stat-category">SECURITY</span>
            </div>

            <div className="stat-value">
              {assetsLoading ? "—" : totalVulnerabilities}
            </div>

            <div className="stat-name">Vulnerabilities</div>

            <div className="stat-line">
              Vulnerabilities associated with assets
            </div>
          </div>
        </section>

        <section className="dashboard-card findings-card">
          <div className="card-heading">
            <div>
              <span className="card-label">
                INFRASTRUCTURE INVENTORY
              </span>

              <h2>Discovered Assets</h2>
            </div>

            <div className="finding-total">
              {uniqueAssets.length} assets
            </div>
          </div>

          <div className="table-container">
            {assetsLoading ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  opacity: 0.7,
                }}
              >
                Loading assets...
              </div>
            ) : uniqueAssets.length === 0 ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  opacity: 0.7,
                }}
              >
                No assets found.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>TARGET</th>
                    <th>HOSTNAME</th>
                    <th>OPERATING SYSTEM</th>
                    <th>SERVICES</th>
                    <th>VULNERABILITIES</th>
                  </tr>
                </thead>

                <tbody>
                  {uniqueAssets.map((asset) => (
                    <tr key={asset.asset_id}>
                      <td>
                        <strong>#{asset.asset_id}</strong>
                      </td>

                      <td>
                        <strong>{asset.target_ip}</strong>
                      </td>

                      <td>
                        <div className="finding-name">
                          {asset.hostname || "N/A"}
                        </div>
                      </td>

                      <td>{asset.os}</td>

                      <td>
                        <span className="cve-code">
                          {asset.services}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`severity-badge ${
                            asset.vulnerabilities > 0
                              ? "critical"
                              : "none"
                          }`}
                        >
                          {asset.vulnerabilities}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {!assetsLoading && assets.length > 0 && (
          <section className="dashboard-card findings-card">
            <div className="card-heading">
              <div>
                <span className="card-label">
                  DISCOVERED SERVICES
                </span>

                <h2>Asset Security Details</h2>
              </div>

              <div className="finding-total">
                {assets.length} records
              </div>
            </div>

            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>SERVICE</th>
                    <th>PRODUCT</th>
                    <th>VERSION</th>
                    <th>PORT</th>
                    <th>CVE</th>
                    <th>SEVERITY</th>
                    <th>CVSS</th>
                  </tr>
                </thead>

                <tbody>
                  {assets.map((item, index) => (
                    <tr
                      key={`${item.asset_id}-${item.service_id}-${index}`}
                    >
                      <td>
                        <div className="finding-name">
                          {item.service_name || "N/A"}
                        </div>
                      </td>

                      <td>{item.product || "N/A"}</td>

                      <td>{item.version || "N/A"}</td>

                      <td>
                        {item.port
                          ? `${item.port}/${item.protocol || ""}`
                          : "N/A"}
                      </td>

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
                        <strong className="risk-number-small">
                          {item.cvss_score ?? "N/A"}
                        </strong>
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

  const renderServices = () => {
    const criticalCount = services.filter(
      (item) => item.severity === "CRITICAL"
    ).length;

    const vulnerableServiceCount = services.filter(
      (item) => item.vulnerability_id
    ).length;

    const uniqueTargets = new Set(
      services
        .map((item) => item.target_ip)
        .filter(Boolean)
    ).size;

    return (
      <main className="dashboard-content">
        <section className="hero-section">
          <div>
            <div className="eyebrow">MONITORING</div>

            <h1>Services</h1>

            <p>
              Review network services discovered across monitored
              assets.
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
            <strong>Connection Error</strong>
            <span>{servicesError}</span>
          </div>
        )}

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon blue">⌘</span>
              <span className="stat-category">NETWORK</span>
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
              <span className="stat-icon purple">◉</span>
              <span className="stat-category">TARGETS</span>
            </div>

            <div className="stat-value">
              {servicesLoading ? "—" : uniqueTargets}
            </div>

            <div className="stat-name">Target Assets</div>

            <div className="stat-line">
              Assets associated with discovered services
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon orange">△</span>
              <span className="stat-category">SECURITY</span>
            </div>

            <div className="stat-value">
              {servicesLoading
                ? "—"
                : vulnerableServiceCount}
            </div>

            <div className="stat-name">Vulnerable Services</div>

            <div className="stat-line">
              Services mapped to vulnerabilities
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-top">
              <span className="stat-icon red">!</span>
              <span className="stat-category">CRITICAL</span>
            </div>

            <div className="stat-value">
              {servicesLoading ? "—" : criticalCount}
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
            {servicesLoading ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  opacity: 0.7,
                }}
              >
                Loading services...
              </div>
            ) : services.length === 0 ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  opacity: 0.7,
                }}
              >
                No services found.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>TARGET</th>
                    <th>PORT</th>
                    <th>PROTOCOL</th>
                    <th>SERVICE</th>
                    <th>PRODUCT</th>
                    <th>VERSION</th>
                    <th>CVE</th>
                    <th>SEVERITY</th>
                    <th>CVSS</th>
                  </tr>
                </thead>

                <tbody>
                  {services.map((item, index) => (
                    <tr
                      key={`${item.id || item.service_id}-${index}`}
                    >
                      <td>
                        <strong>
                          {item.target_ip || "N/A"}
                        </strong>
                      </td>

                      <td>{item.port ?? "N/A"}</td>

                      <td>{item.protocol || "N/A"}</td>

                      <td>
                        <div className="finding-name">
                          {item.service_name || "N/A"}
                        </div>
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
                        <strong className="risk-number-small">
                          {item.cvss_score ?? "N/A"}
                        </strong>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </main>
    );
  };

  const renderVulnerabilities = () => {
    const criticalCount = vulnerabilities.filter(
      (item) => item.severity === "CRITICAL"
    ).length;

    const highCount = vulnerabilities.filter(
      (item) => item.severity === "HIGH"
    ).length;

    const mediumCount = vulnerabilities.filter(
      (item) => item.severity === "MEDIUM"
    ).length;

    const averageCvss =
      vulnerabilities.length > 0
        ? (
            vulnerabilities.reduce(
              (total, item) =>
                total + Number(item.cvss_score || 0),
              0
            ) / vulnerabilities.length
          ).toFixed(1)
        : "0.0";

    return (
      <main className="dashboard-content">
        <section className="hero-section">
          <div>
            <div className="eyebrow">SECURITY</div>

            <h1>Vulnerabilities</h1>

            <p>
              Review CVEs, severity, CVSS scores and vulnerability
              metadata collected by VulnWatch.
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
            <strong>Connection Error</strong>
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
              <span className="stat-category">CRITICAL</span>
            </div>

            <div className="stat-value">
              {vulnerabilitiesLoading ? "—" : criticalCount}
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
              {vulnerabilitiesLoading ? "—" : highCount}
            </div>

            <div className="stat-name">High Severity</div>

            <div className="stat-line">
              High severity vulnerabilities
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-top">
              <span className="stat-icon purple">◈</span>
              <span className="stat-category">CVSS</span>
            </div>

            <div className="stat-value">
              {vulnerabilitiesLoading ? "—" : averageCvss}
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
            {vulnerabilitiesLoading ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  opacity: 0.7,
                }}
              >
                Loading vulnerabilities...
              </div>
            ) : vulnerabilities.length === 0 ? (
              <div
                style={{
                  padding: "40px",
                  textAlign: "center",
                  opacity: 0.7,
                }}
              >
                No vulnerabilities found.
              </div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>DESCRIPTION</th>
                    <th>CVSS</th>
                    <th>SEVERITY</th>
                    <th>CWE</th>
                    <th>PUBLISHED</th>
                    <th>LAST MODIFIED</th>
                  </tr>
                </thead>

                <tbody>
                  {vulnerabilities.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <span className="cve-code">
                          {item.cve_id || "N/A"}
                        </span>
                      </td>

                      <td>
                        <div className="finding-name">
                          {item.description || "N/A"}
                        </div>
                      </td>

                      <td>
                        <strong className="risk-number-small">
                          {item.cvss_score ?? "N/A"}
                        </strong>
                      </td>

                      <td>
                        <span
                          className={`severity-badge ${severityClass(
                            item.severity
                          )}`}
                        >
                          {item.severity || "N/A"}
                        </span>
                      </td>

                      <td>
                        <span className="cve-code">
                          {item.cwe || "N/A"}
                        </span>
                      </td>

                      <td>
                        {item.published
                          ? new Date(
                              item.published
                            ).toLocaleDateString()
                          : "N/A"}
                      </td>

                      <td>
                        {item.last_modified
                          ? new Date(
                              item.last_modified
                            ).toLocaleDateString()
                          : "N/A"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {vulnerabilities.length > 0 && (
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
                  key={`details-${item.id}`}
                >
                  <div>
                    <span
                      className={`severity-dot ${severityClass(
                        item.severity
                      )}`}
                    ></span>

                    <span>
                      {item.cve_id || "Unknown CVE"}
                    </span>
                  </div>

                  <strong>
                    CVSS {item.cvss_score ?? "N/A"} ·{" "}
                    {item.cvss_version || "N/A"}
                  </strong>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>
    );
  };

  const renderPlaceholderPage = () => {
    const pageConfig = {
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
              <span className="card-label">
                VULNWATCH MODULE
              </span>

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
              This module is ready for the next implementation
              phase.
            </p>
          </div>
        </section>
      </main>
    );
  };

  const renderDashboard = () => {
    return (
      <main className="dashboard-content">
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
                          {finding.hostname ||
                            "metasploitable"}
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
                          {finding.status?.replace(
                            "_",
                            " "
                          )}
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
            onClick={() =>
              handleNavigation("Vulnerabilities")
            }
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

      <div className="main-area">
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
          : activePage === "Assets"
          ? renderAssets()
          : activePage === "Services"
          ? renderServices()
          : activePage === "Vulnerabilities"
          ? renderVulnerabilities()
          : renderPlaceholderPage()}
      </div>
    </div>
  );
}

export default App;