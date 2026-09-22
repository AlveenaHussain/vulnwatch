"""
VulnWatch NVD collector.

Flow (API-only; never touches PostgreSQL or NVD from the backend):
    1. GET services from the VulnWatch backend.
    2. For each service with a versioned CPE:
         a. Convert the Nmap CPE (2.2 or 2.3) to a CPE 2.3 string.
         b. Build a VENDOR-WILDCARD virtualMatchString (vendor = *, product and
            version pinned). This lets a single CVE API call catch CVEs no matter
            which vendor string NVD used in the CVE's own configuration -- older
            CVEs often use a different vendor than the current CPE dictionary
            (e.g. vsftpd vs vsftpd_project), so a single canonical CPE would miss
            them. The wildcard is "any vendor", not a guess.
         c. Query the CVE API (/rest/json/cves/2.0, virtualMatchString).
         d. Parse CVEs (CVSS 3.1 -> 3.0 -> 2.0, CWE).
    3. POST all findings to the VulnWatch import endpoint (X-API-Key).

Run from the project root:  python collectors\\nvd\\nvd_collector.py
"""

import logging
import os
import sys
import time
from collections import defaultdict

import requests
from dotenv import load_dotenv

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REQUEST_TIMEOUT = 30          # seconds per HTTP request
NVD_DELAY = 0.8               # seconds between NVD calls (50 req / 30s with a key)
MAX_RETRIES = 4              # for 429 / 503 / network errors
RETRY_BASE = 2               # exponential backoff base (2s, 4s, 8s, ...)
CVE_PAGE = 2000              # NVD CVE page size (max 2000)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("nvd_collector")


def load_config() -> dict:
    """Load required settings from .env. Fail closed if anything is missing."""
    here = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(here, "..", ".."))
    load_dotenv(os.path.join(project_root, ".env"))

    cfg = {
        "nvd_api_key": os.getenv("NVD_API_KEY"),
        "vulnwatch_api_key": os.getenv("VULNWATCH_API_KEY"),
        "backend_url": os.getenv("VULNWATCH_BACKEND_URL", "http://127.0.0.1:8000"),
    }
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        logger.error("Missing required settings in .env: %s", ", ".join(missing))
        sys.exit(1)
    return cfg


# --------------------------------------------------------------------------
# Backend: fetch services
# --------------------------------------------------------------------------
def fetch_services(cfg: dict) -> list[dict]:
    """
    Get all discovered services from the VulnWatch backend.
    Accepts a bare list or a wrapper object (services/items/data/results).
    """
    resp = requests.get(
        f"{cfg['backend_url']}/api/v1/services",
        headers={"X-API-Key": cfg["vulnwatch_api_key"]},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, list):
        services = data
    elif isinstance(data, dict):
        for key in ("services", "items", "data", "results"):
            value = data.get(key)
            if isinstance(value, list):
                services = value
                break
        else:
            raise ValueError(
                f"Unexpected /services response shape; keys={list(data.keys())}"
            )
    else:
        raise ValueError(f"Unexpected /services response type: {type(data)}")

    return [s for s in services if isinstance(s, dict)]


# --------------------------------------------------------------------------
# CPE handling
# --------------------------------------------------------------------------
def cpe22_to_cpe23(cpe: str) -> str | None:
    """Normalise a CPE 2.2 URI or 2.3 string to a CPE 2.3 formatted string."""
    if not cpe:
        return None
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return None
    body = cpe[len("cpe:/"):]
    tokens = body.split(":")
    if not tokens or tokens[0] not in ("a", "o", "h"):
        return None
    while len(tokens) < 7:            # part..language
        tokens.append("*")
    tokens += ["*"] * (11 - len(tokens))
    tokens = [t if t else "*" for t in tokens[:11]]
    return "cpe:2.3:" + ":".join(tokens)


def cpe_components(cpe23: str) -> tuple[str, str, str, str] | None:
    """Return (part, vendor, product, version) from a CPE 2.3 string."""
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[2], parts[3], parts[4], parts[5]


def is_versionless(cpe23: str) -> bool:
    """True if the CPE has no concrete version (version is *, - or empty)."""
    comps = cpe_components(cpe23)
    if comps is None:
        return True
    return comps[3] in ("*", "-", "")


def vendor_wildcard_cpe(cpe23: str) -> str | None:
    """
    Build a vendor-wildcard CPE 2.3 string: part and product/version pinned,
    vendor = * so CVEs are matched regardless of the vendor NVD recorded.
    """
    comps = cpe_components(cpe23)
    if comps is None:
        return None
    part, _vendor, product, version = comps
    if not product or product in ("*", "-"):
        return None
    return f"cpe:2.3:{part}:*:{product}:{version}:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------
# NVD HTTP with retry / backoff / pagination
# --------------------------------------------------------------------------
def nvd_get(url: str, params: dict, api_key: str) -> dict | None:
    """One NVD GET with retry on 429/503/network errors. Returns JSON or None."""
    headers = {"apiKey": api_key, "User-Agent": "VulnWatch/0.1"}
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(
                url, params=params, headers=headers, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            wait = RETRY_BASE ** attempt
            logger.warning("Network error (%s); retrying in %ss", exc, wait)
            time.sleep(wait)
            continue

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (429, 503):
            retry_after = resp.headers.get("Retry-After")
            wait = int(retry_after) if retry_after and retry_after.isdigit() \
                else RETRY_BASE ** attempt
            logger.warning("NVD %s; retrying in %ss", resp.status_code, wait)
            time.sleep(wait)
            continue
        logger.error("NVD returned %s for params=%s", resp.status_code, params)
        return None

    logger.error("NVD giving up after %s retries for params=%s", MAX_RETRIES, params)
    return None


def query_cves(match_cpe: str, api_key: str) -> list[dict]:
    """Fetch all CVEs for a vendor-wildcard CPE, following pagination."""
    results = []
    start = 0
    while True:
        time.sleep(NVD_DELAY)
        data = nvd_get(
            NVD_CVE_URL,
            {
                "virtualMatchString": match_cpe,
                "startIndex": start,
                "resultsPerPage": CVE_PAGE,
            },
            api_key,
        )
        if not data:
            break
        results.extend(data.get("vulnerabilities", []))
        total = data.get("totalResults", 0)
        start += CVE_PAGE
        if start >= total:
            break
    return results


# --------------------------------------------------------------------------
# CVE parsing
# --------------------------------------------------------------------------
def pick_cvss(metrics: dict) -> tuple[str | None, float | None, str | None]:
    """Return (version, score, vector) preferring CVSS 3.1 -> 3.0 -> 2.0."""
    for key, ver in (("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"),
                     ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return ver, data.get("baseScore"), data.get("vectorString")
    return None, None, None


def pick_cwe(weaknesses: list) -> str | None:
    """Return the first concrete CWE id, skipping NVD placeholders."""
    for weakness in weaknesses or []:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                return value
    return None


def parse_cve(item: dict) -> dict | None:
    """Turn one NVD CVE item into the payload shape. None if unusable."""
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    version, score, vector = pick_cvss(cve.get("metrics", {}))
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_version": version,
        "cvss_score": score,
        "cvss_vector": vector,
        "cwe": pick_cwe(cve.get("weaknesses", [])),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


# --------------------------------------------------------------------------
# Submit to VulnWatch
# --------------------------------------------------------------------------
def submit_findings(cfg: dict, findings: list[dict]) -> dict:
    """POST findings to the vulnerability import endpoint."""
    resp = requests.post(
        f"{cfg['backend_url']}/api/v1/vulnerabilities/import",
        headers={"X-API-Key": cfg["vulnwatch_api_key"]},
        json={"source": "nvd", "findings": findings},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    cfg = load_config()
    counters = defaultdict(int)

    services = fetch_services(cfg)
    counters["services_received"] = len(services)

    # Group services by the vendor-wildcard CPE so each is queried once.
    match_to_targets: dict[str, list[dict]] = defaultdict(list)
    for svc in services:
        cpe23 = cpe22_to_cpe23(svc.get("cpe") or "")
        if cpe23 is None:
            counters["skipped_invalid"] += 1
            continue
        if is_versionless(cpe23):
            counters["skipped_versionless"] += 1
            continue
        match_cpe = vendor_wildcard_cpe(cpe23)
        if match_cpe is None:
            counters["skipped_invalid"] += 1
            continue
        match_to_targets[match_cpe].append(svc)

    findings = []
    for match_cpe, targets in match_to_targets.items():
        raw_cves = query_cves(match_cpe, cfg["nvd_api_key"])
        vulns = [v for v in (parse_cve(c) for c in raw_cves) if v]
        if not vulns:
            counters["no_matches"] += 1
            logger.info("No CVEs for %s", match_cpe)
            continue
        counters["cpes_matched"] += 1
        counters["cve_enrichment"] += len(vulns)

        for svc in targets:
            findings.append({
                "target_ip": svc.get("target_ip"),
                "port": svc.get("port"),
                "protocol": svc.get("protocol"),
                "matched_cpe": match_cpe,  # the vendor-wildcard CPE actually queried
                "vulnerabilities": vulns,
            })

    logger.info(
        "services=%d invalid=%d versionless=%d matched=%d no_match=%d cves=%d",
        counters["services_received"], counters["skipped_invalid"],
        counters["skipped_versionless"], counters["cpes_matched"],
        counters["no_matches"], counters["cve_enrichment"],
    )

    if not findings:
        logger.info("No findings to import.")
        return

    result = submit_findings(cfg, findings)
    logger.info("Import result: %s", result)


if __name__ == "__main__":
    main()
