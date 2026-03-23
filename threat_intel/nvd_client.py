import requests
from functools import lru_cache

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

@lru_cache(maxsize=512)
def query_cves_by_cpe(cpe_name: str) -> list[dict]:
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": 20
    }

    response = requests.get(NVD_CVE_API, params=params, timeout=15)
    response.raise_for_status()
    data = response.json()

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None

        if metrics.get("cvssMetricV31"):
            metric = metrics["cvssMetricV31"][0]
            cvss_score = metric.get("cvssData", {}).get("baseScore")
            severity = metric.get("cvssData", {}).get("baseSeverity")
        elif metrics.get("cvssMetricV30"):
            metric = metrics["cvssMetricV30"][0]
            cvss_score = metric.get("cvssData", {}).get("baseScore")
            severity = metric.get("cvssData", {}).get("baseSeverity")

        references = []
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)

        results.append({
            "cve_id": cve_id,
            "summary": summary,
            "cvss_score": cvss_score,
            "severity": severity,
            "references": references
        })

    return results