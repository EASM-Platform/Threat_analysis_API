import requests
from functools import lru_cache

EPSS_API = "https://api.first.org/data/v1/epss"

@lru_cache(maxsize=1024)
def query_epss(cve_id: str) -> dict:
    response = requests.get(EPSS_API, params={"cve": cve_id}, timeout=10)
    response.raise_for_status()
    data = response.json()

    rows = data.get("data", [])
    if not rows:
        return {
            "epss_score": None,
            "epss_percentile": None
        }

    row = rows[0]

    return {
        "epss_score": float(row["epss"]) if row.get("epss") else None,
        "epss_percentile": float(row["percentile"]) if row.get("percentile") else None
    }