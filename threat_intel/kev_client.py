import requests
from functools import lru_cache

CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@lru_cache(maxsize=1)
def load_kev_catalog() -> dict:
    response = requests.get(CISA_KEV_JSON, timeout=20)
    response.raise_for_status()
    return response.json()


def is_known_exploited(cve_id: str) -> bool:
    try:
        kev_data = load_kev_catalog()
        vulnerabilities = kev_data.get("vulnerabilities", [])

        for item in vulnerabilities:
            if item.get("cveID") == cve_id:
                return True
    except Exception:
        pass

    return False