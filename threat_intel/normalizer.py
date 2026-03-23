import requests
import re
from functools import lru_cache

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def normalize_product(product:str) -> str:
    p = (product or "").strip().lower()
    
    if "apache httpd" in p or p == "apache":
        return "Apache httpd"
    if "openssh" in p:
        return "OpenSSH"
    if "werkzeug" in p:
        return "Werkzeug"
    
    return product.strip()

def extract_version(product: str, version: str, extra_info: str="")->str:
    raw = f"{product}{version}{extra_info}".strip()
    
    openssh_match = re.search(r"(\d+\.\d+p\d+)",raw, re.I)
    if openssh_match:
        return openssh_match.group(1)
    
    generic_match = re.search(r"(\d+(?:\.\d+)(?:p\d+)?)",raw,re.I)
    if generic_match:
        return generic_match.group(1)
    return (version or "").strip()

def build_fingerprint(result: dict) -> dict:
    product = normalize_product(result.get("product",""))
    version = extract_version(
        result.get("product",""),
        result.get("version",""),
        result.get("extra_info","")
    )
    return {
        "service": result.get("service",""),
        "product": product,
        "version": version,
        "port": result.get("port",0),
        "state": result.get("state",""),
        "extra_info": result.get("extra_info","")
    }