from threat_intel.normalizer import build_fingerprint
from threat_intel.cpe_builder import build_cpe_candidates
from threat_intel.nvd_client import query_cves_by_cpe
from threat_intel.epss_client import query_epss
from threat_intel.kev_client import is_known_exploited
from threat_intel.scorer import calculate_final_risk, score_to_level


def analyze_single_result(result: dict) -> dict:
    fingerprint = build_fingerprint(result)

    product = fingerprint["product"]
    version = fingerprint["version"]
    port = fingerprint["port"]

    cpe_candidates = build_cpe_candidates(product, version)

    merged_cves = []
    seen = set()

    for cpe in cpe_candidates:
        try:
            cves = query_cves_by_cpe(cpe)
        except Exception as e:
            print(f"[NVD 조회 실패] CPE={cpe}, 오류={e}")
            cves = []

        for cve in cves:
            cve_id = cve["cve_id"]

            if cve_id in seen:
                continue
            seen.add(cve_id)

            try:
                epss_info = query_epss(cve_id)
            except Exception as e:
                print(f"[EPSS 조회 실패] CVE={cve_id}, 오류={e}")
                epss_info = {
                    "epss_score": None,
                    "epss_percentile": None
                }

            kev = is_known_exploited(cve_id)

            merged = dict(cve)
            merged.update(epss_info)
            merged["kev"] = kev

            merged_cves.append(merged)

    final_risk_score = calculate_final_risk(
        result.get("risk_level", "알 수 없음"),
        merged_cves,
        port
    )

    final_risk_level = score_to_level(final_risk_score)

    enriched = dict(result)
    enriched["normalized_product"] = product
    enriched["normalized_version"] = version
    enriched["cpe_candidates"] = cpe_candidates
    enriched["cve_candidates"] = merged_cves
    enriched["final_risk_score"] = final_risk_score
    enriched["final_risk_level"] = final_risk_level

    if merged_cves:
        enriched["reason"] = enriched.get("reason", "") + " 외부 취약점 API 분석 결과 관련 CVE가 확인되었습니다."

    return enriched


def analyze_all_results(results: list[dict]) -> list[dict]:
    analyzed = []

    for result in results:
        enriched = analyze_single_result(result)
        analyzed.append(enriched)

    return analyzed


def build_final_summary(results: list[dict]) -> dict:
    summary = {
        "total": len(results),
        "위험": 0,
        "주의": 0,
        "일반": 0,
        "알 수 없음": 0
    }

    for result in results:
        level = result.get("final_risk_level", "알 수 없음")
        if level not in summary:
            summary[level] = 0
        summary[level] += 1

    return summary