def calculate_final_risk(rule_risk_level: str, cve_candidates: list[dict], port: int) -> float:
    score = 0.0

    if rule_risk_level == "위험":
        score += 4.0
    elif rule_risk_level == "주의":
        score += 2.5
    elif rule_risk_level == "일반":
        score += 1.0

    for cve in cve_candidates:
        cvss = cve.get("cvss_score") or 0.0
        epss = cve.get("epss_score") or 0.0
        kev_bonus = 2.0 if cve.get("kev") else 0.0

        score += cvss * 0.35
        score += epss * 3.5
        score += kev_bonus

    if port in [21, 22, 23, 135, 139, 445, 3389]:
        score += 1.0
    elif port in [80, 443, 8000, 8080, 8443]:
        score += 0.5

    return round(score, 2)


def score_to_level(score: float) -> str:
    if score >= 8:
        return "위험"
    if score >= 5:
        return "주의"
    if score >= 2:
        return "일반"
    return "알 수 없음"