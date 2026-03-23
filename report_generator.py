import json
import os
from html import escape


def ensure_output_dir(output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)


def save_json_report(data: dict, filename: str = "report.json", output_dir: str = "output") -> str:
    ensure_output_dir(output_dir)
    path = os.path.join(output_dir, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    return path


def to_html_image_src(screenshot_path: str, output_dir: str = "output") -> str:
    """
    HTML 파일도 output/ 안에 저장된다고 가정하고,
    이미지 경로를 HTML 기준 상대경로로 변환한다.
    예:
      output/capture_a.png -> capture_a.png
      capture_a.png        -> capture_a.png
    """
    if not screenshot_path:
        return ""

    normalized = screenshot_path.replace("\\", "/")
    output_prefix = output_dir.replace("\\", "/").rstrip("/") + "/"

    if normalized.startswith(output_prefix):
        return normalized[len(output_prefix):]

    return os.path.basename(normalized)


def build_summary_html(summary: dict) -> str:
    return f"""
    <div class="summary-box">
        <h2>요약</h2>
        <ul>
            <li><strong>총 서비스 수:</strong> {summary.get("total", 0)}</li>
            <li><strong>위험:</strong> {summary.get("위험", 0)}</li>
            <li><strong>주의:</strong> {summary.get("주의", 0)}</li>
            <li><strong>일반:</strong> {summary.get("일반", 0)}</li>
            <li><strong>알 수 없음:</strong> {summary.get("알 수 없음", 0)}</li>
        </ul>
    </div>
    """


def build_cve_html(cve_candidates: list) -> str:
    if not cve_candidates:
        return "<p>-</p>"

    rows = []

    for cve in cve_candidates[:5]:
        cve_id = escape(str(cve.get("cve_id", "")))
        summary = escape(str(cve.get("summary", "")))
        cvss = escape(str(cve.get("cvss_score", "")))
        epss = escape(str(cve.get("epss_score", "")))
        severity = escape(str(cve.get("severity", "")))
        kev = "예" if cve.get("kev") else "아니오"

        refs = cve.get("references", [])
        if refs:
            ref_html = "<br>".join(
                f'<a href="{escape(str(ref))}" target="_blank">{escape(str(ref))}</a>'
                for ref in refs[:3]
            )
        else:
            ref_html = "-"

        rows.append(f"""
        <tr>
            <td>{cve_id}</td>
            <td>{severity}</td>
            <td>{cvss}</td>
            <td>{epss}</td>
            <td>{kev}</td>
            <td>{summary}</td>
            <td>{ref_html}</td>
        </tr>
        """)

    return f"""
    <table class="cve-table">
        <thead>
            <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>설명</th>
                <th>참고 링크</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def build_capture_map(captures: list) -> dict:
    capture_map = {}
    for capture in captures:
        port = capture.get("port")
        screenshot_path = capture.get("screenshot_path", "")
        capture_map[port] = screenshot_path
    return capture_map


def build_results_html(results: list, captures: list, output_dir: str = "output") -> str:
    capture_map = build_capture_map(captures)
    cards = []

    for result in results:
        port = result.get("port", "")
        state = escape(str(result.get("state", "")))
        service = escape(str(result.get("service", "")))
        product = escape(str(result.get("product", "")))
        version = escape(str(result.get("version", "")))
        extra_info = escape(str(result.get("extra_info", "")))

        rule_risk = escape(str(result.get("risk_level", "")))
        final_risk = escape(str(result.get("final_risk_level", rule_risk)))
        final_score = escape(str(result.get("final_risk_score", "")))
        reason = escape(str(result.get("reason", "")))

        normalized_product = escape(str(result.get("normalized_product", "")))
        normalized_version = escape(str(result.get("normalized_version", "")))

        cpe_candidates = result.get("cpe_candidates", [])
        cpe_html = "<br>".join(escape(str(cpe)) for cpe in cpe_candidates) if cpe_candidates else "-"

        cve_candidates = result.get("cve_candidates", [])
        cve_count = len(cve_candidates)
        cve_html = build_cve_html(cve_candidates)

        screenshot_path = capture_map.get(port)
        screenshot_html = ""

        if screenshot_path:
            html_src = to_html_image_src(screenshot_path, output_dir=output_dir)
            safe_src = escape(html_src)
            safe_original_path = escape(str(screenshot_path))

            screenshot_html = f"""
            <div class="capture-box">
                <h4>웹 캡처</h4>
                <p>저장 경로: {safe_original_path}</p>
                <img src="{safe_src}" alt="capture_port_{port}">
            </div>
            """

        cards.append(f"""
        <div class="result-card">
            <h3>포트 {port}</h3>
            <table class="info-table">
                <tr><th>상태</th><td>{state}</td></tr>
                <tr><th>서비스</th><td>{service}</td></tr>
                <tr><th>제품</th><td>{product}</td></tr>
                <tr><th>버전</th><td>{version}</td></tr>
                <tr><th>추가 정보</th><td>{extra_info}</td></tr>
                <tr><th>규칙 기반 위험도</th><td>{rule_risk}</td></tr>
                <tr><th>최종 위험도</th><td>{final_risk}</td></tr>
                <tr><th>최종 점수</th><td>{final_score}</td></tr>
                <tr><th>정규화 제품명</th><td>{normalized_product}</td></tr>
                <tr><th>정규화 버전</th><td>{normalized_version}</td></tr>
                <tr><th>CPE 후보</th><td>{cpe_html}</td></tr>
                <tr><th>CVE 개수</th><td>{cve_count}</td></tr>
                <tr><th>판단 이유</th><td>{reason}</td></tr>
            </table>

            <div class="cve-section">
                <h4>CVE 분석 결과</h4>
                {cve_html}
            </div>

            {screenshot_html}
        </div>
        """)

    return "\n".join(cards)


def build_html_report(data: dict, output_dir: str = "output") -> str:
    target_ip = escape(str(data.get("target_ip", "")))
    summary_html = build_summary_html(data.get("summary", {}))
    results_html = build_results_html(
        data.get("results", []),
        data.get("captures", []),
        output_dir=output_dir
    )

    return f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>위협 분석 리포트 - {target_ip}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background-color: #f7f7f7;
            color: #222;
        }}
        h1 {{
            color: #1d3557;
        }}
        .summary-box, .result-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .info-table, .cve-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            margin-bottom: 16px;
        }}
        .info-table th, .info-table td,
        .cve-table th, .cve-table td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}
        .info-table th, .cve-table th {{
            background-color: #f0f4f8;
            width: 180px;
        }}
        .capture-box img {{
            max-width: 100%;
            border: 1px solid #ccc;
            border-radius: 6px;
            margin-top: 8px;
        }}
        .cve-section {{
            margin-top: 20px;
        }}
        a {{
            color: #1d4ed8;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <h1>위협 분석 리포트</h1>
    <p><strong>대상 IP:</strong> {target_ip}</p>
    {summary_html}
    <h2>서비스별 상세 분석</h2>
    {results_html}
</body>
</html>
    """


def save_html_report(data: dict, filename: str = "report.html", output_dir: str = "output") -> str:
    ensure_output_dir(output_dir)
    html = build_html_report(data, output_dir=output_dir)
    path = os.path.join(output_dir, filename)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path