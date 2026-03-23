from port_scanner import (
    scan_ports,
    get_open_ports,
    convert_resolved_target_to_ip_list
)
from resolver import resolve_target
from nmap_scanner import run_nmap_scan, parse_nmap_results
from threat_intel import analyze_all_results, build_final_summary
from report_generator import save_json_report, save_html_report


def apply_rule_based_risk(results: list[dict]) -> list[dict]:
    for result in results:
        service = result.get("service", "").lower()
        port = result.get("port", 0)

        if service in ["telnet"]:
            result["risk_level"] = "위험"
            result["reason"] = "Telnet은 평문 인증을 사용하므로 매우 위험합니다."

        elif service in ["rpcbind", "netbios-ssn", "microsoft-ds"]:
            result["risk_level"] = "주의"
            result["reason"] = "외부 노출 시 내부 서비스 정보 노출 또는 공격 표면 확대 가능성이 있어 주의가 필요합니다."

        elif service == "tcpwrapped":
            result["risk_level"] = "알 수 없음"
            result["reason"] = "서비스가 접근 제어나 래핑으로 보호되어 있어 정확한 식별이 어렵습니다."

        elif port in [80, 443, 8000, 8080, 8443]:
            result["risk_level"] = "일반"
            result["reason"] = "일반적인 웹 서비스입니다."

        elif port == 22:
            result["risk_level"] = "일반"
            result["reason"] = "일반적인 원격 관리 서비스입니다."

        else:
            result["risk_level"] = "일반"
            result["reason"] = "기본적으로 일반 수준의 서비스로 분류했습니다."

    return results


def main():
    target = input("타겟 IP / 도메인 / CIDR 입력: ").strip()
    ports = [22, 80, 111, 139, 445, 2042, 8000]

    resolved = resolve_target(target)
    if resolved is None:
        print("[!] 잘못된 입력입니다. IP, 도메인, CIDR 중 하나를 입력하세요.")
        return

    ip_list = convert_resolved_target_to_ip_list(resolved)
    if not ip_list:
        print("[!] 스캔할 IP가 없습니다.")
        return

    for target_ip in ip_list:
        print(f"\n[+] 스캔 대상: {target_ip}")

        # 1. 포트 스캔
        scan_results = scan_ports(target_ip, ports)
        open_ports = get_open_ports(scan_results)

        print(f"[+] 열린 포트: {open_ports}")

        if not open_ports:
            print("[!] 열린 포트가 없습니다.")
            continue

        # 2. Nmap 분석
        scanner = run_nmap_scan(target_ip, open_ports)
        nmap_results = parse_nmap_results(scanner, target_ip)

        # 3. 규칙 기반 위험도
        risk_results = apply_rule_based_risk(nmap_results)

        # 4. 외부 API 기반 위협 분석
        analyzed_results = analyze_all_results(risk_results)

        # 5. 최종 summary
        summary = build_final_summary(analyzed_results)

        # 6. 캡처 결과 (현재는 예시)
        captures = []

        # 7. 최종 출력 데이터
        output_data = {
            "target_ip": target_ip,
            "summary": summary,
            "results": analyzed_results,
            "captures": captures
        }

        # 8. 저장
        safe_name = target_ip.replace(".", "_").replace("/", "_")
        json_path = save_json_report(
            output_data,
            filename=f"threat_report_{safe_name}.json",
            output_dir="output"
        )
        html_path = save_html_report(
            output_data,
            filename=f"threat_report_{safe_name}.html",
            output_dir="output"
        )

        print(f"[+] JSON 저장 완료: {json_path}")
        print(f"[+] HTML 저장 완료: {html_path}")


if __name__ == "__main__":
    main()