import socket
from resolver import resolve_target


def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return "open"
        else:
            return "closed"

    except Exception as e:
        print(f"오류 발생 - IP: {ip}, 포트: {port}, 오류: {e}")
        return "error"


def scan_ports(ip, ports):
    results = []

    for port in ports:
        status = scan_port(ip, port)
        results.append({
            "port": port,
            "status": status
        })

    return results


def get_open_ports(results):
    open_ports = []

    for result in results:
        if result["status"] == "open":
            open_ports.append(result["port"])

    return open_ports


def convert_resolved_target_to_ip_list(resolved_result):
    if resolved_result is None:
        return []

    target_type = resolved_result["target_type"]

    if target_type == "ip":
        return [resolved_result["resolved_ip"]]

    if target_type == "domain":
        return [resolved_result["resolved_ip"]]

    if target_type == "cidr":
        return resolved_result["resolved_ips"]

    return []


if __name__ == "__main__":
    target = input("IP, 도메인, CIDR 입력: ").strip()
    test_ports = [22, 80, 443, 3306, 8000, 8080]

    resolved = resolve_target(target)

    if resolved is None:
        print("잘못된 입력입니다. IP, 도메인, CIDR 중 하나를 입력하세요.")
    else:
        print("\n[입력 해석 결과]")
        print(resolved)

        ip_list = convert_resolved_target_to_ip_list(resolved)

        if not ip_list:
            print("스캔할 IP가 없습니다.")
        else:
            print("\n[스캔 시작]")
            for ip in ip_list:
                print(f"\n스캔 대상: {ip}")

                results = scan_ports(ip, test_ports)

                for result in results:
                    print(f"포트 {result['port']}: {result['status']}")

                open_ports = get_open_ports(results)
                print(f"열린 포트 목록: {open_ports}")