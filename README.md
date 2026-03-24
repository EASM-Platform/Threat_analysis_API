# Vulnerability_Analysis_API
입력된 타깃에 대해 포트와 서비스 지문을 수집하고, 외부 취약점 인텔리전스를 결합해 위험도를 산정한 뒤, 이를 JSON/HTML 보고서로 출력하는 모듈형 EASM/취약점 분석 파이프라인이다.</br>
1. 스캔
2. 식별
3. 위협 인텔 결합
4. 점수화
5. 리포트 생성
</br>
전체적으로 main.py가 오케스트레이터 역할을 하고, 나머지 파일들은 각 단계별 기능 모듈로 분리되어있다. </br>
main.py는 포트스캔, Nmap분석, 규칙기반 위험도 부여, 외부 취약점 분석, 요약 생성, JSON/HTML 저장까지 한 흐름으로 호출한다.</br>
</br>

## 입력 해석 계층 : resolver.py
resolver.py는 사용자가 넣은 값이 </br>
- 단일 IP인지
- 도메인인지
- CIDR 대역인지
를 구분하고, 스캔 가능한 IP형태로 바꿔주는 역할을 한다. </br>
resolve_target()이 이 분기 처리를 담당하고, CIDR이면 여러 IP로 확장하고, 도메인이면 실제 IP로 해석한다.</br>
즉, 이 계층은 입력 정규화 계층이라고 보면 된다.</br>

## 1차 스캐닝 계층 : port_scanner.pt
이 파일은 가장 기초적인 TCP 연결 기반 포트 스캐너이다. </br>
- scan_port(ip, port)가 단일 포트를 검사하고</br>
- scan_ports(ip, ports)가 여러 포트를 순회하고</br>
- get_open_ports(results)가 열린 포트만 추려냄 </br>

즉, 이 계층은 어느 포트가 살아있는가?를 빠르게 걸러내는 것이다.</br>


## 2차 식별 계층 : nmap_scanner.py
nmap_scanner.py는 열린 포트에 대해 Nmap -sV를 써서 서비스 식별을 수행한다.</br>
run_nmap_scan()에서 열린 포트 목록을 문자열로 묶어서 Nmap에 넘기고, </br> parse_nmap_results()에서 포트별 상태, 서비스명, 제품명, 버전, 추가 정보를 뽑아낸다.
</br> 단순히 80 open만 아는게 아니고, 이 포트가 http인지, 제품이 Apache, nginx, OpenSSH인지, 버전이 무엇인지 등등을 확보한다.</br> 따라서 이 계층은 포트 수준 정보가 서비스 지문 수준 정보로 승격되는 것이다.

## 규칙 기반 1차 판정 : main.py의 appy_rule_based_risk()
Nmap 결과가 나오면 main.py 안에서 1차 위험도 규칙을 적용하게 된다.</br>
예를 들면:</br>
telnet이면 위험</br>
rpcbind, netbios-ssn, microsoft-ds면 주의</br>
tcpwrapped는 알 수 없음</br>
80/443/8000 같은 웹 포트는 일반</br>
22는 일반</br></br>

이런 식으로 서비스와 포트를 기준으로 빠른 초기 판정을 내린다.</br>

## 위협 인텔 패키지 : threat_intel/

### analyzer.py
analyzer.py는 각 서비스 결과 하나씩 받아서 위협 정보를 붙여 주는 오케스트레이터야.</br></br>

동작 순서:</br>

build_fingerprint(result)로 제품/버전 정규화</br>
build_cpe_candidates(product, version)로 CPE 후보 생성</br>
각 CPE 후보에 대해 NVD에서 CVE 조회</br>
각 CVE에 대해 EPSS 조회</br>
각 CVE가 KEV인지 확인</br>
이 정보를 합쳐 최종 점수 계산</br>
결과 객체에 normalized_product, cpe_candidates, cve_candidates, final_risk_score, final_risk_level 등을 붙임 </br>
즉 analyzer.py는 서비스 정보와 외부 위협 인텔을 결합하는 허브임</br>

### normalizer.py
여기는 Nmap이 준 제품명/버전 문자열을 정리해 주는 역할을 한다.</br>
예를 들어 Apache httpd, OpenSSH, Werkzeug 같은 이름을 통일하고, 버전 문자열도 정규식으로 추출해서 후속 처리하기 좋게 만든다.</br> 마지막에 build_fingerprint()가 서비스, 제품, 버전, 포트, 상태, extra_info를 하나의 fingerprint 딕셔너리로 만든다.</br>
즉, 이 단계는 비정형 배너 문자열을 표준화된 분석 입력으로 바꾸는 역할임</br>
### cpe_builder.py
여기는 정규화된 제품명과 버전을 가지고 NVD 조회용 CPE 문자열을 만든다.</br>
예를 들어 Apache는 apache:http_server, OpenSSH는 openbsd:openssh, nginx는 nginx:nginx 식으로 CPE 후보를 생성</br>

### nvd_client.py

이 파일은 NVD CVE API를 호출해서 CPE에 해당하는 CVE 목록을 가져오는 계층이야.</br> 반환 항목에는 CVE ID, 설명, CVSS 점수, 심각도, 참고 링크 등이 들어가도록 구성돼있음</br>

### epss_client.py
이 파일은 FIRST의 EPSS API를 호출해서 각 CVE의 실제 악용 가능성 점수와 percentile을 가져온다.</br> 반환값은 epss_score, epss_percentile 형태</br>

즉 CVSS가 “심각도”에 가깝다면, EPSS는 “현실적으로 악용될 가능성”을 더 보강하는 지표</br>

### kev_client.py

이 파일은 CISA KEV 카탈로그를 불러와서 특정 CVE가 실제로 알려진 악용 목록에 포함되는지 확인한다.</br> is_known_exploited(cve_id)가 True/False를 반환</br>
즉 이 단계는 **“이 취약점이 실제 공격에서 쓰였나?”**를 판별하는 역할</br>

### scorer.py

여기는 최종 점수화 계층이야.
초기 룰 기반 위험도에 가중치를 주고, 각 CVE의 CVSS, EPSS, KEV 여부를 더한 다음, 포트 종류에 따라 추가 점수를 준다.</br> 그리고 score_to_level()로 수치 점수를 위험/주의/일반/알 수 없음으로 바꾼다.</br>
즉 여기는 정성적 판단과 정량적 위협 지표를 합산해 최종 위험도로 환산하는 엔진</br>

## 결과 집계 계층 : build_final_summary()
analyzer.py 안의 build_final_summary()는 전체 결과를 보고 위험, 주의, 일반, 알 수 없음 개수를 세어서 요약 딕셔너리를 만든다.</br>

이 단계는 대시보드 상단이나 보고서 요약 박스에 들어갈 숫자를 만든다.</br>

## 출력 계층 : report_generator.py
이 파일은 분석 결과를 사람이 읽을 수 있는 보고서 형태로 바꾼다.

save_json_report()는 원본 결과를 JSON으로 저장</br>
build_summary_html()는 요약 영역 생성</br>
build_results_html()는 포트별 카드 생성</br>
build_cve_html()는 CVE 표 생성</br>
build_html_report()는 최종 HTML 문서 생성</br>

즉 이 모듈은 분석 데이터의 프레젠테이션 계층이다.</br>
결과적으로 사용자는 output/ 폴더 안에서 JSON과 HTML을 확인하게 된다.</br> main.py도 실제로 output에 JSON/HTML을 저장