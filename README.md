# XDP 패킷 캡처 프로그램

XDP(eXpress Data Path)를 이용해서 고성능으로 네트워크 패킷을 캡처하고 pcap 파일로 저장하는 프로그램입니다.

## 빌드 방법

```bash
make
```

## 사용 방법

```bash
sudo ./capture_main <interface> <output_file.pcap>
```

### 예시

```bash
# ens20 인터페이스에서 패킷 캡처하여 capture.pcap 파일로 저장
sudo ./capture_main ens20 capture.pcap

# 10초 동안만 캡처
sudo timeout 10 ./capture_main ens20 short_capture.pcap
```

## 구성 요소

1. **xdp_capture.c**: XDP 프로그램 (eBPF 커널 코드)
   - 패킷을 받아서 링버퍼를 통해 userspace로 전달
   - 패킷 통계 수집 (수신, 캡처, 드롭, 에러)

2. **capture_main.c**: 사용자 공간 프로그램
   - XDP 프로그램을 커널에 로드
   - 네트워크 인터페이스에 XDP 프로그램 연결
   - 링버퍼에서 패킷 데이터 읽기
   - pcap 파일 형식으로 저장

3. **Makefile**: 빌드 스크립트
   - XDP 프로그램과 userspace 프로그램 컴파일

## 필요 조건

- Linux 커널 (XDP 및 링버퍼 지원)
- clang
- libbpf 개발 라이브러리
- root 권한 (XDP 프로그램 로드용)

## 기능

- **고성능**: XDP를 사용한 커널 바이패스로 빠른 패킷 처리
- **실시간 저장**: 패킷을 실시간으로 pcap 파일에 저장
- **통계 정보**: 패킷 수신/캡처/드롭 통계 실시간 출력
- **표준 형식**: Wireshark 등에서 분석 가능한 pcap 형식
- **대용량 패킷 지원**: 최대 512바이트까지 패킷 캡처 (대부분의 네트워크 패킷 완전 커버)

## 주의사항

- 프로그램 실행시 sudo 권한이 필요합니다
- 종료할 때는 Ctrl+C를 누르면 XDP 프로그램이 자동으로 제거됩니다
- 존재하지 않는 네트워크 인터페이스를 지정하면 오류가 발생합니다
- 캡처된 pcap 파일은 tcpdump, Wireshark 등으로 분석할 수 있습니다

## 테스트

```bash
# 테스트 스크립트 실행
./test_capture.sh
```

## 사용 예시

```bash
# 패킷 캡처 시작
sudo ./capture_main ens20 my_capture.pcap

# 다른 터미널에서 트래픽 생성
ping -c 10 google.com

# pcap 파일 분석
tcpdump -r my_capture.pcap -n
```