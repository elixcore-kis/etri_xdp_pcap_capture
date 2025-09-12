# XDP Packet Capture Development Notes

## 개발 히스토리

### 초기 목표
- XDP를 이용한 packet clone-redirect 기능 (ens20 → ens19)
- C 언어 기반 구현

### 방향 전환
- 사용자 요청으로 packet capture 기능으로 전환
- pcap 파일 형식으로 패킷 저장하는 방식으로 변경

## 주요 기술적 도전과 해결

### 1. BPF Verifier 문제
**문제**: `invalid access to packet, off=14 size=1` 에러
**원인**: `bpf_probe_read_kernel()` 사용으로 인한 BPF verifier 거부
**해결**: 직접 메모리 접근 방식으로 변경, 바이트 단위 bounds checking

### 2. 패킷 데이터 손실
**문제**: Wireshark에서 모든 패킷 데이터가 0으로 표시
**원인**: 잘못된 패킷 복사 메커니즘
**해결**: BPF verifier 호환 직접 메모리 복사 구현

### 3. 패킷 크기 최적화
**진화**: 64 바이트 → 128 바이트 → 512 바이트
**최종**: 대부분의 네트워크 패킷을 완전히 커버하는 512 바이트

## 최종 구현 결과

### 성공적으로 구현된 기능
- ✅ XDP 기반 고성능 패킷 캡처
- ✅ 실시간 pcap 파일 저장
- ✅ BPF verifier 완전 호환
- ✅ 실제 패킷 데이터 캡처 (tcpdump로 ARP 패킷 등 확인됨)
- ✅ 통계 정보 실시간 출력
- ✅ 신호 처리를 통한 graceful shutdown

### 검증된 동작
- ARP 패킷에서 실제 MAC 주소 캡처 확인
- 패킷 통계 정상 동작 (RX/Captured/Dropped/Errors)
- Wireshark에서 정상적인 패킷 분석 가능

## 아키텍처

### 커널 공간 (xdp_capture.c)
- XDP 프로그램으로 패킷 수신
- Ring buffer를 통한 userspace 통신
- 패킷 통계 수집

### 사용자 공간 (capture_main.c)
- XDP 프로그램 로더
- Ring buffer 패킷 reader
- PCAP 파일 writer
- 실시간 통계 출력

## 향후 개발 방향

### 가능한 확장
1. **멀티 인터페이스 지원**: 여러 인터페이스 동시 캡처
2. **필터링 기능**: BPF 레벨에서 패킷 필터링
3. **성능 최적화**: Zero-copy 메커니즘 도입
4. **Clone-Redirect 복귀**: 원래 목표였던 패킷 복제 및 리다이렉션 기능

### 기술적 고려사항
- BPF verifier 제약사항 지속적 고려 필요
- 커널 버전 호환성 유지
- 메모리 사용량 최적화

## 빌드 및 테스트

```bash
# 빌드
make

# 테스트
./test_capture.sh

# 실행
sudo ./capture_main ens20 capture.pcap
```

이 프로젝트는 XDP와 eBPF 기술을 활용한 고성능 네트워크 패킷 처리의 실제 구현 사례입니다.