#!/bin/bash
# 캡처 프로그램 실행 + HTTP 트래픽 발생 + 결과 저장
# 반드시 sudo 로 실행: sudo ./run_test.sh

set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/pcap_prog"
OUT="$DIR/capture_result.txt"
IFACE="${1:-ens33}"

if [ ! -x "$BIN" ]; then
    echo "[!] $BIN 없음. 먼저 make 하세요."
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "[!] root 권한 필요. sudo 로 실행하세요."
    exit 1
fi

echo "[*] 인터페이스: $IFACE"
echo "[*] 백그라운드로 캡처 시작..."
"$BIN" "$IFACE" "tcp port 80" > "$OUT" 2>&1 &
PCAP_PID=$!

# libpcap 이 필터 컴파일 + promisc 모드 진입할 시간
sleep 2

echo "[*] HTTP GET 3회 발생 (example.com, neverssl.com, httpbin.org)"
curl -s -o /dev/null http://example.com/ || true
sleep 1
curl -s -o /dev/null http://neverssl.com/ || true
sleep 1
curl -s -o /dev/null "http://httpbin.org/get?whs=hyowon" || true
sleep 2

echo "[*] 캡처 종료"
kill -INT "$PCAP_PID" 2>/dev/null
wait "$PCAP_PID" 2>/dev/null

# 결과 파일 소유권을 원래 사용자로
if [ -n "${SUDO_USER:-}" ]; then
    chown "$SUDO_USER":"$SUDO_USER" "$OUT" 2>/dev/null || true
fi

echo
echo "==================== 결과 ($OUT) ===================="
cat "$OUT"
echo "===================================================="
echo "[*] 완료. 파일: $OUT"
