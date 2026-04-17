#!/bin/bash
set -e

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    echo ""
    echo "━━━ TEST: $name ━━━"
    if "$@"; then
        echo "✓ $name PASSED"
        PASS=$((PASS + 1))
    else
        echo "✗ $name FAILED"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Building testbed ==="
cd "$E2E_DIR"
docker compose build 2>&1 | tail -5

echo ""
echo "=== Starting testbed ==="
docker compose down 2>/dev/null || true
docker rm -f reflex-testbed 2>/dev/null || true
docker compose up -d
sleep 3

echo ""
echo "=== Testbed ready ==="
docker logs reflex-testbed 2>&1 | grep -E '(OK|PASS|FAIL|Ready|nginx)'

# --- Test 1: AF_PACKET capture ---
run_test "af_packet_capture" bash -c '
    docker exec reflex-testbed e2e_capture br0 3 &
    PID=$!
    sleep 0.5
    docker exec reflex-testbed ip netns exec client curl -sk https://10.77.0.20 > /dev/null 2>&1
    docker exec reflex-testbed ip netns exec client ping -c 2 -W 1 10.77.0.20 > /dev/null 2>&1
    wait $PID
'

# --- Test 2: DPI emulator injects RST on ClientHello ---
run_test "dpi_rst_injection" bash -c '
    # start DPI emulator (5s window)
    docker exec reflex-testbed e2e_rst_emulator br0 5 &
    DPI_PID=$!
    sleep 0.5

    # generate TLS traffic — DPI emulator should inject RST
    docker exec reflex-testbed ip netns exec client curl -sk --max-time 2 https://10.77.0.20 > /dev/null 2>&1 || true
    docker exec reflex-testbed ip netns exec client curl -sk --max-time 2 https://10.77.0.20 > /dev/null 2>&1 || true

    wait $DPI_PID
'

# --- Test 3: RST detector catches injected RST ---
run_test "rst_detector_e2e" bash -c '
    # start DPI emulator in background
    docker exec reflex-testbed e2e_rst_emulator br0 8 &
    DPI_PID=$!
    sleep 0.5

    # start RST detector in background
    docker exec reflex-testbed e2e_rst_detector br0 6 &
    DET_PID=$!
    sleep 0.5

    # generate TLS traffic
    docker exec reflex-testbed ip netns exec client curl -sk --max-time 2 https://10.77.0.20 > /dev/null 2>&1 || true
    sleep 1
    docker exec reflex-testbed ip netns exec client curl -sk --max-time 2 https://10.77.0.20 > /dev/null 2>&1 || true
    sleep 1

    # wait for detector
    wait $DET_PID
    DET_EXIT=$?

    # kill DPI emulator
    kill $DPI_PID 2>/dev/null || true
    wait $DPI_PID 2>/dev/null || true

    exit $DET_EXIT
'

# --- Test 4: multi-disorder strategy ---
run_test "multi_disorder_strategy" bash -c '
    # start multi-disorder strategy (listens for ClientHello to testserver.local)
    docker exec reflex-testbed e2e_multi_disorder br0 6 &
    STRAT_PID=$!
    sleep 0.5

    # generate TLS traffic with SNI=testserver.local — strategy should inject fakes
    docker exec reflex-testbed ip netns exec client curl -sk --resolve testserver.local:443:10.77.0.20 --max-time 2 https://testserver.local > /dev/null 2>&1 || true
    sleep 1
    docker exec reflex-testbed ip netns exec client curl -sk --resolve testserver.local:443:10.77.0.20 --max-time 2 https://testserver.local > /dev/null 2>&1 || true
    sleep 1

    wait $STRAT_PID
'

# --- Test 5: Geneva feedback loop ---
run_test "geneva_feedback_loop" bash -c '
    # start RST emulator (simulates ТСПУ)
    docker exec reflex-testbed e2e_rst_emulator br0 12 &
    EMU_PID=$!
    sleep 0.5

    # start Geneva feedback loop
    docker exec reflex-testbed e2e_feedback_loop br0 10 &
    GENEVA_PID=$!
    sleep 0.5

    # generate TLS traffic — Geneva should detect, apply strategy, observe result
    for i in 1 2 3 4; do
        docker exec reflex-testbed ip netns exec client curl -sk --resolve testserver.local:443:10.77.0.20 --max-time 2 https://testserver.local > /dev/null 2>&1 || true
        sleep 1
    done

    # wait for Geneva to finish
    wait $GENEVA_PID
    GENEVA_EXIT=$?

    kill $EMU_PID 2>/dev/null || true
    wait $EMU_PID 2>/dev/null || true

    exit $GENEVA_EXIT
'

# --- Summary ---
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "=== Cleaning up ==="
docker compose down

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
