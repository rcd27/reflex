#!/bin/bash
set -e

E2E_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Building testbed ==="
cd "$E2E_DIR"
docker compose build

echo ""
echo "=== Starting testbed ==="
docker compose down 2>/dev/null || true
docker rm -f reflex-testbed 2>/dev/null || true
docker compose up -d
sleep 3

echo ""
echo "=== Testbed logs ==="
docker logs reflex-testbed 2>&1 | head -30

echo ""
echo "=== Running e2e: AF_PACKET capture ==="
# start capture in background (3 second window)
docker exec reflex-testbed e2e_capture br0 3 &
CAPTURE_PID=$!

# generate traffic: client -> server TLS
sleep 0.5
docker exec reflex-testbed ip netns exec client curl -sk https://10.77.0.20 > /dev/null 2>&1
docker exec reflex-testbed ip netns exec client curl -sk https://10.77.0.20 > /dev/null 2>&1
docker exec reflex-testbed ip netns exec client ping -c 3 -W 1 10.77.0.20 > /dev/null 2>&1

# wait for capture to finish
wait $CAPTURE_PID
EXIT_CODE=$?

echo ""
echo "=== Cleaning up ==="
docker compose down

exit $EXIT_CODE
