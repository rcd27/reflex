#!/bin/bash
set -e

echo "=== Setting up L2 bridge testbed ==="

# create network namespaces
ip netns add client
ip netns add server

# create veth pairs
# client side: veth-cl (in client ns) <-> veth-cl-br (in default ns)
ip link add veth-cl type veth peer name veth-cl-br
# server side: veth-sv (in server ns) <-> veth-sv-br (in default ns)
ip link add veth-sv type veth peer name veth-sv-br

# move endpoints into namespaces
ip link set veth-cl netns client
ip link set veth-sv netns server

# create L2 bridge
ip link add br0 type bridge
ip link set veth-cl-br master br0
ip link set veth-sv-br master br0

# bring up bridge side
ip link set br0 up
ip link set veth-cl-br up
ip link set veth-sv-br up

# configure client namespace
ip netns exec client ip addr add 10.77.0.10/24 dev veth-cl
ip netns exec client ip link set veth-cl up
ip netns exec client ip link set lo up

# configure server namespace
ip netns exec server ip addr add 10.77.0.20/24 dev veth-sv
ip netns exec server ip link set veth-sv up
ip netns exec server ip link set lo up

echo ""
echo "=== Topology ==="
echo ""
echo "  netns 'client'         default netns          netns 'server'"
echo "  ┌────────────┐    ┌──────────────────┐    ┌────────────┐"
echo "  │ 10.77.0.10 │    │   br0 (L2 bridge)│    │ 10.77.0.20 │"
echo "  │  veth-cl   ├────┤veth-cl-br  veth-sv-br├────┤  veth-sv   │"
echo "  └────────────┘    │                  │    └────────────┘"
echo "                    │  reflex (AF_PACKET)│"
echo "                    └──────────────────┘"
echo ""

# test connectivity
echo "=== Testing connectivity ==="
ip netns exec client ping -c 1 -W 1 10.77.0.20 && echo "client -> server: OK" || echo "client -> server: FAILED"
ip netns exec server ping -c 1 -W 1 10.77.0.10 && echo "server -> client: OK" || echo "server -> client: FAILED"
echo ""

# start nginx in server namespace
echo "=== Starting TLS server in server namespace ==="
ip netns exec server nginx
echo "nginx started on 10.77.0.20:443"
echo ""

# verify TLS
echo "=== Testing TLS ==="
ip netns exec client curl -sk https://10.77.0.20 && echo "" || echo "TLS FAILED"
echo ""

# verify bridge sees traffic
echo "=== Testing AF_PACKET visibility on br0 ==="
timeout 2 tcpdump -i br0 -c 3 2>&1 &
TCPDUMP_PID=$!
sleep 0.5
ip netns exec client ping -c 2 -W 1 10.77.0.20 > /dev/null 2>&1
wait $TCPDUMP_PID 2>/dev/null || true
echo ""

echo "=== Testbed ready ==="
echo ""
echo "Usage:"
echo "  docker exec reflex-testbed ip netns exec client curl -sk https://10.77.0.20"
echo "  docker exec reflex-testbed tcpdump -i br0"
echo "  docker exec reflex-testbed /reflex/target/release/your-binary --iface br0"
echo ""

exec sleep infinity
