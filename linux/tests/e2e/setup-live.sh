#!/bin/bash
set -e

# ============================================================================
# Reflex live test topology — real internet through L2 bridge
#
#   [client namespace]              [router namespace]
#    curl отсюда                     NAT → eth0 → internet
#    10.99.0.2/24                    10.99.0.1/24
#         |                              |
#     veth-cl-br                     veth-rt-br
#         |                              |
#     ┌───┴──────────────────────────────┴───┐
#     │                br0                    │
#     │          reflex on AF_PACKET          │
#     └──────────────────────────────────────┘
#
# Client traffic to real internet passes through br0.
# Reflex observes and can inject on br0.
# ============================================================================

BRIDGE=br0
NS_CLIENT=client
NS_ROUTER=router

echo "=== Setting up live test topology ==="

# --- Create bridge ---
ip link add $BRIDGE type bridge
ip link set $BRIDGE up

# --- Client namespace ---
ip netns add $NS_CLIENT
ip link add veth-cl-br type veth peer name veth-cl-ns
ip link set veth-cl-br master $BRIDGE
ip link set veth-cl-br up
ip link set veth-cl-ns netns $NS_CLIENT
ip netns exec $NS_CLIENT ip addr add 10.99.0.2/24 dev veth-cl-ns
ip netns exec $NS_CLIENT ip link set veth-cl-ns up
ip netns exec $NS_CLIENT ip link set lo up
ip netns exec $NS_CLIENT ip route add default via 10.99.0.1

# DNS: use public resolver (Docker's internal DNS not reachable from netns)
mkdir -p /etc/netns/$NS_CLIENT
echo "nameserver 8.8.8.8" > /etc/netns/$NS_CLIENT/resolv.conf

# --- Router namespace ---
ip netns add $NS_ROUTER
ip link add veth-rt-br type veth peer name veth-rt-ns
ip link set veth-rt-br master $BRIDGE
ip link set veth-rt-br up
ip link set veth-rt-ns netns $NS_ROUTER
ip netns exec $NS_ROUTER ip addr add 10.99.0.1/24 dev veth-rt-ns
ip netns exec $NS_ROUTER ip link set veth-rt-ns up
ip netns exec $NS_ROUTER ip link set lo up

# --- Router → internet via WAN veth ---
ip link add veth-wan-host type veth peer name veth-wan-ns
ip link set veth-wan-host up
ip link set veth-wan-ns netns $NS_ROUTER
ip netns exec $NS_ROUTER ip link set veth-wan-ns up
ip addr add 10.98.0.1/24 dev veth-wan-host
ip netns exec $NS_ROUTER ip addr add 10.98.0.2/24 dev veth-wan-ns
ip netns exec $NS_ROUTER ip route add default via 10.98.0.1

# --- NAT ---
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 10.98.0.0/24 -o eth0 -j MASQUERADE
iptables -P FORWARD ACCEPT
ip netns exec $NS_ROUTER sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ip netns exec $NS_ROUTER iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o veth-wan-ns -j MASQUERADE
ip netns exec $NS_ROUTER iptables -P FORWARD ACCEPT

echo ""
echo "=== Topology ready ==="
echo "  client (10.99.0.2) ──br0── router (10.99.0.1) ──NAT── internet"
echo ""

# --- Test connectivity ---
echo "=== Testing internet access ==="
ip netns exec $NS_CLIENT curl -s --max-time 5 http://example.com | head -3 || echo "WARN: no internet"
echo ""

echo "=== Ready ==="
echo ""
echo "Usage:"
echo "  docker exec reflex-live ip netns exec client curl -sk https://rutracker.org"
echo "  docker exec reflex-live e2e_capture br0 5"
echo "  docker exec reflex-live e2e_feedback_loop br0 30"
echo "  docker exec reflex-live e2e_rst_detector br0 10"
echo ""

exec sleep infinity
