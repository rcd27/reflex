#!/bin/sh
# Девятый закон на живом ядре: состояние уехало в conntrack и вернулось ДРУГОЙ дверью (дамп).
# Плюс мутант apply→None — обязан покраснеть StateLost.
set -u
QUEUE=201
CONTROL=${CONTROL:-vk.com}   # чистая цель — нам нужен живой поток, не цензура
FOREIGN=0x20000000            # чужие биты, которые обязаны пережить наш вердикт

echo "[certify] включаю conntrack acct/timestamp в netns"
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1
sysctl -w net.netfilter.nf_conntrack_timestamp=1 >/dev/null 2>&1
echo "[certify] acct=$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null) timestamp=$(cat /proc/sys/net/netfilter/nf_conntrack_timestamp 2>/dev/null)"

# Правило: пометить поток чужими битами ДО очереди, затем в очередь 201 (обе стороны :443).
nft add table inet cert 2>/dev/null
nft add chain inet cert out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet cert out tcp dport 443 ct mark set $FOREIGN
nft add rule  inet cert out tcp dport 443 queue num $QUEUE
nft add chain inet cert inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet cert inp tcp sport 443 queue num $QUEUE

run_law() {
  BIN=$1; NAME=$2
  "$BIN" remember $QUEUE > /tmp/law.out 2>&1 &
  LAW=$!
  sleep 0.5
  curl -s4 --noproxy '*' --max-time 4 "https://$CONTROL/" >/dev/null 2>&1 &
  wait $LAW 2>/dev/null
  echo "[certify] $NAME → $(cat /tmp/law.out)"
  cat /tmp/law.out
}

echo "=== НОРМАЛЬНЫЙ (ждём verdict=held) ==="
run_law /usr/local/bin/certify-normal normal > /tmp/normal.txt 2>&1
cat /tmp/normal.txt
echo "=== МУТАНТ apply→None (ждём verdict=broken, StateLost) ==="
run_law /usr/local/bin/certify-mutated mutant > /tmp/mutant.txt 2>&1
cat /tmp/mutant.txt

nft delete table inet cert 2>/dev/null

NORMAL_HELD=0; grep -q '"verdict":"held"' /tmp/normal.txt && NORMAL_HELD=1
MUTANT_BROKEN=0; grep -qE '"verdict":"broken".*StateLost' /tmp/mutant.txt && MUTANT_BROKEN=1
echo "[итог] нормальный_held=$NORMAL_HELD (ждём 1)  мутант_StateLost=$MUTANT_BROKEN (ждём 1)"
if [ "$NORMAL_HELD" = 1 ] && [ "$MUTANT_BROKEN" = 1 ]; then
  echo "[итог] ЗЕЛЕНО: девятый закон держится на живом ядре; мутант apply→None краснеет StateLost"
  exit 0
fi
echo "[итог] КРАСНО или НЕОПРЕДЕЛЁННО (см. выше — возможно поток не попал в очередь / acct не встал)"
exit 1
