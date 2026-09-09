#!/bin/sh
# A/B на БОЕВОМ ТСПУ: ядерный путь (EdgeSilence, очередь 201, пакетный закон) против юзерспейсного
# (фасад, очередь 200). acct/timestamp — из compose sysctls. КУРИМ БЕЗ ПРОКСИ: через прокси curl
# уходит мимо ТСПУ, и дроп физически не появляется в замере (стоило нам ложного «блокировки нет»).
set -u
TARGET=${TARGET:-rutracker.org}
CONTROL=${CONTROL:-vk.com}
N=${N:-20}
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy 2>/dev/null
echo "[ab] acct=$(cat /proc/sys/net/netfilter/nf_conntrack_acct) timestamp=$(cat /proc/sys/net/netfilter/nf_conntrack_timestamp)"

hammer() { # цель, сколько раз. Свои curl ждём по PID — `wait` без аргументов ждал бы и демон.
  pids=""
  i=0; while [ $i -lt "$2" ]; do
    curl -s4 --noproxy '*' --max-time 10 "https://$1/" >/dev/null 2>&1 &
    pids="$pids $!"
    i=$((i+1)); sleep 0.3
  done
  for pid in $pids; do wait "$pid" 2>/dev/null; done
}
q_on()  { nft add table inet ab 2>/dev/null; nft add chain inet ab out "{ type filter hook output priority -150; policy accept; }"; nft add rule inet ab out tcp dport 443 queue num "$1"; nft add chain inet ab inp "{ type filter hook input priority -150; policy accept; }"; nft add rule inet ab inp tcp sport 443 queue num "$1"; }
q_off() { nft delete table inet ab 2>/dev/null; }

# Трасса РИСКА ACK-спуфера: для каждого потока — максимум up_pk, увиденный ПОД ПОДОЗРЕНИЕМ. Всюду 1 →
# дроп ВЫШЕ подтверждающего устройства, счётчик замер, ловим (behavior a). Есть >1 → ТСПУ шлёт пакеты
# от имени цели, и по счётчикам conntrack дроп неотличим от живого пути — предел носителя (behavior b).
trace_report() {
  echo "-- ACK-спуфер: max up_pk по потокам под подозрением (1=замер/ловим, >1=растёт/предел носителя) --"
  n=$(grep -c '\[trace\]' "$1")
  if [ "$n" = 0 ]; then echo "  (следов подозрения нет)"; return; fi
  grep '\[trace\]' "$1" | sed -E 's/.*ct=([0-9]+) up_pk=([0-9]+).*/\1 \2/' \
    | awk '{ if($2>m[$1]) m[$1]=$2 } END { for(c in m) print m[c] }' \
    | sort -n | uniq -c | awk '{ print "  потоков с max up_pk="$2": "$1 }'
}

echo "=== A: ФАСАД (юзерспейс, очередь 200) — база сравнения на $TARGET+$CONTROL ==="
detect-silent-drop > /tmp/facade.log 2>&1 &
FP=$!; sleep 1; q_on 200
hammer "$TARGET" "$N"; hammer "$CONTROL" "$N"; sleep 9
q_off; kill "$FP" 2>/dev/null; wait "$FP" 2>/dev/null
FAC_T=$(grep -c "$TARGET" /tmp/facade.log); FAC_C=$(grep -c "$CONTROL" /tmp/facade.log)

echo "=== B1: ЯДЕРНЫЙ (EdgeSilence, очередь 201) на $TARGET — ЖИВОЙ дроп ==="
detect-silent-drop-edge > /tmp/edge_t.log 2>&1 &
EP=$!; sleep 1; q_on 201
hammer "$TARGET" "$N"; sleep 3
q_off; kill "$EP" 2>/dev/null; wait "$EP" 2>/dev/null
echo "-- находки --"; grep '\[край\]' /tmp/edge_t.log | grep -v "слушаю" | sort | uniq -c
trace_report /tmp/edge_t.log
NB_T=$(grep -c "no_bytes" /tmp/edge_t.log); BH_T=$(grep -c "blackhole" /tmp/edge_t.log)

echo "=== B2: ЯДЕРНЫЙ на $CONTROL (санитар ложного срабатывания) ==="
detect-silent-drop-edge > /tmp/edge_c.log 2>&1 &
EP=$!; sleep 1; q_on 201
hammer "$CONTROL" "$N"; sleep 3
q_off; kill "$EP" 2>/dev/null; wait "$EP" 2>/dev/null
echo "-- находки --"; grep '\[край\]' /tmp/edge_c.log | grep -v "слушаю" | sort | uniq -c
FALSE_C=$(grep -cE "no_bytes|blackhole|silence" /tmp/edge_c.log)

# B3: ЖИВОЙ Blackhole по АДРЕСУ (IP-SYN-дроп Telegram DC): SYN уходит, SYN+ACK не приходит, up.packets
# замирает на 0 — иная буква, чем NoBytes, и её надо подтвердить живьём, не только стендом/тестом.
BH_TARGET=${BH_TARGET:-149.154.167.50}
echo "=== B3: ЯДЕРНЫЙ на $BH_TARGET:443 (живой IP-SYN-дроп → Blackhole) ==="
detect-silent-drop-edge > /tmp/edge_bh.log 2>&1 &
EP=$!; sleep 1; q_on 201
i=0; pids=""; while [ $i -lt "$N" ]; do curl -s4 --noproxy '*' --max-time 8 -k "https://$BH_TARGET/" >/dev/null 2>&1 & pids="$pids $!"; i=$((i+1)); sleep 0.3; done
for pid in $pids; do wait "$pid" 2>/dev/null; done; sleep 3
q_off; kill "$EP" 2>/dev/null; wait "$EP" 2>/dev/null
echo "-- находки --"; grep '\[край\]' /tmp/edge_bh.log | grep -v "слушаю" | sort | uniq -c
BH_LIVE=$(grep -c "blackhole" /tmp/edge_bh.log)

echo "[итог] фасад: $TARGET=$FAC_T (ждём >0) $CONTROL=$FAC_C (ждём 0)"
echo "[итог] edge $TARGET (NoBytes, живой SNI-дроп): no_bytes=$NB_T (ждём >0)"
echo "[итог] edge $BH_TARGET (Blackhole, живой IP-SYN-дроп): blackhole=$BH_LIVE (ждём >0)"
echo "[итог] edge $CONTROL (санитар): ложных=$FALSE_C (ждём строгий 0)"
if [ "$FAC_T" -gt 0 ] && [ "$FAC_C" = 0 ] && [ "$NB_T" -gt 0 ] && [ "$BH_LIVE" -gt 0 ] && [ "$FALSE_C" = 0 ]; then
  echo "[итог] ЗЕЛЕНО: NoBytes И Blackhole пойманы ЖИВЬЁМ, чистая цель молчит"
  exit 0
fi
echo "[итог] РАСХОЖДЕНИЕ — разбираю (ложное на контроле? дроп не пойман? прокси-артефакт? acct?)"
exit 1
