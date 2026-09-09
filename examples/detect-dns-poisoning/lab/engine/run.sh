#!/bin/sh
# Внутри контейнера: движок на очереди UDP:53 + боевые DNS-запросы через реальный ТСПУ вантажа.
# Цель — домен со стабильным инжектом NXDOMAIN; контроль — домашний домен (настоящий ответ).
set -u

TARGET=${TARGET:-nnmclub.to}   # стабильный инжект NXDOMAIN @8.8.8.8 на вантаже
CONTROL=${CONTROL:-vk.com}     # настоящий ответ — контроль на ложное срабатывание
RESOLVER=${RESOLVER:-8.8.8.8}
QUEUE=200
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  резолвер=$RESOLVER  очередь=$QUEUE"

detect-dns-poisoning >"$LOG" 2>&1 &
ENGINE=$!
sleep 1
if ! kill -0 "$ENGINE" 2>/dev/null; then
  echo "[стенд] движок не поднялся:"; cat "$LOG"; exit 2
fi

# DNS обе стороны в очередь: запрос (dport 53) и ответ/инжект (sport 53).
nft add table inet reflex_lab
nft add chain inet reflex_lab out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_lab out udp dport 53 queue num 200
nft add chain inet reflex_lab inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_lab inp udp sport 53 queue num 200

# Боевые запросы напрямую к публичному резолверу (мимо системного stub).
dig +tries=1 +time=3 "@$RESOLVER" "$TARGET"  A >/dev/null 2>&1 || true
dig +tries=1 +time=3 "@$RESOLVER" "$CONTROL" A >/dev/null 2>&1 || true

sleep 3

nft delete table inet reflex_lab 2>/dev/null
kill "$ENGINE" 2>/dev/null; wait "$ENGINE" 2>/dev/null

echo "─── лог движка ───────────────────────────"
cat "$LOG"
echo "──────────────────────────────────────────"

GOT=0;         grep -q "отравление DNS: $TARGET" "$LOG" && GOT=1
CONTROL_HIT=0; grep -q "$CONTROL"                "$LOG" && CONTROL_HIT=1
echo "[итог] отравление=$GOT (ждём 1)  контроль=$CONTROL_HIT (ждём 0)"
if [ "$GOT" = 1 ] && [ "$CONTROL_HIT" = 0 ]; then
  echo "[итог] ЗЕЛЕНО: отравление DNS «$TARGET» поймано на боевом трафике; «$CONTROL» чист"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
