#!/bin/sh
# Внутри контейнера: движок с ПОТРЕБИТЕЛЬСКИМ прибором на очереди + боевой трафик через реальный
# аплинк (ТСПУ вантажа). Доказываем: чужой движку автомат Мили ловит тихий дроп на живом трафике.
set -u

TARGET=${TARGET:-rutracker.org}   # тихий дроп по SNI на этом вантаже
CONTROL=${CONTROL:-vk.com}        # домашняя чистая цель — контроль на ложное срабатывание
QUEUE=200
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  очередь=$QUEUE  (детектор — СВОЙ, порог 3с)"

bring-your-own-detector >"$LOG" 2>&1 &
ENGINE=$!
sleep 1
if ! kill -0 "$ENGINE" 2>/dev/null; then
  echo "[стенд] движок не поднялся:"; cat "$LOG"; exit 2
fi

# :443 в очередь, обе стороны (уход ClientHello и отсутствие ответа).
nft add table inet reflex_lab
nft add chain inet reflex_lab out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_lab out tcp dport 443 queue num 200
nft add chain inet reflex_lab inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_lab inp tcp sport 443 queue num 200

# Боевой трафик: цель повиснет (max-time держит дольше порога 3с), контроль пройдёт. Мимо прокси.
curl -s4 --noproxy '*' --max-time 10 "https://$TARGET/"  >/dev/null 2>&1 &
curl -s4 --noproxy '*' --max-time 8  "https://$CONTROL/" >/dev/null 2>&1 || true

# Дать своему прибору тикнуть за порог 3с с запасом.
sleep 7

nft delete table inet reflex_lab 2>/dev/null
kill "$ENGINE" 2>/dev/null; wait "$ENGINE" 2>/dev/null

echo "─── лог движка ───────────────────────────"
cat "$LOG"
echo "──────────────────────────────────────────"

HIT=0; grep -q "свой прибор поймал тишину: $TARGET" "$LOG" && HIT=1
CONTROL_HIT=0; grep -q "$CONTROL" "$LOG" && CONTROL_HIT=1
echo "[итог] свой_прибор_поймал=$HIT (ждём 1)  контроль=$CONTROL_HIT (ждём 0)"
if [ "$HIT" = 1 ] && [ "$CONTROL_HIT" = 0 ]; then
  echo "[итог] ЗЕЛЕНО: чужой движку автомат поймал тихий дроп «$TARGET» на боевом трафике; «$CONTROL» чист"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
