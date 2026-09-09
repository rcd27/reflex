#!/bin/sh
# Внутри контейнера: поднять движок на очереди, погнать БОЕВОЙ трафик через реальный аплинк
# (ТСПУ этого вантажа), снять вердикт. Цель реально роняется молча по SNI; контроль — чистая цель.
set -u

TARGET=${TARGET:-rutracker.org}   # тихий дроп по SNI на нашем вантаже
CONTROL=${CONTROL:-grani.ru}      # чистая цель — контроль на ложное срабатывание
QUEUE=200
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  очередь=$QUEUE"

# 1. Движок на очереди. Правило ставим ПОСЛЕ — очередь без слушателя дропает трафик.
detect-silent-drop >"$LOG" 2>&1 &
ENGINE=$!
sleep 1
if ! kill -0 "$ENGINE" 2>/dev/null; then
  echo "[стенд] движок не поднялся:"; cat "$LOG"; exit 2
fi

# 2. Наш :443 — в очередь, обе стороны (исходящий ClientHello и входящий ответ/его отсутствие).
nft add table inet reflex_lab
nft add chain inet reflex_lab out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_lab out tcp dport 443 queue num 200
nft add chain inet reflex_lab inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_lab inp tcp sport 443 queue num 200

# 3. Боевой трафик. Цель повиснет (max-time держит соединение дольше окна тишины 5с);
#    контроль пройдёт быстро. Оба — напрямую, мимо любого прокси.
curl -s4 --noproxy '*' --max-time 12 "https://$TARGET/"  >/dev/null 2>&1 &
curl -s4 --noproxy '*' --max-time 8  "https://$CONTROL/" >/dev/null 2>&1 || true

# 4. Дать движку тикнуть за окно тишины (5с) с запасом.
sleep 9

# 5. Прибраться.
nft delete table inet reflex_lab 2>/dev/null
kill "$ENGINE" 2>/dev/null; wait "$ENGINE" 2>/dev/null

echo "─── лог движка ───────────────────────────"
cat "$LOG"
echo "──────────────────────────────────────────"

# 6. Вердикт: цель поймана ОБОИМИ приборами (подозрение по повтору + подтверждение тишиной),
#    контроль молчит.
SUSPECT=0; grep -q "подозрение на тихий дроп: $TARGET" "$LOG" && SUSPECT=1
CONFIRM=0; grep -q "подтверждено: $TARGET"             "$LOG" && CONFIRM=1
CONTROL_HIT=0; grep -q "$CONTROL"                      "$LOG" && CONTROL_HIT=1
echo "[итог] подозрение=$SUSPECT (ждём 1)  подтверждение=$CONFIRM (ждём 1)  контроль=$CONTROL_HIT (ждём 0)"
if [ "$SUSPECT" = 1 ] && [ "$CONFIRM" = 1 ] && [ "$CONTROL_HIT" = 0 ]; then
  echo "[итог] ЗЕЛЕНО: «$TARGET» пойман обоими приборами на боевом трафике; «$CONTROL» чист"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
