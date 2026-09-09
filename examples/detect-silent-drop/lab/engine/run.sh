#!/bin/sh
# Внутри контейнера: поднять движок на очереди, погнать БОЕВОЙ трафик через реальный аплинк
# (ТСПУ этого вантажа), снять вердикт. Цель реально роняется молча по SNI; контроль — чистая цель.
set -u
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy 2>/dev/null

TARGET=${TARGET:-rutracker.org}   # тихий дроп по SNI на нашем вантаже
CONTROL=${CONTROL:-grani.ru}      # чистая цель — контроль на ложное срабатывание
QUEUE=200
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  очередь=$QUEUE"

# 0. Предпосылки КРАЯ: движок читает счётчики и возраст потока у conntrack, а ядро их не ведёт,
#    пока не сказано. Без учёта движок не поднимется — и скажет об этом, а не соврёт нулями.
#    Пишем в /proc напрямую: `sysctl` в тонком образе нет, а procps ради двух строк не тянем.
echo 1 >/proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null \
  || echo "[стенд] ВНИМАНИЕ: учёт счётчиков не включился — краевые приборы будут молчать честно"
echo 1 >/proc/sys/net/netfilter/nf_conntrack_timestamp 2>/dev/null \
  || echo "[стенд] ВНИМАНИЕ: отметки времени не включились — возраста потока не будет"

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
# МОЛОТ, а не одиночная проба: краевой прибор судит по возрасту потока, и одному соединению редко
# случается пережить порог под наблюдением. Одна проба давала ноль подтверждений там, где двадцать
# дают двадцать — «не измерено» выглядело как «не работает».
i=0
while [ "$i" -lt 20 ]; do
  curl -s4 --noproxy '*' --max-time 10 "https://$TARGET/" >/dev/null 2>&1 &
  i=$((i + 1))
  sleep 0.3
done
curl -s4 --noproxy '*' --max-time 8 "https://$CONTROL/" >/dev/null 2>&1 || true

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
