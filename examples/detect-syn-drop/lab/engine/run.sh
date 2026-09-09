#!/bin/sh
# Внутри контейнера: движок на очереди + боевой трафик через реальный ТСПУ вантажа. Цель —
# IP датацентра Телеграма (SYN роняется по адресу); контроль — домашняя цель (рукопожатие проходит).
set -u

TARGET=${TARGET:-149.154.167.50}  # Telegram DC IP — SYN-дроп по адресу, имени нет
CONTROL=${CONTROL:-vk.com}        # домашняя цель — рукопожатие есть, blackhole не должен сработать
QUEUE=200
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  очередь=$QUEUE"

detect-syn-drop >"$LOG" 2>&1 &
ENGINE=$!
sleep 1
if ! kill -0 "$ENGINE" 2>/dev/null; then
  echo "[стенд] движок не поднялся:"; cat "$LOG"; exit 2
fi

nft add table inet reflex_lab
nft add chain inet reflex_lab out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_lab out tcp dport 443 queue num 200
nft add chain inet reflex_lab inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_lab inp tcp sport 443 queue num 200

# МОЛОТ, а не одиночная проба: блэкхол судит по ВОЗРАСТУ потока (порог 2с), и наблюдение обязано
# прийти ПОСЛЕ порога. У одиночного `SYN` повторы редки (RTO удваивается), и попасть в окно ему
# случается не всегда — «не измерено» читалось бы как «не работает».
i=0
while [ "$i" -lt 20 ]; do
  curl -s4 --noproxy '*' --max-time 10 -k "https://$TARGET/" >/dev/null 2>&1 &
  i=$((i + 1))
  sleep 0.3
done
curl -s4 --noproxy '*' --max-time 8 "https://$CONTROL/" >/dev/null 2>&1 || true

sleep 6

nft delete table inet reflex_lab 2>/dev/null
kill "$ENGINE" 2>/dev/null; wait "$ENGINE" 2>/dev/null

echo "─── лог движка ───────────────────────────"
cat "$LOG"
echo "──────────────────────────────────────────"

# Вердикт: цель поймана как blackhole ПО АДРЕСУ, контроль молчит.
GOT=0;      grep -q "IP-blackhole: $TARGET" "$LOG" && GOT=1
CONTROL_HIT=0; grep -q "$CONTROL"           "$LOG" && CONTROL_HIT=1
echo "[итог] blackhole=$GOT (ждём 1)  контроль=$CONTROL_HIT (ждём 0)"
if [ "$GOT" = 1 ] && [ "$CONTROL_HIT" = 0 ]; then
  echo "[итог] ЗЕЛЕНО: IP-blackhole «$TARGET» пойман по адресу на боевом трафике; «$CONTROL» чист"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
