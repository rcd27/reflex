#!/bin/sh
# Внутри контейнера: движок с ЭФФЕКТОМ на очереди + боевой трафик к тихо-дропаемой цели.
# Доказываем ДЕЙСТВИЕ замером: с обрывом curl падает быстро (RST), без него висел бы ~12с.
set -u

TARGET=${TARGET:-rutracker.org}   # тихий дроп по SNI на вантаже
QUEUE=200
MARK=0xBB                         # reflex::INJECT_MARK — метка своих инъекций
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  очередь=$QUEUE  метка_инъекций=$MARK"

sever-silent-drop >"$LOG" 2>&1 &
ENGINE=$!
sleep 1
if ! kill -0 "$ENGINE" 2>/dev/null; then
  echo "[стенд] движок не поднялся:"; cat "$LOG"; exit 2
fi

# :443 в очередь ОБЕ стороны, но свои инъекции (метка) пропускаем — RST не должен вернуться в очередь.
nft add table inet reflex_lab
nft add chain inet reflex_lab out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_lab out tcp dport 443 meta mark != $MARK queue num 200
nft add chain inet reflex_lab inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_lab inp tcp sport 443 meta mark != $MARK queue num 200

# ЗАМЕР: сколько curl провисел до обрыва. Без нас тихий дроп держит до ~12с.
t0=$(date +%s%3N)
curl -sS4 --noproxy '*' -o /dev/null --connect-timeout 4 --max-time 15 "https://$TARGET/" >/dev/null 2>&1
rc=$?
t1=$(date +%s%3N)
elapsed=$((t1 - t0))

nft delete table inet reflex_lab 2>/dev/null
kill "$ENGINE" 2>/dev/null; wait "$ENGINE" 2>/dev/null

echo "─── лог движка ───────────────────────────"
cat "$LOG"
echo "──────────────────────────────────────────"
echo "[замер] curl rc=$rc, провисел ${elapsed}мс (rc=56 — сброшено, rc=28 — таймаут/висел)"

SEVERED=0; grep -q "обрываю тихий дроп: $TARGET" "$LOG" && SEVERED=1
FAST=0; [ "$elapsed" -lt 6000 ] && FAST=1
echo "[итог] обрыв_залогирован=$SEVERED (ждём 1)  оборвалось_быстро=$FAST (ждём 1, <6с)"
if [ "$SEVERED" = 1 ] && [ "$FAST" = 1 ]; then
  echo "[итог] ЗЕЛЕНО: тихий дроп «$TARGET» оборван RST за ${elapsed}мс (без нас висел бы ~12с)"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
