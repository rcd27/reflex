#!/bin/sh
# Внутри контейнера: движок с ЭФФЕКТОМ на очереди + реальный трафик к тихо-дропаемой цели.
# Доказываем ДЕЙСТВИЕ замером: с обрывом curl падает быстро (RST), без него висит до таймаута.
#
# КОНТРОЛЬ СНИМАЕТСЯ В ЭТОМ ЖЕ ПРОГОНЕ, а не берётся из памяти. Прежде порог был абсолютным
# («меньше шести секунд»), а «без нас висел бы ~12с» — историей, которую стенд не проверял. Тогда
# цель, переставшая блокироваться, давала быстрый curl и БЕЗ нас — и стенд зеленел, доказывая не
# то. Это тот же изъян, что ловит §10.1: зелёный результат не считается, пока не показана
# способность того же замера дать красный.
#
# Контроль идёт ДО постановки правил: мир, в котором нас ещё нет, — та же линия, та же цель, та же
# минута. Разница между контролем и замером и есть наше действие.
set -u

TARGET=${TARGET:-rutracker.org}   # тихий дроп по SNI на вантаже
QUEUE=200
MARK=0xBB                         # reflex::INJECT_MARK — метка своих инъекций
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  очередь=$QUEUE  метка_инъекций=$MARK"

# ── КОНТРОЛЬ: сколько цель держит БЕЗ НАС. Движка ещё нет, правил ещё нет. ──
c0=$(date +%s%3N)
curl -sS4 --noproxy '*' -o /dev/null --connect-timeout 4 --max-time 15 "https://$TARGET/" >/dev/null 2>&1
crc=$?
c1=$(date +%s%3N)
control=$((c1 - c0))
echo "[контроль] без движка: rc=$crc, провисел ${control}мс"

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
# ЗАМЕР ОБЯЗАН ОТЛИЧАТЬСЯ ОТ КОНТРОЛЯ. Держи цель быстро и без нас — доказывать нечего: беды,
# которую мы лечим, на этой линии сегодня нет, и зелёный был бы зелёным по чужой причине.
BLOCKED=0; [ "$control" -ge 6000 ] && BLOCKED=1
echo "[итог] обрыв_залогирован=$SEVERED (ждём 1)  оборвалось_быстро=$FAST (ждём 1, <6с)"
echo "[итог] беда_есть=$BLOCKED (ждём 1: без нас ${control}мс, с нами ${elapsed}мс)"
if [ "$BLOCKED" = 0 ]; then
  echo "[итог] НЕДЕЙСТВИТЕЛЕН: без движка цель отвечала за ${control}мс — тихого дропа на этой"
  echo "       линии сейчас нет, и доказывать действию нечего. Это не отказ движка (§7: «не"
  echo "       наблюдали» ≠ «наблюдали и пусто»): возьми цель, которая режется, либо линию, где режут."
  exit 2
fi
if [ "$SEVERED" = 1 ] && [ "$FAST" = 1 ]; then
  echo "[итог] ЗЕЛЕНО: тихий дроп «$TARGET» оборван RST за ${elapsed}мс против ${control}мс без нас"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
