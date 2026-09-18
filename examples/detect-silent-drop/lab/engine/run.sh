#!/bin/sh
# Внутри контейнера: поднять движок на очереди, погнать РЕАЛЬНЫЙ трафик через реальный аплинк
# (ТСПУ этого вантажа), снять вердикт.
#
# ПРЕДМЕТ СТЕНДА — ЗАДЕРЖАННЫЙ ОТВЕТ, а не тихий дроп, и это замер, а не выбор. 18.09.2026 цель
# сменила род блокировки: рукопожатие проходит целиком (сертификат приходит за 0,76 с), клиент
# шлёт запрос, цель подтверждает его `ACK`-ом БЕЗ ДАННЫХ и молчит ~20 секунд, после чего отвечает
# `301`. Прежний предмет (дроп по имени: рукопожатие не проходит, ответа нет никогда) на этой цели
# больше не воспроизводится, и стенд, ждавший его, краснел бы вечно, ничего не проверяя.
#
# Контроль — чистая цель: отвечает за доли секунды и бедой называться не должна.
set -u
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy 2>/dev/null

TARGET=${TARGET:-rutracker.org}   # принимает запрос и молчит ~20 с на нашем вантаже
CONTROL=${CONTROL:-grani.ru}      # чистая цель — контроль на ложное срабатывание
QUEUE=200
LOG=/tmp/reflex.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  очередь=$QUEUE"
if [ -n "${REFLEX_LAB_TINY_QUEUE:-}" ] || [ -n "${REFLEX_LAB_TINY_RCVBUF:-}" ]; then
  echo "[стенд] мутант ЗАМЕРА: REFLEX_LAB_TINY_QUEUE=${REFLEX_LAB_TINY_QUEUE:-нет}  REFLEX_LAB_TINY_RCVBUF=${REFLEX_LAB_TINY_RCVBUF:-нет}"
fi

# `queue_dropped`/`user_dropped` — ДВА разных оракула (Д8, T13): первый видит ядро ДО очереди,
# второй — ДО нашего чтения. Формат: `queue_num peer_portid queue_total copy_mode copy_range
# queue_dropped user_dropped id_sequence 1` (нашей ОЧЕРЕДИ соответствует первое поле).
qstats() {
  awk -v q="$QUEUE" '$1==q {print $6, $7}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null
}

# 0. Предпосылка КРАЯ: движок читает счётчики и возраст потока у conntrack. `compose.yml` ставит
#    `nf_conntrack_acct`/`timestamp` namespaced-sysctl'ами ПРИ СОЗДАНИИ netns — единственном
#    моменте, когда /proc/sys ещё не read-only; здесь их только ЧИТАЕМ. Прежде здесь стояла ЗАПИСЬ
#    поверх уже готового — она гарантированно отказывала ("Read-only file system") и печатала
#    «ВНИМАНИЕ: не включился» даже когда учёт работал, путая читающего: отказ записи не был
#    отказом края.
ACCT=$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || echo '?')
TS=$(cat /proc/sys/net/netfilter/nf_conntrack_timestamp 2>/dev/null || echo '?')
echo "[стенд] учёт conntrack: acct=$ACCT timestamp=$TS (ставит compose.yml при создании netns)"
if [ "$ACCT" != "1" ] || [ "$TS" != "1" ]; then
  echo "[стенд] ВНИМАНИЕ: учёт и правда не включён — краевые приборы будут молчать честно" >&2
fi

# 1. Движок на очереди. Правило ставим ПОСЛЕ — очередь без слушателя дропает трафик.
detect-silent-drop >"$LOG" 2>&1 &
ENGINE=$!
sleep 1
if ! kill -0 "$ENGINE" 2>/dev/null; then
  echo "[стенд] движок не поднялся:"; cat "$LOG"; exit 2
fi

BEFORE=$(qstats); BEFORE=${BEFORE:-"? ?"}
echo "[стенд] счётчики очереди ДО (queue_dropped user_dropped): $BEFORE"

# 2. Наш :443 — в очередь, обе стороны (исходящий ClientHello и входящий ответ/его отсутствие).
nft add table inet reflex_lab
nft add chain inet reflex_lab out '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_lab out tcp dport 443 queue num 200
nft add chain inet reflex_lab inp '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_lab inp tcp sport 443 queue num 200

# 3. Реальный трафик. Соединение к цели обязано ПЕРЕЖИТЬ окно тишины (5 с) — оттого `max-time`
#    заведомо больше него: оборви пробу раньше, и молчать станет некому. Контроль пройдёт быстро.
#    Оба — напрямую, мимо любого прокси.
# МОЛОТ, а не одиночная проба: приборы судят по одному разговору, а живая сеть даёт разброс —
# двадцать проб отделяют закономерность от случая. Одна проба давала ноль подтверждений там, где
# двадцать дают двадцать: «не измерено» выглядело как «не работает».
i=0
while [ "$i" -lt 20 ]; do
  curl -s4 --noproxy '*' --max-time 10 "https://$TARGET/" >/dev/null 2>&1 &
  i=$((i + 1))
  sleep 0.3
done
curl -s4 --noproxy '*' --max-time 8 "https://$CONTROL/" >/dev/null 2>&1 || true

# 4. Дать движку тикнуть за окно тишины (5с) с запасом.
sleep 9

AFTER=$(qstats); AFTER=${AFTER:-"? ?"}
OVERRUN=$(grep -c Overrun "$LOG" 2>/dev/null || echo 0)
echo "[стенд] счётчики очереди ПОСЛЕ (queue_dropped user_dropped): $AFTER  строк Overrun=$OVERRUN"
# Строка для машинного разбора (`mutants.sh`) — не для человека: тот читает строку выше.
echo "[метрика] queue_dropped=$(echo "$AFTER" | awk '{print $1}') user_dropped=$(echo "$AFTER" | awk '{print $2}') overrun=$OVERRUN"

# 5. Прибраться.
nft delete table inet reflex_lab 2>/dev/null
kill "$ENGINE" 2>/dev/null; wait "$ENGINE" 2>/dev/null

echo "─── лог движка ───────────────────────────"
cat "$LOG"
echo "──────────────────────────────────────────"

# 6. ВЕРДИКТ. Ждём ровно то, что предмет даёт: цель названа по МОЛЧАНИЮ после принятого запроса,
#    контроль молчаливым не назван.
#
#    Повтора клиента здесь НЕ ЖДЁМ, и это не послабление: цель подтверждает запрос `ACK`-ом, то
#    есть доставка состоялась и повторять клиенту нечего. Требуй стенд повтора — он требовал бы
#    симптома, которого у этого рода блокировки нет по построению.
STALLED=0; grep -q "подтверждено: $TARGET молчит" "$LOG" && STALLED=1
CONTROL_HIT=0; grep -q "$CONTROL"                 "$LOG" && CONTROL_HIT=1
echo "[итог] молчание_цели=$STALLED (ждём 1)  контроль=$CONTROL_HIT (ждём 0)"
if [ "$STALLED" = 1 ] && [ "$CONTROL_HIT" = 0 ]; then
  echo "[итог] ЗЕЛЕНО: «$TARGET» принял запрос и замолчал — движок назвал это на реальном трафике; «$CONTROL» чист"
  exit 0
fi
echo "[итог] КРАСНО"
exit 1
