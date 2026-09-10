#!/bin/sh
# Дифференциальный стенд (задача 11): ДВА движка (ct-край и местный край) на ОДНОМ netns — иначе
# правила nft развели бы их по разным сетевым пространствам, и через каждую очередь прошёл бы СВОЙ
# трафик, а не ОДИН И ТОТ ЖЕ пакет.
#
# ДВЕ ОТДЕЛЬНЫЕ ЦЕПОЧКИ на одном хуке, СОСЕДНИЕ ПРИОРИТЕТЫ (-150 и -140), по ОДНОМУ правилу
# `queue num` в каждой — а НЕ «одна цепочка, два правила подряд», как задумывалось сперва. Причина —
# ЗАМЕР, не рассуждение: вердикт `NF_ACCEPT` из очереди завершает обход ИМЕННО ЭТОЙ цепочки, а не
# переходит к следующему её правилу, так что второе `queue num` в ТОЙ ЖЕ цепочке недостижимо по
# построению ядра — никакая перестановка правил или флаг этого не меняет. Проверено ДВАЖДЫ на двух
# ОДИНАКОВЫХ ct-движках (один и тот же бинарь, чтобы исключить `Nfqueue::local` из подозреваемых
# методом, а не рассуждением): «одна цепочка, оба queue num» — второе правило получило 0 наблюдений
# из 20 хотя первое поймало все 20; «две цепочки, один хук, приоритеты -150/-140, по одному queue
# num» — оба получили по 20. Кто добавляет рядом третий движок — здесь третья цепочка, свой
# приоритет, не третье правило в существующей.
#
# ДИФФЕРЕНЦИАЛ ОТ ЭТОГО НЕ СТРАДАЕТ. Сравниваются МНОЖЕСТВА наблюдений об одном и том же трафике,
# а не их моменты: пакет проходит обе цепочки ПОСЛЕДОВАТЕЛЬНО (хук идёт по приоритету), оба движка
# видят ТОТ ЖЕ САМЫЙ пакет — расходится только момент решения (кто из двух процессов тикнул раньше),
# а момент в сравнение `compare.sh` не входит (см. его докблок: множества, не последовательности).
# Взаимного влияния через марку тоже нет: ct-движок пишет `ct_mark`, `Local` его не читает и ведёт
# свою карту в юзерспейсе (задача 10) — цепочки независимы и по данным, не только по порядку.
set -u
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy 2>/dev/null

TARGET=${TARGET:-rutracker.org}   # тихий дроп по SNI на нашем вантаже
CONTROL=${CONTROL:-vk.com}        # чистая цель — контроль на ложное срабатывание
CT_LOG=/tmp/ct.log
LOCAL_LOG=/tmp/local.log

echo "[стенд] цель=$TARGET  контроль=$CONTROL  ct=очередь200  local=очередь201"

# 0. Предпосылка КРАЯ engine-ct: `compose.yml` ставит `nf_conntrack_acct`/`timestamp` namespaced-
#    sysctl'ами ПРИ СОЗДАНИИ netns — единственном моменте, когда /proc/sys ещё не read-only. Здесь
#    их только ЧИТАЕМ, не пишем: запись поверх готового ничего не решает, а её отказ ("Read-only
#    file system") не говорит о состоянии края — прежняя формулировка это путала (см. `lab/engine`,
#    почина той же ошибки датирована тем же коммитом).
ACCT=$(cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null || echo '?')
TS=$(cat /proc/sys/net/netfilter/nf_conntrack_timestamp 2>/dev/null || echo '?')
echo "[стенд] учёт conntrack (для engine-ct): acct=$ACCT timestamp=$TS (ставит compose.yml)"
if [ "$ACCT" != "1" ] || [ "$TS" != "1" ]; then
  echo "[стенд] ВНИМАНИЕ: учёт и правда не включён — engine-ct не поднимется, engine-local не тронут этим вовсе" >&2
fi

# 1. Оба движка — ДО правил nft: очередь без слушателя дропает трафик.
CARRIER=ct    QUEUE=200 detect-silent-drop-edges >"$CT_LOG" 2>&1 &
CT_PID=$!
CARRIER=local QUEUE=201 detect-silent-drop-edges >"$LOCAL_LOG" 2>&1 &
LOCAL_PID=$!
sleep 1
FAILED=0
kill -0 "$CT_PID" 2>/dev/null || { echo "[стенд] engine-ct не поднялся:"; cat "$CT_LOG"; FAILED=1; }
kill -0 "$LOCAL_PID" 2>/dev/null || { echo "[стенд] engine-local не поднялся:"; cat "$LOCAL_LOG"; FAILED=1; }
[ "$FAILED" = 0 ] || exit 2

# 2. ДВЕ цепочки на каждый хук, разные приоритеты, по ОДНОМУ queue num в каждой — контракт стенда
#    (докблок выше: «одна цепочка, два queue num» недостижима по построению ядра, замерено).
nft add table inet reflex_edges
nft add chain inet reflex_edges out_ct    '{ type filter hook output priority -150; policy accept; }'
nft add rule  inet reflex_edges out_ct    tcp dport 443 queue num 200
nft add chain inet reflex_edges out_local '{ type filter hook output priority -140; policy accept; }'
nft add rule  inet reflex_edges out_local tcp dport 443 queue num 201
nft add chain inet reflex_edges inp_ct    '{ type filter hook input priority -150; policy accept; }'
nft add rule  inet reflex_edges inp_ct    tcp sport 443 queue num 200
nft add chain inet reflex_edges inp_local '{ type filter hook input priority -140; policy accept; }'
nft add rule  inet reflex_edges inp_local tcp sport 443 queue num 201

# 3. Боевой трафик — МОЛОТОМ, не одиночной пробой: краевой прибор судит по возрасту потока, и одному
#    соединению редко случается пережить порог под наблюдением (тот же урок, что в `lab/engine`).
hammer() {
  pids=""
  i=0
  while [ "$i" -lt 20 ]; do
    curl -s4 --noproxy '*' --max-time 10 "https://$1/" >/dev/null 2>&1 &
    pids="$pids $!"
    i=$((i + 1))
    sleep 0.3
  done
  for pid in $pids; do wait "$pid" 2>/dev/null; done
}
hammer "$TARGET"
hammer "$CONTROL"

# 4. Дать движкам тикнуть за окно тишины (5с) с запасом.
sleep 9

# 5. Прибраться.
nft delete table inet reflex_edges 2>/dev/null
kill "$CT_PID" "$LOCAL_PID" 2>/dev/null
wait "$CT_PID" "$LOCAL_PID" 2>/dev/null

echo "─── лог engine-ct (очередь 200) ────────────"
cat "$CT_LOG"
echo "─── лог engine-local (очередь 201) ─────────"
cat "$LOCAL_LOG"
echo "──────────────────────────────────────────"

# 6. Сверка МНОЖЕСТВ — сам вердикт стенда, включая порог пустоты (докблок `compare.sh`).
compare.sh "$CT_LOG" "$LOCAL_LOG"
