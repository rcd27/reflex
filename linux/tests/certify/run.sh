#!/usr/bin/env bash
# ПРОГОН ВСЕХ ЗАКОНОВ КАЛИТКИ — ОДИН ВХОД, ОДИН ОТЧЁТ.
#
# # Что здесь bash, а что нет
#
# Вердикт этот скрипт НЕ ВЫНОСИТ и вынести не может: каждую строку отчёта печатает бинарь,
# считавший закон рядом с наблюдением. Прежний стенд (`tests/e2e/run-e2e.sh`, снят 05.09) судил
# именно оболочкой — `run_test "name" bash -c '…'` смотрел на код возврата, — и связь между
# наблюдением в контейнере и утверждением на хосте была честным словом.
#
# Здесь оболочка делает ровно то, для чего годится: ведёт ПОРЯДОК. Наблюдатель стартует раньше
# отправителя, том чист, отчёт мира удалён, обстановка ядра возвращена к исходной между прогонами.
# Всё это человек прежде держал в голове и потому иногда не держал: первое живое обезоруживание
# прошло на томе с кадром прошлого прогона, и действительность опиралась на остаток.
#
# # Идентификаторы ЛАТИНИЦЕЙ, речь по-русски
#
# `bash` не принимает кириллицу в именах переменных, в отличие от `zsh`. Первая редакция этого
# файла была написана русскими именами, и она НЕ ПАДАЛА заметно: печатала «стенд не поднялся» и
# выходила — то есть выглядела как честная неудача стенда. Та же грабля записана в CLAUDE.md про
# git-хуки, и найдена она там тем же способом — прогоном, а не чтением.
#
# # Отчёт называет и НЕПРОВЕРЕННОЕ
#
# Строка «все зелёные» без этого врёт о полноте. Две ветви законов на живом ядре недостижимы по
# построению, и о них сказано в отчёте, а не только в README, — иначе читатель решит, что покрыто
# всё.
set -u

STAND="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f $STAND/compose.yml"
MARK="0x2a"
PORT=5333

held=0
broken=0
no_verdict=0

# СЧИТАЕТ ПО КОДУ ВОЗВРАТА БИНАРЯ, А НЕ ПО ЕГО ТЕКСТУ. Разбирай оболочка вывод — она стала бы
# вторым толкователем вердикта, и разойтись с первым было бы делом одной опечатки.
tally() {
    local name="$1" out="$2" code="$3"
    printf '  %-9s ' "$name"
    case $code in
        0) held=$((held + 1));             printf '✓ %s\n' "$out" ;;
        1) broken=$((broken + 1));         printf '✗ %s\n' "$out" ;;
        *) no_verdict=$((no_verdict + 1)); printf '· %s\n' "$out" ;;
    esac
}

run() {
    local name="$1"; shift
    local out code
    out="$("$@" 2>&1)"; code=$?
    tally "$name" "$out" "$code"
}

echo "═══ ПОДЪЁМ СТЕНДА (том чистый: иначе действительность обопрётся на остаток) ═══"
$COMPOSE down -v >/dev/null 2>&1
$COMPOSE up -d --build >/dev/null 2>&1 || { echo "стенд не поднялся"; exit 2; }
sleep 5

# РОЛИ ПРОВЕРЯЮТСЯ ЖИВЫМИ ПОИМЁННО, и это не перестраховка (#326, 05.09.2026).
#
# `up -d` отвечает успехом, когда контейнер СТАРТОВАЛ, — умри он секундой позже, оболочка этого не
# узнает. Первый же прогон закона обрыва так и прошёл: опечатка в имени цепочки (`fwd` —
# зарезервированное слово `nft`) уронила движок, `docker exec` вернул код 1 на каждый закон, и
# устройство напечатало ДЕВЯТЬ НАРУШЕНИЙ. Беда стенда выглядела виной подопытного — ровно та
# подмена, которую `Verdict::Invalid` заведён различать, только этажом выше закона.
for role in certify-witness certify-dut certify-queue certify-client; do
    alive=$(docker inspect "$role" --format '{{.State.Running}}' 2>/dev/null)
    test "$alive" = "true" || {
        echo "роль $role не жива — вердиктов не будет, разбирайте стенд:"
        docker logs "$role" 2>&1 | tail -5
        $COMPOSE down -v >/dev/null 2>&1
        exit 2
    }
done

# ПО АДРЕСУ, А НЕ ПО ИМЕНИ. Свидетель здесь заодно адресат проб, и при его остановке падает резолв
# имени — прогон кончается ошибкой раньше, чем закон скажет своё. Первое обезоруживание закона
# отказа именно так и провалилось: вышло `invalid` по чужой причине, и дыра осталась невидимой.
WITNESS=$(docker inspect certify-witness --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "  свидетель: $WITNESS"
echo

echo "═══ AF_PACKET ═══"
run inject docker exec certify-dut certify inject eth0 /shared/far.pcap "nonce-inject-$$"

# НАБЛЮДЕНИЕ СНИМАЕТ ТОТ ЖЕ ПРОЦЕСС, ЧТО СЛУШАЛ. Наблюдатель обязан стартовать раньше отправителя,
# поэтому он уходит в фон, а оболочка ДОЖИДАЕТСЯ его и читает то, что напечатал он сам.
#
# Первая редакция запускала наблюдателя впустую, а вердикт снимала ВТОРЫМ запуском по готовому
# отчёту мира — и это было бы враньём: у второго процесса своего наблюдения нет вовсе, кадры прошли
# мимо него. Гейт `bash_business_logic` указал на это раньше, чем стенд успел соврать.
docker exec certify-dut sh -c 'rm -f /shared/sent.txt'
SPEECH=$(mktemp)
docker exec certify-dut certify observe eth0 "nonce-observe-$$" /shared/sent.txt 6000 >"$SPEECH" 2>&1 &
listening=$!
sleep 1
docker exec certify-witness certify emit eth0 "nonce-observe-$$" 50 /shared/sent.txt >/dev/null 2>&1
wait $listening; watched=$?
tally observe "$(cat "$SPEECH")" "$watched"
rm -f "$SPEECH"
echo

echo "═══ ОЧЕРЕДЬ ЯДРА (бэкенд продукта) ═══"
run hold    docker exec certify-queue certify hold 0 /shared/far.pcap "nonce-hold-$$" "$WITNESS:$PORT"
run refuse  docker exec certify-queue certify refuse 0 /shared/far.pcap "nonce-refuse-$$" "$WITNESS:$PORT"
run rewrite docker exec certify-queue certify rewrite 0 /shared/far.pcap "nonce-rw-aaaa" "nonce-rw-zzzz" "$WITNESS:$PORT"
run mark    docker exec certify-queue certify mark 0 /shared/far.pcap "$MARK" "nonce-mark-$$" "$WITNESS:$PORT"
echo

echo "═══ ОБРЫВ: ДВЕ ГРАНИЦЫ, ДВА СВИДЕТЕЛЯ ═══"
# ПОДОПЫТНЫЙ ТОЛЬКО ЖДЁТ, ПРОБУ ШЛЁТ КЛИЕНТ — и это не удобство устройства, а условие закона.
# Останься сторона отправителя тем же процессом, что обрывает, — доставку извещения заверял бы
# доставляющий, то есть ровно тот корень, ради снятия которого написан весь модуль.
#
# Порядок обязателен: ожидание поднимается раньше пробы. Наоборот — пакет уйдёт в очередь, которую
# никто не слушает, и правило дропнет его молча.
SEVER=$(mktemp)
docker exec certify-queue certify sever 1 /shared/far.pcap /shared/near.pcap "nonce-sever-$$" sender >"$SEVER" 2>&1 &
severing=$!
sleep 1
docker exec certify-client certify probe-tcp "$WITNESS:$PORT" "nonce-sever-$$" >/dev/null 2>&1
wait $severing; severed=$?
tally sever "$(cat "$SEVER")" "$severed"
rm -f "$SEVER"
echo

echo "═══ ОБЕЗОРУЖИВАНИЕ: законы обязаны уметь КРАСНЕТЬ ═══"
# Проверка, которую не удалось заставить покраснеть, не в покрытии. Обстановка ядра меняется и
# ВОЗВРАЩАЕТСЯ — прогон, отравляющий следующий, хуже отсутствующего.

# Читатель метки переезжает ВЫШЕ очереди: пакет продолжает обход с места, где его забрали, и метку
# не увидит никто. Грабля записана у `Answer::Marked` с 31.08 и до закона не проверялась ничем.
docker exec certify-queue sh -c "nft flush chain inet certify post && nft 'add chain inet certify above { type filter hook output priority -10; }' && nft add rule inet certify above meta mark $MARK counter" >/dev/null 2>&1
run 'mark^' docker exec certify-queue certify mark 0 /shared/far.pcap "$MARK" "nonce-above-$$" "$WITNESS:$PORT"
docker exec certify-queue sh -c "nft delete chain inet certify above; nft add rule inet certify post meta mark $MARK counter" >/dev/null 2>&1

# Чужое правило НИЖЕ очереди отменяет наше решение: мы отпускаем, а пакет не идёт.
docker exec certify-queue nft add rule inet certify post udp dport $PORT drop >/dev/null 2>&1
run 'hold_v' docker exec certify-queue certify hold 0 /shared/far.pcap "nonce-overruled-$$" "$WITNESS:$PORT"
docker exec certify-queue sh -c "nft flush chain inet certify post && nft add rule inet certify post meta mark $MARK counter" >/dev/null 2>&1

# СТОРОНЫ ПЕРЕПУТАНЫ: извещение адресуется получателю вместо отправителя, то есть уезжает ЦЕЛИ.
# Правка одной строки в живом коде, и ни закон отказа, ни закон инъекции её не увидят: первый
# скажет «исходное не прошло», второй — «наш кадр наблюдаем». Красит эту беду только адресация.
SWAP=$(mktemp)
docker exec certify-queue certify sever 1 /shared/far.pcap /shared/near.pcap "nonce-swap-$$" receiver >"$SWAP" 2>&1 &
swapped=$!
sleep 1
docker exec certify-client certify probe-tcp "$WITNESS:$PORT" "nonce-swap-$$" >/dev/null 2>&1
wait $swapped; misdirected=$?
tally 'sever→' "$(cat "$SWAP")" "$misdirected"
rm -f "$SWAP"

# Свидетель остановлен: закон обязан сказать «вердикта нет», а не подтвердить способность.
docker stop certify-witness >/dev/null 2>&1
run 'mute' docker exec certify-queue certify refuse 0 /shared/far.pcap "nonce-dead-$$" "$WITNESS:$PORT"
docker start certify-witness >/dev/null 2>&1
sleep 3
echo

echo "═══ ИТОГ ═══"
echo "  держится: $held · нарушено: $broken · без вердикта: $no_verdict"
echo
echo "  ОЖИДАЕТСЯ: 7 держится (законы) · 3 нарушено и 1 без вердикта (обезоруживание)."
echo "  Всякое иное число — находка, и разбирать её надо до того, как поверить зелёному."
echo
echo "  НЕ ПРОВЕРЕНО ЗДЕСЬ, и это не забывчивость:"
echo "    · holds/PassedBeforeAnswer  — без правила носителя нет вовсе, закон не начинается;"
echo "    · refuses/PassedAnyway      — ядро исполняет Drop надёжно, подделать нечем;"
echo "    · отказ ядра (NotTaken)     — воспроизводится лишь протухшим сообщением очереди;"
echo "    · severs/ПОРЯДОК извещения  — «дошло раньше, чем цель ответила» здесь невыразимо:"
echo "      у пакета, которого нет, нет метки времени. Выразимо станет с ЭХО-РОЛЬЮ цели —"
echo "      собеседником, метящим ответ своим моментом; условие и цена — в докблоке"
echo "      core/src/certify/severing.rs, чтобы долг не жил номером чужого тикета."
echo "  Все прочие проверены в памятном мире: cargo test -p reflex-core."

$COMPOSE down -v >/dev/null 2>&1

# КОД ВОЗВРАТА — ПО ЗАКОНАМ, А НЕ ПО ОБЕЗОРУЖИВАНИЮ. Семь держащихся законов есть условие
# годности; красное обезоруживание — ожидаемое поведение, и смешивать их значило бы получить
# зелёный прогон при мёртвой проверке.
test "$held" -eq 7
