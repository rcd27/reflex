#!/usr/bin/env bash
# ВСЁ, ЧТО ГОНЯЕТ CI, — ОДНОЙ КОМАНДОЙ, ЗДЕСЬ.
#
# 20.09.2026 три прогона CI подряд упали на течи двери фасада (`reflex_core::mark::Claim` встал в
# публичную подпись и не был назван фасадом). Локально это ловит `facade-closure.sh` — он и был
# прогнан, но В НАЧАЛЕ работы; дверь расширилась в середине, и вернуться к сторожу никто не
# догадался. Всё прочее гонялось исправно, и зелень прочего читалась как зелень целого.
#
# Болезнь не в забывчивости, а в том, что набор проверок жил ПАМЯТЬЮ: одиннадцать команд, из
# которых человек (и машина) держит в голове три-четыре самых свежих. Здесь он лежит списком, и
# список сверяется с `ci.yml` — иначе разойдутся молча, как расходится всякая копия.
#
# ЧЕГО ЭТОТ СКРИПТ НЕ ДАЁТ. Он не заменяет CI: на раннере есть шаг `sysctl
# kernel.apparmor_restrict_unprivileged_userns=0`, без которого падают тесты, зовущие `unshare -Ur`
# (AppArmor на ubuntu-24.04 запрещает непривилегированные user namespaces). Локально эта настройка
# либо уже такая, либо её правка требует root — и подменять её здесь значило бы менять машину
# человека ради зелёного прогона. Разница названа, а не спрятана.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CI=".github/workflows/ci.yml"
FAILED=()

# ── СВЕРКА СПИСКА С `ci.yml` ──
#
# Предмет сверки — команды `cargo`/`bash`/`./scripts`, стоящие в `run:`. Каждая обязана
# встретиться в теле этого скрипта; иначе CI гоняет то, чего локальный прогон не знает, и
# расхождение обнаружится на пуше, как обнаружилось сегодня.
#
# Предел: сверяется ВХОЖДЕНИЕ строки, а не смысл. Шаг, переписанный на другую форму той же
# проверки, сверку пройдёт — здесь ловится пропажа, не подмена.
mine="$(cat "${BASH_SOURCE[0]}")"
missing=0
while read -r step; do
    [ -z "$step" ] && continue
    if ! grep -qF -- "$step" <<<"$mine"; then
        echo "  НЕТ В ЭТОМ СКРИПТЕ: $step"
        missing=1
    fi
done < <(grep -oP '^\s*(- )?run: \K(cargo|bash|\./scripts).*' "$CI" | sed 's/[[:space:]]*$//')

if [ "$missing" -ne 0 ]; then
    echo "список разошёлся с $CI — допишите недостающее сюда" >&2
    exit 2
fi

step() {
    local what="$1"
    shift
    echo "── $what"
    if ! "$@"; then
        FAILED+=("$what")
    fi
}

# ── ТО ЖЕ, ЧТО НА РАННЕРЕ, В ТОМ ЖЕ ПОРЯДКЕ ──
step "тесты дерева" cargo test --workspace
step "тесты: telling" cargo test -p reflex --features telling
step "тесты: quic" cargo test -p reflex --features quic
step "фасад не знает Linux" cargo check -p reflex --target x86_64-pc-windows-msvc
step "дверь замкнута" ./scripts/facade-closure.sh
step "парк годен без носителя" cargo check -p reflex-instrument --target riscv64gc-unknown-linux-gnu
step "фундамент без 64-битных атомиков" bash scripts/portable.sh
step "документация собирается" cargo doc --workspace --no-deps

# РАЗРЕЗ ПАРКА — не `cargo`-команда, а греп по дереву зависимостей; в `ci.yml` он живёт
# многострочным `run:`, и сверка выше его не видит. Повторён здесь дословно.
echo "── в парке нет ни носителя, ни платформы"
if cargo tree -p reflex-instrument --edges normal \
   | grep -E '(nfq|ring|tokio|reflex-linux|reflex-engine|reflex-runtime) v'; then
    FAILED+=("разрез парка")
fi

# ── СВОИ СТОРОЖА, КОТОРЫХ НА РАННЕРЕ НЕТ ──
#
# Они требуют ночного тулчейна либо просто не заведены в `ci.yml`; гонять их перед пушем всё равно
# надо, и место им здесь, а не в памяти.
step "канон и дерево" ./scripts/canon.sh
step "бюджет предупреждений" ./scripts/warnings.sh

echo "──"
if [ "${#FAILED[@]}" -ne 0 ]; then
    printf 'УПАЛО: %s\n' "${FAILED[*]}" >&2
    exit 1
fi
echo "всё, что гоняет CI, прогнано здесь — и зелено"
