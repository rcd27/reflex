#!/usr/bin/env bash
# Прогон сторожа замкнутости фасада. Довод и пределы — в шапке `facade-closure.py`.
#
# НОЧНОЙ ТУЛЧЕЙН нужен не прихотью: дерево предметов в машинном виде (`--output-format json`) даёт
# только он. Стабильный отдаёт HTML, по которому пришлось бы грепать, — то есть ровно тот замер,
# от которого сторож и заведён.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! cargo +nightly --version >/dev/null 2>&1; then
    echo "нужен ночной тулчейн: rustup toolchain install nightly" >&2
    exit 2
fi

OUT="${CARGO_TARGET_DIR:-target}/doc/reflex.json"
cargo +nightly rustdoc -p reflex --all-features -- -Z unstable-options --output-format json >/dev/null
exec python3 scripts/facade-closure.py "$OUT"
