#!/bin/sh
# Проверка на реальном трафике с хоста: собрать образ, прогнать движок на РЕАЛЬНОМ трафике вантажа,
# пробросить вердикт. Требует: docker, вантаж за ТСПУ (иначе цель не роняется — см. README).
set -eu
cd "$(dirname "$0")"
echo "[verify] сборка образа (multi-stage)…"
docker compose build engine
echo "[verify] прогон движка на реальном трафике…"
exec docker compose run --rm engine
