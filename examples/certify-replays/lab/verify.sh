#!/bin/sh
# Боевая верификация с хоста: собрать образ, прогнать движок на РЕАЛЬНОМ трафике вантажа,
# пробросить вердикт. Требует: docker, вантаж за ТСПУ (иначе цель не роняется — см. README).
set -eu
cd "$(dirname "$0")"
echo "[verify] сборка образа (multi-stage)…"
docker compose build engine
echo "[verify] прогон 1/2 — ИСПОРЧЕННАЯ машина: стенд обязан покраснеть…"
docker compose run --rm -e MUTANT=1 engine
echo "[verify] прогон 2/2 — исправная машина: §10 обязан держаться…"
exec docker compose run --rm engine
