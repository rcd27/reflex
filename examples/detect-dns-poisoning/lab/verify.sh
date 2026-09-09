#!/bin/sh
set -eu
cd "$(dirname "$0")"
echo "[verify] сборка образа (multi-stage)…"
docker compose build engine
echo "[verify] прогон движка на боевом трафике…"
exec docker compose run --rm engine
