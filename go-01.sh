#!/usr/bin/env bash
set -euo pipefail

# POSIX-safe .env loader
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

rm -f ./data/session.json


go run ./cmd/cookiedump --from-browser chrome \
  --for https://localhost:5001 \
  --out ./data/session.json

