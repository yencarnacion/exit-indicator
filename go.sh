#!/usr/bin/env bash
set -euo pipefail

# POSIX-safe .env loader
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

export EXIT_INDICATOR_LOGIN_WAIT_SECONDS=900   # 15 minutes

export EXIT_INDICATOR_IBKR_RL=2
rm -f ./data/session.json

go run ./cmd/exit-indicator/main.go
