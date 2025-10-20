#!/usr/bin/env bash
set -euo pipefail

# POSIX-safe .env loader
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

URL="${1:-https://localhost:5001}"
OUT="./data/session.json"
TMP="$(mktemp "${OUT}.tmp.XXXXXX")"
echo "Dumping cookies for ${URL}…"
if go run ./cmd/cookiedump --from-browser chrome --for "${URL}" --out "${TMP}"; then
  mv -f "${TMP}" "${OUT}"
  echo "Updated ${OUT}"
else
  echo "cookie dump failed; leaving existing ${OUT} unchanged" >&2
  rm -f "${TMP}"
  exit 1
fi

