#!/usr/bin/env bash
set -euo pipefail
export $(grep -v '^#' .env | xargs -d '\n' -r) || true
go run ./cmd/exit-indicator/main.go


