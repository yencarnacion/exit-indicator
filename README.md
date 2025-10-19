# exit-indicator

Detect large sell/buy walls on SMART‑aggregated Level II (DOM) depth for US equities using the [IBKR Client Portal Web API (Gateway)][ibkr-cp-gateway]. The app serves a minimal Web UI (default http://localhost:8086) and raises an audio/visual alert when an aggregated price level crosses your share threshold.

> What it does (one sentence): Watches the top‑10 offer (ask) or bid levels across SMART venues, aggregates by price, and alerts when any one price level’s total shares ≥ your threshold.

---

## Features

- SMART aggregation: sums shares across venues at the same price (ask or bid)
- Top‑10 ladder (best price outward); 1s default cooldown per (symbol, price) to avoid spam
- Threshold control (default 20,000 shares) editable live in the UI
- Side toggle: ASK (offer) or BID
- Session persistence for the IB Gateway (cookies stored at `session_store_path`)
- Auto‑reconnect and auto‑resubscribe after disconnects
- Zero‑build Web UI: ticker input, start/stop, threshold field, side toggle, status badge, ladder table with meters, alert log, and “test sound”
- Audio alerts: plays `web/sounds/hey.mp3` if present, otherwise a WebAudio beep fallback (no server‑side audio)
- Minimal runtime deps: a single Go process + IBKR Client Portal Gateway

---

## Contents
- [Quick Start (TL;DR)](#quick-start-tldr)
- [Retail Setup & Usage Guide](#retail-setup--usage-guide)
  - [1) IBKR account & market‑data you need](#1-ibkr-account--market-data-you-need)
  - [2) Install IBKR Client Portal Gateway (Win/macOS/Linux)](#2-install-ibkr-client-portal-gateway-winmacoslinux)
  - [3) Install Go 1.21+ & get this app](#3-install-go-121--get-this-app)
  - [4) Configure exit-indicator](#4-configure-exit-indicator)
  - [5) First run checklist](#5-first-run-checklist)
  - [6) Daily operation](#6-daily-operation)
  - [7) (Optional) Run as a service](#7-optional-run-as-a-service)
  - [8) Security notes](#8-security-notes)
- [How it works](#how-it-works)
- [HTTP & WebSocket API](#http--websocket-api)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Development notes & tests](#development-notes--tests)
- [References](#references)

---

## Quick Start (TL;DR)

1) Ensure your IBKR account is funded and has Level II/market‑depth entitlements for the US exchanges you care about (e.g., NASDAQ TotalView, NYSE OpenBook, NYSE ArcaBook). SMART depth aggregates only from the depth feeds you subscribe to.

2) Install and run the [IBKR Client Portal Gateway][ibkr-cp-gateway], then sign in (with 2FA) at https://127.0.0.1:5000/. Keep it running.

3) Run this app:
```bash
./go.sh
# then open:
#   http://localhost:8086/
```
In the UI, enter a ticker (e.g., AAPL), choose ASK or BID, set a threshold (shares), and click Subscribe.

---

## Retail Setup & Usage Guide

### 1) IBKR account & market‑data you need
To see Level II/DOM via SMART aggregation in APIs, IBKR aggregates the depth from the exchanges for which your user is subscribed. You only see depth from the venues you pay for; SMART stitches them together.

For US stocks, a common baseline looks like:
- NASDAQ TotalView‑OpenView (Level II)
- NYSE OpenBook (Level II)
- NYSE ArcaBook (Level II)
- Optionally: Cboe US depth products (BZX/EDGX/etc.)

Notes:
- Level I (top‑of‑book) is not a substitute for Level II; DOM requires Level II packages per venue
- IBKR limits simultaneous Level II symbols based on your market‑data line allocation. This app monitors one symbol at a time
- Subscription names/pricing/rules vary by region; confirm in IBKR’s Market Data docs
- Most accounts must be funded before live market‑data subscriptions are enabled

### 2) Install IBKR Client Portal Gateway (Win/macOS/Linux)
This app talks to Client Portal Gateway (not TWS/IB Gateway). You run a local web server from IBKR, log in once with 2FA, and then local apps use its REST/WS endpoints at https://127.0.0.1:5000/v1/api. See the official docs: [IBKR Client Portal Web API (Gateway)][ibkr-cp-gateway].

Linux/macOS:
```bash
cd /path/to/clientportal.gw
./bin/run.sh root/conf.yaml
# Then open https://127.0.0.1:5000/ in a browser, accept the self‑signed cert, and log in (2FA).
```

Windows:
```bat
cd \path\to\clientportal.gw
bin\run.bat root\conf.yaml
rem Then open https://127.0.0.1:5000/ in a browser and log in (2FA).
```

Minimal conf.yaml pointers (for local use):
- `listenPort: 5000` — change if 5000 is busy
- `listenSsl: true` — keep for local HTTPS; with a reverse proxy, you may terminate TLS at the proxy
- `ips.allow:` — restrict/expand the allowlist for LAN/VPN access. Do not expose the gateway to the public internet

Java note: Some downloads bundle a JRE. If yours does not and you see “java not found,” install OpenJDK 11+ and re‑run run.sh / run.bat.

### 3) Install Go 1.21+ & get this app
Install Go (1.21+) from your platform’s package manager or from https://go.dev.
```bash
git clone <your repo url> exit-indicator
cd exit-indicator
```

### 4) Configure exit-indicator
The app loads config.yaml at startup:
```yaml
# config.yaml
port: 8086
default_threshold_shares: 20000
sound_file: "./web/sounds/hey.mp3"
cooldown_seconds: 1
smart_depth: true
levels_to_scan: 10
price_reference: "best_ask"
log_level: "info"
ibkr_gateway_url: "https://127.0.0.1:5000"
session_store_path: "./data/session.json"
```
- `ibkr_gateway_url` must match where your Client Portal Gateway is reachable
- `sound_file` is optional. If missing, the browser plays a short beep
- `session_store_path` stores cookies/tokens so your session survives restarts
- `levels_to_scan` is fixed at 10 (top‑10 from best price)
- `price_reference` is currently "best_ask" (applies when ASK side is selected)

Optional environment (e.g., `.env` during local dev):
```env
EXIT_INDICATOR_ALLOW_START=1
```
This allows `/api/start` before the gateway reports “connected” (handy for UI testing).

### 5) First run checklist
- Confirm your Level II/DOM subscriptions in Client Portal
- Start Client Portal Gateway and fully sign in at https://127.0.0.1:5000/ (2FA). You can verify with GET /v1/api/iserver/auth/status → "authenticated": true
- Run the app:
```bash
./go.sh
# open:
#   http://localhost:8086/
```
In the UI: enter a ticker (e.g., AAPL), pick Offer (ASK) or Bid, set Threshold (shares), then Subscribe. Use “Test Sound” to confirm audio works (or you’ll get the fallback beep).

### 6) Daily operation
- Start order: Gateway first (log in) → then start exit-indicator
- The app reconnects automatically if the gateway drops and will re‑subscribe when connected
- Session persistence: cookies are saved to ./data/session.json; if auth becomes invalid, open the Gateway URL and sign in again
- One symbol at a time: the ladder and alerts apply to the current UI subscription

### 7) (Optional) Run as a service

#### Linux (systemd)
Client Portal Gateway service:
```ini
# /etc/systemd/system/ibkr-gateway.service
[Unit]
Description=IBKR Client Portal Gateway
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/clientportal.gw
ExecStart=/opt/clientportal.gw/bin/run.sh /opt/clientportal.gw/root/conf.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

exit-indicator service:
```ini
# /etc/systemd/system/exit-indicator.service
[Unit]
Description=exit-indicator (SMART depth alert)
After=network-online.target ibkr-gateway.service
Requires=ibkr-gateway.service

[Service]
Type=simple
WorkingDirectory=/opt/exit-indicator
ExecStart=/usr/local/go/bin/go run ./cmd/exit-indicator/main.go
Environment=EXIT_INDICATOR_ALLOW_START=0
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```
Enable & start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ibkr-gateway.service
sudo systemctl enable --now exit-indicator.service
```

#### macOS (launchd)
Create `~/Library/LaunchAgents/com.example.ibkr-gateway.plist` pointing to `clientportal.gw/bin/run.sh`, and `~/Library/LaunchAgents/com.example.exit-indicator.plist` pointing to `go run ./cmd/exit-indicator/main.go`, then load:
```bash
launchctl load ~/Library/LaunchAgents/com.example.ibkr-gateway.plist
launchctl load ~/Library/LaunchAgents/com.example.exit-indicator.plist
```

#### Windows (Task Scheduler)
Create two “At logon” tasks:
- Client Portal Gateway → `bin\run.bat root\conf.yaml`
- exit-indicator → run:
```bat
go run .\cmd\exit-indicator\main.go
```
Want a native binary?
```bash
go build -o exit-indicator ./cmd/exit-indicator
```

### 8) Security notes
- Never expose Client Portal Gateway directly to the public internet. It ships with a self‑signed cert and is designed for localhost/trusted networks. For remote access, use a VPN or a reverse proxy and a strict allowlist
- This app skips certificate verification only for 127.0.0.1 (gateway default). If you move the gateway to another host, use proper TLS and firewall rules
- `session_store_path` contains authentication cookies — store it on a secure disk and protect backups

---

## How it works
- On startup, the app loads `config.yaml`, initializes the HTTP + WebSocket server, and starts an IBKR client reconnect loop
- The UI “Subscribe” posts `/api/start` with `{ symbol, threshold?, side? }`
- The IBKR depth feed subscribes to SMART DOM for the symbol (via a WebSocket topic internally)
- On each snapshot, the aggregator:
  - Picks the selected side (ASK/BID)
  - Aggregates per‑price across venues
  - Sorts top‑10 from the best price
  - Emits a book update
  - Raises an alert if any level’s sum ≥ threshold and the (symbol, price) cooldown elapsed (default 1s)
- Alerts are pushed over WebSocket; the browser plays the MP3 (or beep)

---

## HTTP & WebSocket API
- `GET /api/health` → `{ ok, connected }`
- `GET /api/config` → runtime config (threshold, side, sound availability)
- `POST /api/start` `{ symbol, threshold?, side? }`
- `POST /api/stop`
- `POST /api/threshold` `{ threshold }` (≥ 1)
- `POST /api/side` `{ side: "ASK" | "BID" }`
- `GET /ws` (WebSocket)

Messages:
- `{ type: "status", data: { connected, symbol, side } }`
- `{ type: "book", data: { levels: [{ price, sumShares, rank }], side } }`
- `{ type: "alert", data: { symbol, side, price, sumShares, timeISO } }`
- `{ type: "error", data: { message } }`

---

## Troubleshooting & FAQ
- I subscribed to market data but see no DOM: Ensure you have Level II (DOM) subscriptions for the venues you want, not just Level I. SMART aggregation uses the depth feeds you subscribe to
- Gateway says “not authenticated”: Open https://127.0.0.1:5000/ and sign in (2FA). You can check `GET /v1/api/iserver/auth/status`. The app will retry and reconnect once authenticated
- How many L2 tickers can I watch: IBKR limits simultaneous L2 symbols based on your market‑data line allocation. This app uses one at a time
- Can I view the UI remotely: Yes. The UI is on `http://<host>:8086`. If you reverse‑proxy with HTTPS, browsers will use `wss://` automatically for the WebSocket
- Linux servers without a GUI: The gateway login requires a one‑time browser login for auth. Many users do that locally or via port‑forwarding; headless tools exist but use at your own risk
- The sound doesn’t play: Place an MP3 at `web/sounds/hey.mp3`. If missing, the browser falls back to a short beep. To clear/refresh session, delete `./data/session.json` and re‑login

---

## Development notes & tests
- Requires Go 1.21+
- Logging via Go’s `slog` with configurable level
- IBKR WS payload isolation: `internal/ibkrcp/depth_feed.go`

Run unit tests:
```bash
go test ./...
```
Covered:
- Aggregation & top‑10 selection from best price
- Cooldown enforcement
- Symbol normalization

---

## References
- [IBKR Client Portal Web API (Gateway) – official docs][ibkr-cp-gateway]
- Market‑data subscriptions overview and where to subscribe in Client Portal
- Level II requirement for DOM displays
- L2 symbol limits per market‑data allocation & booster packs
- Client Portal Gateway: launch/authenticate docs & common run commands
- Self‑signed cert / remote‑access hardening (keep local, use allowlist or reverse proxy)

[ibkr-cp-gateway]: https://interactivebrokers.github.io/cpwebapi/

