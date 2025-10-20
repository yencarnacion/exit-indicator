package ibkrcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
    "net"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/shopspring/decimal"

	"exit-indicator/internal/depth"

	"github.com/gorilla/websocket"
)

type DepthFeed interface {
	Run(ctx context.Context, onStatus func(connected bool))
	SubscribeSymbol(symbol string) error
	Unsubscribe()
	Updates() <-chan depth.Update
	Errors() <-chan error
	Connected() bool
	Close()
}

// IBKRCPGatewayDepthFeed implements DepthFeed against the Client Portal Gateway.
// It maintains a single subscription (one active symbol at a time), with reconnect & resubscribe.
type IBKRCPGatewayDepthFeed struct {
	client *Client
	log    *slog.Logger

	mu        sync.RWMutex
	symbol    string
	conid     int64
    acctId    string
	connected bool

	updCh  chan depth.Update
	errCh  chan error
	wsConn *websocket.Conn

	ctx    context.Context
	cancel context.CancelFunc
}

func NewGatewayDepthFeed(client *Client, logger *slog.Logger) *IBKRCPGatewayDepthFeed {
	return &IBKRCPGatewayDepthFeed{
		client: client,
		log:    logger,
		updCh:  make(chan depth.Update, 1024),
		errCh:  make(chan error, 16),
	}
}

func (f *IBKRCPGatewayDepthFeed) Connected() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.connected
}

func (f *IBKRCPGatewayDepthFeed) setConnected(v bool) {
	f.mu.Lock()
	f.connected = v
	f.mu.Unlock()
}

func (f *IBKRCPGatewayDepthFeed) Updates() <-chan depth.Update { return f.updCh }
func (f *IBKRCPGatewayDepthFeed) Errors() <-chan error         { return f.errCh }

func (f *IBKRCPGatewayDepthFeed) SubscribeSymbol(symbol string) error {
	canon := strings.ToUpper(strings.TrimSpace(symbol))
	if canon == "" {
		return fmt.Errorf("empty symbol")
	}
	f.mu.Lock()
	f.symbol = canon
	f.mu.Unlock()
	// Trigger resubscription by closing ws; the run loop will reconnect and resubscribe
	// if already connected. Otherwise next successful connect will subscribe.
	if f.wsConn != nil {
		_ = f.wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "resub"))
		_ = f.wsConn.Close()
	}
	return nil
}

func (f *IBKRCPGatewayDepthFeed) Unsubscribe() {
    // Capture current values while holding the lock, then clear symbol/conid.
    f.mu.Lock()
    ws := f.wsConn
    conid := f.conid
    acct := f.acctId
    f.symbol = ""
    f.conid = 0
    f.mu.Unlock()

    // Send unsubscribe(s) if possible, then close the socket.
    if ws != nil && conid != 0 {
        if acct != "" {
            _ = ws.WriteMessage(websocket.TextMessage, []byte(
                fmt.Sprintf("ubd+%s+%d+SMART", acct, conid),
            ))
        }
        _ = ws.WriteMessage(websocket.TextMessage, []byte(
            fmt.Sprintf("ubd+%d+SMART", conid),
        ))
    }
    if ws != nil {
        _ = ws.WriteMessage(websocket.CloseMessage,
            websocket.FormatCloseMessage(websocket.CloseNormalClosure, "unsubscribe"))
        _ = ws.Close()
    }
}

func (f *IBKRCPGatewayDepthFeed) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	close(f.errCh)
	close(f.updCh)
}

func (f *IBKRCPGatewayDepthFeed) Run(ctx context.Context, onStatus func(connected bool)) {
	if f.cancel != nil {
		return
	}
	f.ctx, f.cancel = context.WithCancel(ctx)

	backoff := time.Second
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		// 1) Ensure HTTP session (re)established
		if err := f.client.Connect(f.ctx); err != nil {
			onStatus(false)
			f.setConnected(false)
			f.emitErr(fmt.Errorf("connect: %w", err))
			time.Sleep(backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}

        // 1b) Resolve and cache accountId required for book-depth topics.
        acctId, err := f.client.GetAccountID(f.ctx)
        if err != nil {
            onStatus(false)
            f.setConnected(false)
            f.emitErr(fmt.Errorf("get account id: %w", err))
            time.Sleep(backoff)
            backoff = min(backoff*2, 30*time.Second)
            continue
        }
        // cache locally for topic building
        f.mu.Lock()
        f.acctId = acctId
        f.mu.Unlock()

        // 2) If we have a symbol, resolve conid
		sym := f.currentSymbol()
		if sym != "" {
			conid, err := f.client.ConidForSymbol(f.ctx, sym)
			if err != nil {
				onStatus(false)
				f.setConnected(false)
				f.emitErr(fmt.Errorf("secdef for %s: %w", sym, err))
				time.Sleep(backoff)
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			f.mu.Lock()
			f.conid = conid
			f.mu.Unlock()
		}

		// 3) Open WebSocket and subscribe if we have a conid
		ws, err := f.openWS()
		if err != nil {
			onStatus(false)
			f.setConnected(false)
			f.emitErr(fmt.Errorf("ws open: %w", err))
			time.Sleep(backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		f.wsConn = ws
		f.setConnected(true)
		onStatus(true)
		backoff = time.Second

		if f.conid != 0 {
			if err := f.subscribeDepth(f.conid); err != nil {
				f.emitErr(fmt.Errorf("subscribe depth: %w", err))
				_ = ws.Close()
				continue
			}
		}

		// 4) Read pump
		if err := f.readLoop(); err != nil {
			onStatus(false)
			f.setConnected(false)
			f.emitErr(err)
			// loop will reconnect
		}
	}
}

func (f *IBKRCPGatewayDepthFeed) currentSymbol() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.symbol
}

func (f *IBKRCPGatewayDepthFeed) openWS() (*websocket.Conn, error) {
	u, err := url.Parse(f.client.BaseURL())
	if err != nil {
		return nil, err
	}
	u.Scheme = "wss"
	u.Path = "/v1/api/ws"
	d := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 local gateway
        NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            var nd net.Dialer
            return nd.DialContext(ctx, "tcp4", addr)
        },
	}
	ws, _, err := d.DialContext(f.ctx, u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Immediately send session ID to authenticate the WebSocket connection.
	sid, _ := f.client.RefreshSessionID(f.ctx) // try refresh first
	if sid == "" {
		sid = f.client.SessionID() // fall back to cached value
	}
	if sid != "" {
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"session":"`+sid+`"}`))
	}

	return ws, nil
}

// subscribeDepth sends a minimal subscription command. IBKR may change these specifics;
// keep this isolated. The readLoop coalesces incoming messages into snapshots for the aggregator.
func (f *IBKRCPGatewayDepthFeed) subscribeDepth(conid int64) error {
    // IBKR Client Portal WS commonly uses string topics for book depth.
    f.mu.RLock()
    acct := f.acctId
    f.mu.RUnlock()
    // Try both known topic formats.
    // 1) With accountId (newer builds)
    if acct != "" {
        _ = f.wsConn.WriteMessage(websocket.TextMessage, []byte(
            fmt.Sprintf("sbd+%s+%d+SMART", acct, conid),
        ))
    }
    // 2) Without accountId (older/common builds)
    return f.wsConn.WriteMessage(websocket.TextMessage, []byte(
        fmt.Sprintf("sbd+%d+SMART", conid),
    ))
}

type bookRow struct {
	Side     string  `json:"side"`
	Price    float64 `json:"price"`
	Size     int     `json:"size"`
	Venue    string  `json:"venue"`	// some builds use "venue"
	Exchange string  `json:"exchange"` // others use "exchange"
	Level    int     `json:"level"`
}

type inboundWS struct {
	Topic string    `json:"topic"`
	Conid int64     `json:"conid"`
	Rows  []bookRow `json:"rows"`
	Data  []bookRow `json:"data"` // many IBKR builds use "data" not "rows"
}

func (f *IBKRCPGatewayDepthFeed) readLoop() error {
	defer func() {
		if f.wsConn != nil {
			_ = f.wsConn.Close()
		}
	}()

	sym := f.currentSymbol()
	if sym == "" || f.conid == 0 {
		// idle until symbol is provided. Keep ws open to get status updates/pings.
	}

	f.wsConn.SetReadLimit(1 << 20)
	_ = f.wsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	f.wsConn.SetPongHandler(func(string) error {
		_ = f.wsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	var lastSnapshot time.Time

	for {
		select {
		case <-f.ctx.Done():
			return nil
		default:
		}

		// Keepalive ping
		select {
		case <-ticker.C:
			_ = f.wsConn.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(5*time.Second))
		default:
		}

		// Read next message (blocking)
		_, data, err := f.wsConn.ReadMessage()
		if err != nil {
			return fmt.Errorf("ws read: %w", err)
		}

		// Try to decode as inboundWS; if not, ignore (could be ack/heartbeat)
		var msg inboundWS
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		rows := msg.Rows
		if len(rows) == 0 {
			rows = msg.Data
		}
		if len(rows) == 0 {
			continue
		}

		asks := make([]depth.DepthLevel, 0, 64)
		bids := make([]depth.DepthLevel, 0, 64)
		for _, r := range rows {
			dl := depth.DepthLevel{
				Side:  strings.ToUpper(r.Side),
				Price: decimal.NewFromFloat(r.Price),
				Size:  r.Size,
				Venue: func() string {
					if r.Venue != "" { return r.Venue }
					return r.Exchange
				}(),
				Level: r.Level,
			}
			if dl.Side == "ASK" {
				asks = append(asks, dl)
			} else if dl.Side == "BID" {
				bids = append(bids, dl)
			}
		}
		if len(asks) == 0 && len(bids) == 0 {
			continue
		}

		// Coalesce messages: throttle snapshots to e.g., every 50ms to reduce UI spam
		now := time.Now()
		if now.Sub(lastSnapshot) < 50*time.Millisecond {
			continue
		}
		lastSnapshot = now

		f.updCh <- depth.Update{
			Symbol:     f.currentSymbol(),
			Asks:       asks,
			Bids:       bids,
			IsSnapshot: true,
		}
	}
}

func (f *IBKRCPGatewayDepthFeed) emitErr(err error) {
	select {
	case f.errCh <- err:
	default:
		// drop if buffer full
	}
}

// ---------- Test/mock feed (handy for integration tests & demos) ----------
type MockDepthFeed struct {
    updates   chan depth.Update
    errors    chan error
    connected bool
    subSymbol string
    ctx       context.Context
    cancel    context.CancelFunc
}

func NewMockDepthFeed() DepthFeed {
    return &MockDepthFeed{
        updates:   make(chan depth.Update, 10),
        errors:    make(chan error, 10),
        connected: true,
    }
}

func (m *MockDepthFeed) Run(ctx context.Context, onStatus func(connected bool)) {
    m.ctx, m.cancel = context.WithCancel(ctx)
    go func() {
        onStatus(m.connected)
        <-m.ctx.Done()
    }()
}

func (m *MockDepthFeed) SubscribeSymbol(symbol string) error {
    m.subSymbol = strings.ToUpper(strings.TrimSpace(symbol))
    return nil
}

func (m *MockDepthFeed) Unsubscribe() { m.subSymbol = "" }
func (m *MockDepthFeed) Updates() <-chan depth.Update { return m.updates }
func (m *MockDepthFeed) Errors() <-chan error         { return m.errors }
func (m *MockDepthFeed) Connected() bool              { return m.connected }

func (m *MockDepthFeed) Close() {
    if m.cancel != nil { m.cancel() }
    close(m.updates)
    close(m.errors)
}

// Helpers for tests
func (m *MockDepthFeed) SendUpdate(u depth.Update) { m.updates <- u }
func (m *MockDepthFeed) SendError(e error)         { m.errors <- e }
func (m *MockDepthFeed) SetConnected(c bool)       { m.connected = c }

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}


