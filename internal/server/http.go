package server

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"

    "exit-indicator/internal/config"
    "exit-indicator/internal/depth"
    "exit-indicator/internal/ibkrcp"
    "exit-indicator/internal/sound"
    "exit-indicator/internal/state"
)

type HTTPServer struct {
    cfg   config.Config
    st    *state.State
    snd   *sound.Manager
    feed  ibkrcp.DepthFeed
    agg   *depth.Aggregator
    hub   *hub
    log   *slog.Logger
    mux   *http.ServeMux
}

func NewHTTPServer(cfg config.Config, st *state.State, snd *sound.Manager, feed ibkrcp.DepthFeed, agg *depth.Aggregator, logger *slog.Logger) *HTTPServer {
    s := &HTTPServer{
        cfg:  cfg,
        st:   st,
        snd:  snd,
        feed: feed,
        agg:  agg,
        hub:  newHub(logger),
        log:  logger,
        mux:  http.NewServeMux(),
    }
    s.routes()
    go s.hub.run()
    return s
}

func (s *HTTPServer) Router() http.Handler { return s.mux }

// --------- WS broadcasts ----------

func (s *HTTPServer) BroadcastStatus() {
    msg := map[string]any{
        "connected": s.st.Connected(),
        "symbol":    s.st.Symbol(),
        "side":      s.st.Side(),
    }
    s.hub.broadcast <- marshalWS("status", msg)
}

func (s *HTTPServer) BroadcastBook(levels []depth.AggregatedLevel) {
    s.hub.broadcast <- marshalWS("book", map[string]any{"asks": levels, "levels": levels, "side": s.st.Side()})
}

func (s *HTTPServer) BroadcastAlert(a depth.AlertEvent) {
    payload := map[string]any{
        "side":      a.Side,
        "symbol":    a.Symbol,
        "price":     a.Price,
        "sumShares": a.SumShares,
        "timeISO":   a.Time.UTC().Format(time.RFC3339Nano),
    }
    s.hub.broadcast <- marshalWS("alert", payload)
}

func (s *HTTPServer) BroadcastError(msg string) {
    s.hub.broadcast <- marshalWS("error", map[string]string{"message": msg})
}

// --------- Routes ----------

func (s *HTTPServer) routes() {
    // SPA
    s.mux.HandleFunc("/", s.serveIndex)
    s.mux.HandleFunc("/index.html", s.serveIndex)
    s.mux.HandleFunc("/app.js", s.serveAppJS)
    s.mux.HandleFunc("/styles.css", s.serveCSS)

    // Sounds
    s.mux.HandleFunc("/sounds/", s.serveSound)

    // WS
    s.mux.HandleFunc("/ws", s.hub.serveWS)

    // API
    s.mux.HandleFunc("/api/health", s.apiHealth)
    s.mux.HandleFunc("/api/config", s.apiConfig)
    s.mux.HandleFunc("/api/start", s.apiStart)
    s.mux.HandleFunc("/api/stop", s.apiStop)
    s.mux.HandleFunc("/api/threshold", s.apiThreshold)
    s.mux.HandleFunc("/api/side", s.apiSide)
}

func (s *HTTPServer) serveIndex(w http.ResponseWriter, r *http.Request) {
    b, err := os.ReadFile("./web/index.html")
    if err != nil {
        http.Error(w, "index missing", http.StatusInternalServerError)
        return
    }
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write(b)
}

func (s *HTTPServer) serveAppJS(w http.ResponseWriter, r *http.Request) {
    b, err := os.ReadFile("./web/app.js")
    if err != nil {
        http.NotFound(w, r)
        return
    }
    w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
    _, _ = w.Write(b)
}

func (s *HTTPServer) serveCSS(w http.ResponseWriter, r *http.Request) {
    b, err := os.ReadFile("./web/styles.css")
    if err != nil {
        http.NotFound(w, r)
        return
    }
    w.Header().Set("Content-Type", "text/css; charset=utf-8")
    _, _ = w.Write(b)
}

func (s *HTTPServer) serveSound(w http.ResponseWriter, r *http.Request) {
    // Only serve configured file name (to keep it simple)
    if s.snd == nil || !s.snd.Available() {
        http.NotFound(w, r)
        return
    }
    _, name := filepath.Split(s.snd.Path())
    if !strings.HasSuffix(r.URL.Path, name) {
        http.NotFound(w, r)
        return
    }
    // strong caching (1 year) + immutable
    w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
    w.Header().Set("Content-Type", "audio/mpeg")
    http.ServeFile(w, r, s.snd.Path())
}

func (s *HTTPServer) apiHealth(w http.ResponseWriter, r *http.Request) {
    writeJSON(w, map[string]any{
        "ok":        true,
        "connected": s.st.Connected(),
    })
}

func (s *HTTPServer) apiConfig(w http.ResponseWriter, r *http.Request) {
    writeJSON(w, map[string]any{
        "defaultThresholdShares": s.cfg.DefaultThresholdShares,
        "currentThresholdShares": s.st.Threshold(),
        "cooldownSeconds":        s.cfg.CooldownSeconds,
        "levelsToScan":           s.cfg.LevelsToScan,
        "priceReference":         s.cfg.PriceReference,
        "smartDepth":             s.cfg.SmartDepth,
        "soundAvailable":         s.snd != nil && s.snd.Available(),
        "soundURL":               func() string { if s.snd != nil { return s.snd.URL() } ; return "" }(),
        "currentSide":            s.st.Side(),
    })
}

func (s *HTTPServer) apiStart(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    type reqT struct {
        Symbol    string `json:"symbol"`
        Threshold *int   `json:"threshold,omitempty"`
        Side      string `json:"side,omitempty"`
    }
    var req reqT
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest)
        return
    }
    sym := strings.ToUpper(strings.TrimSpace(req.Symbol))
    if sym == "" {
        http.Error(w, "symbol required", http.StatusBadRequest)
        return
    }

    // If gateway not connected, return 503
    if !s.st.Connected() && !isLocalDev() {
        http.Error(w, "gateway not connected", http.StatusServiceUnavailable)
        s.BroadcastError("Client Portal Gateway not connected. Is it running at the configured ibkr_gateway_url?")
        return
    }

    // apply threshold if provided
    if req.Threshold != nil && *req.Threshold > 0 {
        s.st.SetThreshold(*req.Threshold)
    }

    if req.Side != "" {
        s.st.SetSide(req.Side)
    } else {
        s.st.SetSide("ASK")
    }
    s.st.SetSymbol(sym)
    if err := s.feed.SubscribeSymbol(sym); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    s.BroadcastStatus()
    writeJSON(w, map[string]any{"ok": true, "symbol": s.st.Symbol(), "threshold": s.st.Threshold(), "side": s.st.Side()})
}

func (s *HTTPServer) apiStop(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    s.feed.Unsubscribe()
    s.st.SetSymbol("")
    s.BroadcastStatus()
    writeJSON(w, map[string]any{"ok": true})
}

func (s *HTTPServer) apiThreshold(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    var req struct {
        Threshold int `json:"threshold"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest)
        return
    }
    if req.Threshold < 1 {
        http.Error(w, "threshold must be >=1", http.StatusBadRequest)
        return
    }
    s.st.SetThreshold(req.Threshold)
    writeJSON(w, map[string]any{"ok": true, "threshold": s.st.Threshold()})
}

// POST /api/side { "side": "ASK"|"BID" }
func (s *HTTPServer) apiSide(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "POST required", http.StatusMethodNotAllowed)
        return
    }
    var req struct{ Side string `json:"side"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest)
        return
    }
    side := strings.ToUpper(strings.TrimSpace(req.Side))
    if side != "ASK" && side != "BID" {
        http.Error(w, "side must be ASK or BID", http.StatusBadRequest)
        return
    }
    s.st.SetSide(side)
    writeJSON(w, map[string]any{"ok": true, "side": s.st.Side()})
}

func writeJSON(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    _ = enc.Encode(v)
}

func isLocalDev() bool {
    // If you want /api/start to be usable before the Gateway connects in local dev, set EXIT_INDICATOR_ALLOW_START=1
    return os.Getenv("EXIT_INDICATOR_ALLOW_START") == "1"
}
