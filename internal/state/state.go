package state

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"github.com/shopspring/decimal"
	"time"
)

type State struct {
	activeMu     sync.RWMutex
	activeSymbol string

	threshold atomic.Int64
    alertSide string // "ASK" or "BID"
	connected atomic.Bool

	alertMu    sync.Mutex
	lastAlert  map[string]time.Time // key: "SYMBOL:PRICE"
	cooldown   time.Duration
}

func NewState(cooldown time.Duration, defaultThreshold int) *State {
	s := &State{
		lastAlert: make(map[string]time.Time),
		cooldown:  cooldown,
	}
    s.alertSide = "ASK"
	s.threshold.Store(int64(defaultThreshold))
	return s
}

func (s *State) SetSymbol(sym string) string {
	canon := strings.ToUpper(strings.TrimSpace(sym))
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	s.activeSymbol = canon
	return canon
}

func (s *State) Symbol() string {
	s.activeMu.RLock()
	defer s.activeMu.RUnlock()
	return s.activeSymbol
}

func (s *State) Threshold() int {
	return int(s.threshold.Load())
}

func (s *State) SetThreshold(v int) {
	if v < 1 {
		v = 1
	}
	s.threshold.Store(int64(v))
}

func (s *State) SetConnected(v bool) { s.connected.Store(v) }
func (s *State) Connected() bool     { return s.connected.Load() }

// Side controls which book side to aggregate/alert on: "ASK" (offer) or "BID".
func (s *State) SetSide(side string) string {
    up := strings.ToUpper(strings.TrimSpace(side))
    if up != "BID" {
        up = "ASK"
    }
    s.activeMu.Lock()
    defer s.activeMu.Unlock()
    s.alertSide = up
    return up
}

func (s *State) Side() string { s.activeMu.RLock(); defer s.activeMu.RUnlock(); return s.alertSide }

func (s *State) key(symbol string, price decimal.Decimal) string {
	return fmt.Sprintf("%s:%s", strings.ToUpper(symbol), price.String())
}

func (s *State) AllowAlert(symbol string, price decimal.Decimal, now time.Time) bool {
	k := s.key(symbol, price)
	s.alertMu.Lock()
	defer s.alertMu.Unlock()
	last, ok := s.lastAlert[k]
	if !ok || now.Sub(last) >= s.cooldown {
		s.lastAlert[k] = now
		return true
	}
	return false
}


