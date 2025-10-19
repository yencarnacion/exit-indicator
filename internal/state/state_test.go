package state

import (
    "strings"
    "testing"
    "time"
    "github.com/shopspring/decimal"
)

func TestSymbolNormalization(t *testing.T) {
    s := NewState(time.Second, 20000)
    c := s.SetSymbol(" aapl ")
    if c != "AAPL" {
        t.Fatalf("canon got %s want AAPL", c)
    }
    if got := s.Symbol(); got != "AAPL" {
        t.Fatalf("state symbol got %s", got)
    }
}

func TestAllowAlertCooldown(t *testing.T) {
    s := NewState(1*time.Second, 1000)
    if !s.AllowAlert("AAPL", decimal.NewFromFloat(100.0), time.Now()) {
        t.Fatal("first should allow")
    }
    if s.AllowAlert("aapl", decimal.NewFromFloat(100.0), time.Now()) {
        t.Fatal("should block within cooldown (case-insensitive key)")
    }
    time.Sleep(1100 * time.Millisecond)
    if !s.AllowAlert("AAPL", decimal.NewFromFloat(100.0), time.Now()) {
        t.Fatal("should allow after cooldown")
    }
}

func TestThreshold(t *testing.T) {
    s := NewState(time.Second, 10)
    if s.Threshold() != 10 {
        t.Fatalf("want 10")
    }
    s.SetThreshold(0)
    if s.Threshold() != 1 {
        t.Fatalf("min threshold enforced, got %d", s.Threshold())
    }
    s.SetThreshold(50000)
    if s.Threshold() != 50000 {
        t.Fatalf("set failed")
    }
    if strings.ToUpper(s.Symbol()) != strings.ToUpper(s.Symbol()) {
        t.Fatal("noop to avoid lint")
    }
}


