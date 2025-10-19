package depth

import (
    "testing"
    "time"
    "github.com/shopspring/decimal"

    "exit-indicator/internal/state"
)

func TestAggregationTop10FromBestAsk(t *testing.T) {
    st := state.NewState(1*time.Second, 20000)
    agg := NewAggregator(st, 10)

    up := Update{
        Symbol: "AAPL",
        Asks: []DepthLevel{
            {Side: "ASK", Price: decimal.NewFromFloat(100.00), Size: 5000, Venue: "X", Level: 0},
            {Side: "ASK", Price: decimal.NewFromFloat(100.00), Size: 7000, Venue: "Y", Level: 0},
            {Side: "ASK", Price: decimal.NewFromFloat(100.01), Size: 12000, Venue: "X", Level: 1},
            {Side: "ASK", Price: decimal.NewFromFloat(100.02), Size: 3000, Venue: "X", Level: 2},
            {Side: "ASK", Price: decimal.NewFromFloat(100.03), Size: 25000, Venue: "X", Level: 3},
            {Side: "ASK", Price: decimal.NewFromFloat(100.03), Size: 5000, Venue: "Y", Level: 3},
            {Side: "ASK", Price: decimal.NewFromFloat(100.05), Size: 1000, Venue: "X", Level: 5},
        },
    }

    book, alerts := agg.ProcessSnapshot(up)
    if len(book) == 0 {
        t.Fatalf("expected book")
    }
    if !book[0].Price.Equals(decimal.NewFromFloat(100.00)) {
        t.Fatalf("best ask price got %v want 100.00", book[0].Price)
    }
    if book[0].SumShares != 12000 { // 5000 + 7000 aggregated
        t.Fatalf("sum at best ask got %d want 12000", book[0].SumShares)
    }
    // Only the 100.03 level exceeds 20k threshold (25k+5k = 30k)
    if len(alerts) != 1 {
        t.Fatalf("alerts got %d want 1", len(alerts))
    }
    if !alerts[0].Price.Equals(decimal.NewFromFloat(100.03)) {
        t.Fatalf("alert at wrong price: %v", alerts[0].Price.String())
    }
}

func TestCooldown(t *testing.T) {
    st := state.NewState(1*time.Second, 10000)
    agg := NewAggregator(st, 10)

    // First snapshot triggers alert
    up := Update{
        Symbol: "MSFT",
        Asks: []DepthLevel{
            {Side: "ASK", Price: decimal.NewFromFloat(300.00), Size: 12000, Venue: "SMART"},
        },
    }
    _, alerts := agg.ProcessSnapshot(up)
    if len(alerts) != 1 {
        t.Fatalf("first alert missing")
    }
    // Within cooldown; should NOT alert
    _, alerts2 := agg.ProcessSnapshot(up)
    if len(alerts2) != 0 {
        t.Fatalf("unexpected alert during cooldown")
    }
    // After cooldown; should alert again
    time.Sleep(1050 * time.Millisecond)
    _, alerts3 := agg.ProcessSnapshot(up)
    if len(alerts3) != 1 {
        t.Fatalf("expected alert after cooldown")
    }
}


