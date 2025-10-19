package ibkrcp

import (
    "context"
    "testing"
    "time"

    "exit-indicator/internal/depth"
)

func TestMockDepthFeed(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    mock := NewMockDepthFeed().(*MockDepthFeed)

    statusCh := make(chan bool, 1)
    go mock.Run(ctx, func(c bool) { statusCh <- c })

    select {
    case c := <-statusCh:
        if !c { t.Fatal("expected connected status") }
    case <-time.After(time.Second):
        t.Fatal("no status")
    }

    if err := mock.SubscribeSymbol(" aapl "); err != nil {
        t.Fatal(err)
    }
    if mock.subSymbol != "AAPL" {
        t.Fatalf("got %s want AAPL", mock.subSymbol)
    }

    u := depth.Update{Symbol: "AAPL"}
    mock.SendUpdate(u)

    select {
    case got := <-mock.Updates():
        if got.Symbol != "AAPL" { t.Fatal("bad update") }
    case <-time.After(time.Second):
        t.Fatal("no update")
    }

    mock.Close()
}


