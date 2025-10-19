package depth

import (
	"time"
	"github.com/shopspring/decimal"
)

type DepthLevel struct {
	Side  string  `json:"side"`  // "ASK" or "BID"
	Price decimal.Decimal `json:"price"` // price level
	Size  int     `json:"size"`  // shares at this venue at this price
	Venue string  `json:"venue"` // exchange/venue
	Level int     `json:"level"` // optional: source-reported level index
}

type Update struct {
	Symbol string       // canonical UPPER symbol
	Asks   []DepthLevel // ask-side venue rows
	Bids   []DepthLevel // bid-side venue rows (currently ignored by aggregator rules, but retained)
	// IsSnapshot indicates this contains the latest full view we should work from (aggregator treats all Updates as snapshots).
	IsSnapshot bool
}

type AggregatedLevel struct {
	Price     decimal.Decimal `json:"price"`
	SumShares int     `json:"sumShares"`
	Rank      int     `json:"rank"` // 0..9; 0 is best ask
}

type AlertEvent struct {
    Side      string    `json:"side"`   // "ASK" or "BID"
	Symbol    string    `json:"symbol"`
	Price     decimal.Decimal   `json:"price"`
	SumShares int       `json:"sumShares"`
	Time      time.Time `json:"time"`
}


