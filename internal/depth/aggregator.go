package depth

import (
    "strings"
	"slices"
	"github.com/shopspring/decimal"
	"time"

	"exit-indicator/internal/state"
)

type Aggregator struct {
	st           *state.State
	levelsToScan int
}

func NewAggregator(st *state.State, levelsToScan int) *Aggregator {
	return &Aggregator{st: st, levelsToScan: levelsToScan}
}

// ProcessSnapshot implements the SMART aggregation by price for the selected side (ASK/BID),
// selecting the top 10 starting from the current best level. It emits both the book (for UI)
// and any alerts that passed cooldown.
func (a *Aggregator) ProcessSnapshot(up Update) ([]AggregatedLevel, []AlertEvent) {
    if len(up.Asks) == 0 && len(up.Bids) == 0 {
		return nil, nil
	}

    // Pick side
    side := a.st.Side()
    rows := up.Asks
    if side == "BID" {
        rows = up.Bids
    }
    if len(rows) == 0 {
        return nil, nil
    }

    // Aggregate by price: sum across venues at the same price.
    // IMPORTANT: decimal.Decimal values that are numerically equal can carry different exponents
    // (e.g., "100" vs "100.00"). If we use Decimal as a map key, those become distinct keys.
    // To ensure correct aggregation, canonicalize the price into a normalized string key.
    sumByKey := map[string]int{}
    priceByKey := map[string]decimal.Decimal{} // keep one representative Decimal per key for sorting/return
    for _, lvl := range rows {
        if strings.ToUpper(lvl.Side) != side {
            continue
        }
        k := canonicalPriceKey(lvl.Price)
        sumByKey[k] += lvl.Size
        if _, ok := priceByKey[k]; !ok {
            priceByKey[k] = lvl.Price
        }
    }

    if len(sumByKey) == 0 {
		return nil, nil
	}

    // Order ascending by price for asks, descending for bids; pick top 10 from the best level.
    keys := make([]string, 0, len(sumByKey))
    for k := range sumByKey {
        keys = append(keys, k)
    }
    slices.SortFunc(keys, func(ka, kb string) int {
        pa := priceByKey[ka]
        pb := priceByKey[kb]
        if side == "BID" {
            // best bid is highest price first (descending)
            return pb.Cmp(pa)
        }
        // best ask is lowest price first (ascending)
        return pa.Cmp(pb)
    })
    if len(keys) > a.levelsToScan {
        keys = keys[:a.levelsToScan]
    }

    book := make([]AggregatedLevel, 0, len(keys))
	alerts := make([]AlertEvent, 0, 2)

    for i, k := range keys {
        p := priceByKey[k]
        sum := sumByKey[k]
		book = append(book, AggregatedLevel{
			Price:     p,
			SumShares: sum,
			Rank:      i,
		})
        thr := a.st.Threshold()
		if sum >= thr {
			if a.st.AllowAlert(up.Symbol, p, time.Now()) {
				alerts = append(alerts, AlertEvent{
                    Side:      side,
					Symbol:    up.Symbol,
					Price:     p,
					SumShares: sum,
					Time:      time.Now(),
				})
			}
		}
	}

	return book, alerts
}

// canonicalPriceKey normalizes a Decimal so numerically equal values hash to the same key.
// We use String(), which removes redundant trailing zeros (e.g., "100.00" -> "100").
func canonicalPriceKey(p decimal.Decimal) string {
    return p.String()
}


