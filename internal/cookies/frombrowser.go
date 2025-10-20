package cookies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // register all browser finders
)

// json shape expected by internal/ibkrcp/client.go
type cookieDump struct {
	Cookies []*http.Cookie `json:"cookies"`
}

// ForURL reads valid, non-expired cookies for the given URL host from all browsers
// registered by kooky (Chrome, Edge, Firefox, Safari, etc.).
func ForURL(ctx context.Context, rawURL string) ([]*http.Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()

	// Pull cookies from all known stores, filter by host, and keep valid/non-expired ones.
	kcs := kooky.TraverseCookies(
		ctx,
		kooky.DomainHasSuffix(host),
		kooky.Valid,
		kooky.NotExpired,
	).OnlyCookies()

	out := make([]*http.Cookie, 0, len(kcs))
	for _, c := range kcs {
		// Kooky Cookie has similar fields; convert to net/http.Cookie.
		var exp time.Time
		if !c.Expires.IsZero() {
			exp = c.Expires
		}
		out = append(out, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  exp,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly, // note: field is HTTPOnly in kooky
		})
	}
	return out, nil
}

// WriteDump writes cookies as {"cookies":[...]} to the given path (600 perms).
func WriteDump(path string, cs []*http.Cookie) error {
	b, err := json.MarshalIndent(cookieDump{Cookies: cs}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
