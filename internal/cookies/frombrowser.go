package cookies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // register all browser finders
)

// json shape expected by internal/ibkrcp/client.go
type cookieDump struct {
	Cookies []*http.Cookie `json:"cookies"`
}

// ForURL reads cookies for the given base URL's host from all supported browsers.
// It filters by domain suffix, keeps valid/non-expired cookies, converts to net/http,
// and de-duplicates by (domain, path, name).
func ForURL(ctx context.Context, rawURL string) ([]*http.Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid url host in %q", rawURL)
	}

	stores := kooky.FindAllCookieStores()
	if len(stores) == 0 {
		return nil, fmt.Errorf("no browser cookie stores found")
	}
	defer func() {
		for _, s := range stores {
			_ = s.Close()
		}
	}()

	now := time.Now()
	var out []*http.Cookie
	seen := make(map[string]bool)

	for _, s := range stores {
		// Pull cookies matching the domain suffix
		kcs, _ := s.ReadCookies(
			kooky.DomainHasSuffix(host),
			kooky.Valid, // discard obviously invalid entries
		)
		for _, kc := range kcs {
			hc := kc.HTTPCookie() // convert to net/http.Cookie

			// filter expired
			if !hc.Expires.IsZero() && now.After(hc.Expires) {
				continue
			}

			// dedupe by domain+path+name (case-insensitive domain)
			key := strings.ToLower(hc.Domain) + "\t" + hc.Path + "\t" + hc.Name
			if seen[key] {
				continue
			}
			seen[key] = true

			// keep a pointer copy
			c := hc // copy
			out = append(out, &c)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no cookies for %q found", host)
	}
	return out, nil
}

// WriteDump writes cookies as {"cookies":[...]} to the given path (0600 perms).
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
