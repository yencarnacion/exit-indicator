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
		kcs, _ := s.ReadCookies(
			kooky.DomainHasSuffix(host),
			kooky.Valid, // discard corrupt entries
		)
		for _, kc := range kcs {
			// Manual expiry filter
			if !kc.Expires.IsZero() && now.After(kc.Expires) {
				continue
			}
			// Convert kooky.Cookie -> net/http.Cookie
			hc := &http.Cookie{
				Name:     kc.Name,
				Value:    kc.Value,
				Domain:   kc.Domain,
				Path:     kc.Path,
				Expires:  kc.Expires,   // zero -> session cookie
				Secure:   kc.Secure,
				HttpOnly: kc.HttpOnly,  // note the capitalization in kooky
				// SameSite is optional; kooky has kc.SameSite (http.SameSite) if you want to copy it.
			}

			key := strings.ToLower(hc.Domain) + "\t" + hc.Path + "\t" + hc.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, hc)
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

// ExtractFromBrowser is a convenience wrapper used by main.go. For now we
// ignore the specific browser name and just read from all stores.
func ExtractFromBrowser(_ string, rawURL string) ([]*http.Cookie, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return ForURL(ctx, rawURL)
}
