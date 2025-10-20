package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // register finders for major browsers
	"encoding/json"
)

type Row struct {
	Browser     string `json:"browser"`
	ProfilePath string `json:"profile_path"`
	StoreFile   string `json:"store_file"`
	Domain      string `json:"domain"`
	HostOnly    bool   `json:"host_only"`
	Path        string `json:"path"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	ValueHex    string `json:"value_hex"` // new: hex dump of []byte(value)
	ValidUTF8   bool   `json:"value_valid_utf8"` // new: utf8.ValidString(value)
	HasNonASCII bool   `json:"has_non_ascii"` // new: any rune >127
	Secure      bool   `json:"secure"`
	HttpOnly    bool   `json:"http_only"`
	SameSite    string `json:"same_site"`
	Expires     string `json:"expires"` // RFC3339 or "session"
}

func main() {
	matchFlag := flag.String("match", "local,127", "comma-separated substrings to match in cookie domain (case-insensitive)")
	fullFlag := flag.Bool("full", false, "print full cookie values (default truncates to 80 chars)")
	jsonFlag := flag.Bool("json", false, "output JSON instead of pretty text")
	hexFlag := flag.Bool("hex", false, "always print hex dump of value bytes (default: only if invalid UTF-8 or non-ASCII)")
	flag.Parse()

	matches := splitList(*matchFlag)
	if len(matches) == 0 {
		fmt.Fprintln(os.Stderr, "No match substrings provided via -match")
		os.Exit(2)
	}

	stores := kooky.FindAllCookieStores()
	if len(stores) == 0 {
		fmt.Fprintln(os.Stderr, "No browser cookie stores found")
		os.Exit(1)
	}
	defer func() {
		for _, s := range stores {
			_ = s.Close()
		}
	}()

	var rows []Row
	now := time.Now()
	for _, s := range stores {
		kcs, _ := s.ReadCookies(kooky.Valid)
		for _, kc := range kcs {
			if !domainHasAny(kc.Domain, matches) {
				continue
			}
			val := kc.Value
			b := []byte(val)
			validUTF8 := utf8.Valid(b)
			hasNonASCII := false
			for _, r := range val {
				if r > 127 {
					hasNonASCII = true
					break
				}
			}
			r := Row{
				Browser:     s.Browser(),
				ProfilePath: s.Profile(),
				StoreFile:   s.FilePath(),
				Domain:      kc.Domain,
				HostOnly:    hostOnlyHeuristic(kc.Domain),
				Path:        kc.Path,
				Name:        kc.Name,
				Value:       maybeTruncate(val, *fullFlag),
				ValueHex:    hex.EncodeToString(b),
				ValidUTF8:   validUTF8,
				HasNonASCII: hasNonASCII,
				Secure:      kc.Secure,
				HttpOnly:    kc.HttpOnly,
				SameSite:    sameSiteToString(kc.SameSite),
				Expires:     expiresToString(kc.Expires),
			}
			if !kc.Expires.IsZero() && now.After(kc.Expires) {
				r.Expires += " (expired)"
			}
			rows = append(rows, r)
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Browser != b.Browser {
			return a.Browser < b.Browser
		}
		if a.StoreFile != b.StoreFile {
			return a.StoreFile < b.StoreFile
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Name < b.Name
	})

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		_ = enc.Encode(map[string]any{
			"env": map[string]any{
				"go":       runtime.Version(),
				"os":       runtime.GOOS,
				"arch":     runtime.GOARCH,
				"time_utc": time.Now().UTC().Format(time.RFC3339),
				"match":    matches,
			},
			"count": len(rows),
			"rows":  rows,
		})
		return
	}

	fmt.Printf("Cookie debug (%s %s, %s) — match=%v\n", runtime.GOOS, runtime.GOARCH, time.Now().UTC().Format(time.RFC3339), matches)
	fmt.Printf("Found %d matching cookies across %d stores.\n\n", len(rows), len(stores))

	lastStore := ""
	for _, r := range rows {
		storeKey := r.Browser + " :: " + r.StoreFile
		if storeKey != lastStore {
			fmt.Printf("=== %s\n", storeKey)
			if r.ProfilePath != "" {
				fmt.Printf(" profile: %s\n", prettifyPath(r.ProfilePath))
			}
			lastStore = storeKey
		}
		fmt.Printf("- domain: %s path: %s name: %s\n", r.Domain, r.Path, r.Name)
		fmt.Printf("  value : %s\n", r.Value)
		showHex := *hexFlag || !r.ValidUTF8 || r.HasNonASCII
		if showHex {
			fmt.Printf("  value-hex: %s\n", r.ValueHex)
			fmt.Printf("  value-info: valid_utf8=%v has_non_ascii=%v byte_len=%d\n", r.ValidUTF8, r.HasNonASCII, len([]byte(r.Value)))
		}
		fmt.Printf("  flags : secure=%v httpOnly=%v sameSite=%s hostOnly=%v\n", r.Secure, r.HttpOnly, r.SameSite, r.HostOnly)
		fmt.Printf("  times : expires=%s\n", r.Expires)
	}

	if len(rows) == 0 {
		fmt.Println("No matching cookies. Try logging in to your Gateway on BOTH https://localhost:PORT and https://127.0.0.1:PORT and re-run.")
	}
}

// ------- helpers -------

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func domainHasAny(domain string, subs []string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	for _, sub := range subs {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

func hostOnlyHeuristic(domain string) bool {
	// Browsers usually store host-only cookies without a leading dot.
	d := strings.TrimSpace(domain)
	return d != "" && !strings.HasPrefix(d, ".")
}

func maybeTruncate(v string, full bool) string {
	if full || len(v) <= 80 {
		return v
	}
	return v[:80] + "…"
}

func expiresToString(t time.Time) string {
	if t.IsZero() {
		return "session"
	}
	return t.UTC().Format(time.RFC3339)
}

func sameSiteToString(ss http.SameSite) string {
	switch ss {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

func prettifyPath(p string) string {
	if p == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") {
			return "~/" + rel
		}
	}
	return p
}