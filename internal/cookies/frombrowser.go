package cookies

import (
    "errors"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "strings"

    "github.com/zellyn/kooky"
    _ "github.com/zellyn/kooky/allbrowsers" // register finders (Chrome, Chromium, Edge, Brave, Opera, etc.)
)

// ExtractFromBrowser loads cookies for baseURL from the requested browser family
// ("chrome", "chromium", "edge", "brave", "opera"). It returns a de-duplicated
// slice of *http.Cookie ready to be stored or injected into an http.Client jar.
//
// On macOS/Windows/Linux, decryption is handled by kooky.
// Chrome/Edge can be running; kooky reads a snapshot/copy of the DB if needed.
func ExtractFromBrowser(browser, baseURL string) ([]*http.Cookie, error) {
    if baseURL == "" {
        return nil, errors.New("baseURL required")
    }
    u, err := url.Parse(baseURL)
    if err != nil {
        return nil, fmt.Errorf("parse baseURL: %w", err)
    }
    host := u.Hostname()
    if host == "" {
        return nil, fmt.Errorf("invalid baseURL host in %q", baseURL)
    }

    want := normalizeBrowser(browser)

    // If caller passed a path to a profile (advanced), honor it:
    // e.g., --from-browser chrome:/Users/me/Library/.../Default
    var wantProfilePath string
    if i := strings.IndexByte(want, ':'); i > 0 {
        wantProfilePath = want[i+1:]
        want = want[:i]
    }

    // Find all known cookie stores (Chrome/Brave/Edge, etc.)
    stores := kooky.FindAllCookieStores()
    // Filter stores by requested browser and (optional) profile path
    var use []kooky.CookieStore
    for _, s := range stores {
        bname := normalizeBrowser(s.Browser())
        if bname != want {
            continue
        }
        if wantProfilePath != "" {
            if !samePath(s.FilePath(), wantProfilePath) && !strings.Contains(strings.ToLower(s.FilePath()), strings.ToLower(wantProfilePath)) {
                continue
            }
        }
        use = append(use, s)
    }

    if len(use) == 0 {
        return nil, fmt.Errorf("no %s cookie stores found", want)
    }
    defer func() {
        for _, s := range use {
            _ = s.Close()
        }
    }()

    // Collect cookies for the target host across all matching stores/profiles.
    // We include session cookies (no expiry) because IBKR auth relies on them.
    var out []*http.Cookie
    seen := map[string]bool{}
    for _, s := range use {
        // Restrict to domain; don't filter Secure/Path so we carry everything useful.
        cc, _ := s.ReadCookies(kooky.DomainHasSuffix(host))
        for _, kc := range cc {
            hc := kc.HTTPCookie()
            key := dedupeKey(hc)
            if !seen[key] {
                seen[key] = true
                out = append(out, &hc)
            }
        }
    }

    if len(out) == 0 {
        return nil, fmt.Errorf("no cookies for %q found in %s", host, want)
    }
    return out, nil
}

func normalizeBrowser(s string) string {
    s = strings.ToLower(strings.TrimSpace(s))
    switch s {
    case "chrome", "google chrome":
        return "chrome"
    case "chromium":
        return "chromium"
    case "edge", "microsoft edge":
        return "edge"
    case "brave":
        return "brave"
    case "opera":
        return "opera"
    default:
        // Accept "chrome" as default
        return "chrome"
    }
}

func samePath(a, b string) bool {
    ra := filepath.Clean(a)
    rb := filepath.Clean(b)
    if ea, err := filepath.EvalSymlinks(ra); err == nil {
        ra = ea
    }
    if eb, err := filepath.EvalSymlinks(rb); err == nil {
        rb = eb
    }
    return ra == rb
}

func dedupeKey(c *http.Cookie) string {
    // http.Cookie equality: domain+path+name scope uniquely identifies cookie
    // NB: case-insensitive domain comparison
    return strings.ToLower(c.Domain) + "\t" + c.Path + "\t" + c.Name
}

// SaveAsSessionJSON writes cookies to ./data/session.json-compatible format
// used by internal/ibkrcp (cookieDump { cookies: []http.Cookie }).
func SaveAsSessionJSON(path string, cookies []*http.Cookie) error {
    type cookieDump struct {
        Cookies []*http.Cookie `json:"cookies"`
    }

    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        return err
    }
    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()

    b := &cookieDump{Cookies: cookies}
    enc := jsonEnc(f)
    return enc.Encode(b)
}

// tiny wrapper: pretty JSON when terminal, compact otherwise.
func jsonEnc(w interface {
    Write([]byte) (int, error)
}) *jsonEncoder {
    return &jsonEncoder{w: w}
}

// ---- minimal local JSON encoder to keep file self-contained ----
type jsonEncoder struct{ w interface{ Write([]byte) (int, error) } }

func (e *jsonEncoder) Encode(v any) error {
    b, err := marshalIndent(v)
    if err != nil {
        return err
    }
    _, err = e.w.Write(b)
    return err
}

// we keep these helpers local to avoid adding a full JSON pretty lib dependency
func marshalIndent(v any) ([]byte, error) {
    type M = map[string]any
    type A = []any
    // delegate to stdlib json
    return json.MarshalIndent(v, "", "  ")
}

// import std json only here (avoids cluttering top)
import "encoding/json"


