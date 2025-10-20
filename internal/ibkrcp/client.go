package ibkrcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"exit-indicator/internal/authbrowser"
)

type Client struct {
	baseURL        string
	acctId         string
	httpc          *http.Client
	logger         *slog.Logger
	sessionPath    string
	sessionCookies []*http.Cookie // raw cookies; we manually handle headers to avoid sanitization
	lastSessionID  string         // session id returned by /tickle (used to auth the websocket)
}

func NewClient(baseURL, sessionStorePath string, logger *slog.Logger) *Client {
	// CP Gateway on 127.0.0.1: self-signed cert; allow insecure for local dev
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 local gateway
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 15 * time.Second}
			return d.DialContext(ctx, "tcp4", addr) // force IPv4
		},
	}
	// Allow overriding HTTP timeout for slow-starting gateways
	to := 15 * time.Second
	if s := os.Getenv("EXIT_INDICATOR_HTTP_TIMEOUT_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 600 {
			to = time.Duration(n) * time.Second
		}
	}
	httpc := &http.Client{Transport: tr, Timeout: to}
	return &Client{
		baseURL:     baseURL,
		httpc:       httpc,
		logger:      logger,
		sessionPath: sessionStorePath,
	}
}

func (c *Client) loadSession() {
	b, err := os.ReadFile(c.sessionPath)
	if err != nil {
		return
	}
	var dump cookieDump
	if err := json.Unmarshal(b, &dump); err != nil {
		return
	}
	var hcs []*http.Cookie
	for _, sc := range dump.Cookies {
		vb, err := base64.StdEncoding.DecodeString(sc.ValueBase64)
		if err != nil {
			continue
		}
		hc := &http.Cookie{
			Name:     sc.Name,
			Value:    string(vb), // raw bytes as string
			Path:     sc.Path,
			Domain:   sc.Domain,
			Expires:  sc.Expires,
			Secure:   sc.Secure,
			HttpOnly: sc.HttpOnly,
			SameSite: sc.SameSite,
		}
		hcs = append(hcs, hc)
	}
	c.sessionCookies = hcs
}

func (c *Client) saveSession() {
	var scs []savedCookie
	for _, ck := range c.sessionCookies {
		sc := savedCookie{
			Name:        ck.Name,
			ValueBase64: base64.StdEncoding.EncodeToString([]byte(ck.Value)),
			Path:        ck.Path,
			Domain:      ck.Domain,
			Expires:     ck.Expires,
			Secure:      ck.Secure,
			HttpOnly:    ck.HttpOnly,
			SameSite:    ck.SameSite,
		}
		scs = append(scs, sc)
	}
	b, _ := json.MarshalIndent(cookieDump{Cookies: scs}, "", " ")
	_ = os.MkdirAll(filepath.Dir(c.sessionPath), fs.ModePerm)
	_ = os.WriteFile(c.sessionPath, b, 0o600)
}

type savedCookie struct {
	Name        string          `json:"name"`
	ValueBase64 string          `json:"value_base64"`
	Path        string          `json:"path"`
	Domain      string          `json:"domain"`
	Expires     time.Time       `json:"expires"`
	Secure      bool            `json:"secure"`
	HttpOnly    bool            `json:"http_only"`
	SameSite    http.SameSite   `json:"same_site"`
}

type cookieDump struct {
	Cookies []savedCookie `json:"cookies"`
}

func (c *Client) url(p string) string {
	return fmt.Sprintf("%s%s", c.baseURL, p)
}

// probeStatus checks auth status using the documented POST (/v1/api/iserver/auth/status).
// Older builds sometimes expose a /v1/portal fallback; we keep it as a safety net, also with POST.
func (c *Client) probeStatus(ctx context.Context) (bool, error) {
	h := c.originHeaders()
	if resp, err := c.do(ctx, http.MethodPost, "/v1/api/iserver/auth/status", h); err == nil {
		defer resp.Body.Close()
		var v map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&v)
		if ok, _ := v["authenticated"].(bool); ok {
			return true, nil
		}
	}
	if resp, err := c.do(ctx, http.MethodPost, "/v1/portal/iserver/auth/status", h); err == nil {
		defer resp.Body.Close()
		var v map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&v)
		if ok, _ := v["authenticated"].(bool); ok {
			return true, nil
		}
	}
	return false, nil
}

// doJSON sends a JSON body with Content-Type: application/json.
func (c *Client) doJSON(ctx context.Context, method, path string, body any, hdr http.Header) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}
	if hdr == nil {
		hdr = make(http.Header)
	}
	if hdr.Get("Content-Type") == "" {
		hdr.Set("Content-Type", "application/json")
	}
	return c.doWithBody(ctx, method, path, &buf, hdr)
}

// do is retained for empty-body requests (delegates to doWithBody).
func (c *Client) do(ctx context.Context, method, path string, hdr http.Header) (*http.Response, error) {
	return c.doWithBody(ctx, method, path, nil, hdr)
}

func (c *Client) doWithBody(ctx context.Context, method, path string, body io.Reader, hdr http.Header) (*http.Response, error) {
	fullURL := c.url(path)
	req, _ := http.NewRequestWithContext(ctx, method, fullURL, body)
	for k, vv := range hdr {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	// Only attach cookies that actually match host/path and aren't expired.
	if u, err := url.Parse(fullURL); err == nil {
		host := u.Hostname()
		var cookieStrs []string
		now := time.Now()
		for _, ck := range c.sessionCookies {
			if ck == nil {
				continue
			}
			if !cookieDomainMatches(host, ck.Domain) {
				continue
			}
			if !cookiePathMatches(u.EscapedPath(), ck.Path) {
				continue
			}
			if !ck.Expires.IsZero() && now.After(ck.Expires) {
				continue
			}
			cookieStrs = append(cookieStrs, ck.Name+"="+ck.Value)
		}
		if len(cookieStrs) > 0 {
			req.Header.Set("Cookie", strings.Join(cookieStrs, "; "))
		}
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	// Merge Set-Cookie back into session and persist.
	c.mergeSetCookies(resp, fullURL)
	return resp, nil
}

func cookieDomainMatches(host, domain string) bool {
    if domain == "" { return false }
    hd := strings.TrimPrefix(strings.ToLower(host), ".")
    d  := strings.TrimPrefix(strings.ToLower(domain), ".")
    if hd == d { return true }
    return strings.HasSuffix(hd, "."+d)
}
func cookiePathMatches(reqPath, cookiePath string) bool {
    if cookiePath == "" || cookiePath == "/" { return true }
    return strings.HasPrefix(reqPath, cookiePath)
}
func (c *Client) mergeSetCookies(resp *http.Response, requestURL string) {
    if resp == nil { return }
    u, _ := url.Parse(requestURL)
    host := ""
    if u != nil { host = u.Hostname() }
    idx := make(map[string]int, len(c.sessionCookies))
    for i, ck := range c.sessionCookies {
        if ck == nil { continue }
        key := strings.ToLower(strings.TrimPrefix(ck.Domain, ".")) + "|" + ck.Path + "|" + ck.Name
        idx[key] = i
    }
    updated := false
    for _, sc := range resp.Cookies() {
        if sc == nil || sc.Name == "" { continue }
        if sc.Domain == "" && host != "" { sc.Domain = host }
        key := strings.ToLower(strings.TrimPrefix(sc.Domain, ".")) + "|" + sc.Path + "|" + sc.Name
        if pos, ok := idx[key]; ok {
            c.sessionCookies[pos] = sc
        } else {
            idx[key] = len(c.sessionCookies)
            c.sessionCookies = append(c.sessionCookies, sc)
        }
        updated = true
    }
    if updated { c.saveSession() }
}

func (c *Client) originHeaders() http.Header {
	h := make(http.Header)
	// Origin/Referer should match the base URL host to mimic browser calls
	u, _ := url.Parse(c.baseURL)
	origin := u.Scheme + "://" + u.Host
	h.Set("Origin", origin)
	h.Set("Referer", origin+"/")
	h.Set("X-Requested-With", "XMLHttpRequest")
	h.Set("Accept", "application/json")
	return h
}

// RL=1 (live), RL=2 (paper). Default 1, override via env EXIT_INDICATOR_IBKR_RL
func rlParam() string {
	if v := os.Getenv("EXIT_INDICATOR_IBKR_RL"); v == "2" {
		return "2"
	}
	return "1"
}

// ensureBrokerageSession reproduces the IBeam dance (tickle → validate → reauth → status),
// resilient to 204/401 and timing. It assumes the user already completed the browser login
// on the SAME host+port as c.baseURL.
func (c *Client) ensureBrokerageSession(ctx context.Context) error {
	h := c.originHeaders()

	// 0) seed/refresh session (POST /v1/api/tickle) and capture session id if present
	if resp, err := c.do(ctx, http.MethodPost, "/v1/api/tickle", nil); err == nil {
		func() {
			defer resp.Body.Close()
			var t struct{ Session string `json:"session"` }
			if err := json.NewDecoder(resp.Body).Decode(&t); err == nil && t.Session != "" {
				c.lastSessionID = t.Session
			}
		}()
	}

	// Attempt validate → reauth → status a few times; some builds need a few seconds
	const tries = 8
	for i := 0; i < tries; i++ {
		// 1) validate SSO (GET /v1/api/sso/validate)
		if resp, err := c.do(ctx, http.MethodGet, "/v1/api/sso/validate", h); err == nil {
			_ = resp.Body.Close()
		}
		// 2) reauthenticate brokerage (POST /v1/api/iserver/reauthenticate)
		if resp, err := c.do(ctx, http.MethodPost, "/v1/api/iserver/reauthenticate?force=true", h); err == nil {
			_ = resp.Body.Close()
		}
		// 3) status (POST per docs)
		if ok, _ := c.probeStatus(ctx); ok {
			c.saveSession()
			return nil
		}
		time.Sleep(1500 * time.Millisecond)
	}
	return errors.New("brokerage session did not authenticate after validate/reauth/status sequence")
}

func (c *Client) Connect(ctx context.Context) error {
	// Load cookies and try minimal status first
	c.loadSession()
	// Probe status via API then Portal
	ok, err := c.probeStatus(ctx)
	skipBrowser := func() bool {
		s := os.Getenv("EXIT_INDICATOR_LOGIN_WAIT_SECONDS")
		if s == "" { return false }
		w, err := strconv.Atoi(s)
		if err != nil { return false }
		return w <= 0
	}()
	if err != nil {
		if skipBrowser {
			return fmt.Errorf("gateway unreachable (browser disabled): %w", err)
		}
		// Try a one-shot browser-assisted login to nudge the gateway into a session
		rl := 2
		if os.Getenv("EXIT_INDICATOR_IBKR_RL") == "1" {
			rl = 1
		}
		abOpts := authbrowser.Options{
			BaseURL:   c.baseURL,
			RL:        rl,
			Headless:  false,
			Wait:      0, // uses EXIT_INDICATOR_LOGIN_WAIT_SECONDS
			Quiet:     true,
		}
		jar, _ := cookiejar.New(nil) // temp jar for browser flow
		if err2 := authbrowser.AcquireSessionCookie(ctx, jar, abOpts); err2 != nil {
			return fmt.Errorf("gateway unreachable: %w", err)
		}
		u, _ := url.Parse(c.baseURL)
		c.sessionCookies = jar.Cookies(u)
		// Re-probe after browser flow
		ok, err = c.probeStatus(ctx)
		if err != nil {
			return fmt.Errorf("gateway unreachable after browser flow: %w", err)
		}
	}
	if ok {
		c.saveSession()
		return nil
	}
	// Not authenticated yet → try programmatic validate/reauth/status first
	if err := c.ensureBrokerageSession(ctx); err != nil {
		if skipBrowser {
			return fmt.Errorf("not authenticated in Client Portal Gateway (browser disabled): %w", err)
		}
		// Last resort: drive Chrome to complete SSO and seed our cookie jar
		rl := 2
		if os.Getenv("EXIT_INDICATOR_IBKR_RL") == "1" {
			rl = 1
		}
		abOpts := authbrowser.Options{
			BaseURL:  c.baseURL, // e.g. https://localhost:5001
			RL:       rl,
			Headless: false, // show the window so you can do 2FA
			// Wait=0 => authbrowser uses EXIT_INDICATOR_LOGIN_WAIT_SECONDS (or its default)
			Wait:  0,
		}
		jar, _ := cookiejar.New(nil) // temp jar for browser flow
		// Launch visible Chrome; complete 2FA, helper will inject cookies
		if err2 := authbrowser.AcquireSessionCookie(ctx, jar, abOpts); err2 != nil {
			return fmt.Errorf("not authenticated in Client Portal Gateway: %w", err2)
		}
		u, _ := url.Parse(c.baseURL)
		c.sessionCookies = jar.Cookies(u)
		// Re-check status now that cookie jar is seeded (API or Portal)
		if ok, _ := c.probeStatus(ctx); !ok {
			return errors.New("authentication did not complete after browser flow")
		}
		c.saveSession()
	}
	return nil
}

// GetAccountID fetches and caches the first available accountId from the
// Client Portal Gateway. Many WS subscription topics require it.
func (c *Client) GetAccountID(ctx context.Context) (string, error) {
	if c.acctId != "" {
		return c.acctId, nil
	}
	resp, err := c.do(ctx, http.MethodGet, "/v1/api/iserver/accounts", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("iserver/accounts status %d", resp.StatusCode)
	}
	var v struct {
		Accounts []string `json:"accounts"`
		Selected string   `json:"selectedAccount"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	acct := v.Selected
	if acct == "" && len(v.Accounts) > 0 {
		acct = v.Accounts[0]
	}
	if acct == "" {
		return "", errors.New("no tradeable accounts found")
	}
	c.acctId = acct
	return acct, nil
}

// Minimal secdef search to map symbol→conid (STK). Picks the first STK result.
func (c *Client) ConidForSymbol(ctx context.Context, symbol string) (int64, error) {
	// Per docs: POST /iserver/secdef/search with JSON body {"symbol":"AAPL"}
	resp, err := c.doJSON(ctx, http.MethodPost, "/v1/api/iserver/secdef/search",
		map[string]any{"symbol": symbol}, c.originHeaders())
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("secdef search status %d", resp.StatusCode)
	}
	// Response is an array; STK presence may be in top-level "secType" or under "sections[*].secType"
	var results []struct {
		Conid    int64  `json:"conid"`
		SecType  string `json:"secType"`
		Symbol   string `json:"symbol"`
		Sections []struct {
			SecType string `json:"secType"`
			Symbol  string `json:"symbol"`
		} `json:"sections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return 0, err
	}
	symUpper := strings.ToUpper(symbol)
	choose := func(r any) bool { return true }
	for _, r := range results {
		// Prefer exact symbol matches when present
		if r.Symbol != "" {
			choose = func(rr any) bool { return strings.EqualFold(r.Symbol, symUpper) }
		}
		if r.SecType == "STK" && choose(r) {
			return r.Conid, nil
		}
		for _, s := range r.Sections {
			if s.SecType == "STK" && (s.Symbol == "" || strings.EqualFold(s.Symbol, symUpper)) {
				return r.Conid, nil
			}
		}
	}
	return 0, fmt.Errorf("no STK contract found for %s", symbol)
}

func (c *Client) HTTPClient() *http.Client { return c.httpc }
func (c *Client) BaseURL() string           { return c.baseURL }

// InjectCookies seeds the client's session cookies and persists to session_store_path.
func (c *Client) InjectCookies(cookies []*http.Cookie) {
	c.sessionCookies = cookies
	c.saveSession()
}

// LastSessionID returns the last session id captured from /tickle, used to authorize the websocket.
func (c *Client) LastSessionID() string {
	return c.lastSessionID
}