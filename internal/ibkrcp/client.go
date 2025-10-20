package ibkrcp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// probeStatus checks both API and Portal auth status endpoints using browser-like headers.
func (c *Client) probeStatus(ctx context.Context) (bool, error) {
	h := c.originHeaders()
	if resp, err := c.do(ctx, http.MethodGet, "/v1/api/iserver/auth/status", h); err == nil {
		defer resp.Body.Close()
		var v map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&v)
		if ok, _ := v["authenticated"].(bool); ok {
			return true, nil
		}
	}
	if resp, err := c.do(ctx, http.MethodGet, "/v1/portal/iserver/auth/status", h); err == nil {
		defer resp.Body.Close()
		var v map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&v)
		if ok, _ := v["authenticated"].(bool); ok {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) do(ctx context.Context, method, path string, hdr http.Header) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, method, c.url(path), nil)
	for k, vv := range hdr {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	// Manually set Cookie header with raw values (no sanitization)
	var cookieStrs []string
	for _, ck := range c.sessionCookies {
		cookieStrs = append(cookieStrs, ck.Name+"="+ck.Value)
	}
	if len(cookieStrs) > 0 {
		req.Header.Set("Cookie", strings.Join(cookieStrs, "; "))
	}
	return c.httpc.Do(req)
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
	// 0) seed cookie jar (tickle usually returns 401 but sets x-sess-uuid)
	_, _ = c.do(ctx, http.MethodGet, "/v1/api/tickle", nil)
	// 0b) (optional) hit the SSO login route to align context (does nothing if already logged in)
	authPath := "/sso/Login?forwardTo=22&RL=" + rlParam() + "&ip2loc=on"
	_, _ = c.do(ctx, http.MethodGet, authPath, h)
	// Attempt validate → reauth → status a few times; some builds need a few seconds
	const tries = 8
	for i := 0; i < tries; i++ {
		// 1) validate SSO (GET)
		resp, err := c.do(ctx, http.MethodGet, "/v1/portal/sso/validate", h)
		if err == nil {
			_ = resp.Body.Close()
		}
		// 2) reauthenticate brokerage (POST) – prefer /v1/api, fall back to /v1/portal
		for _, p := range []string{
			"/v1/api/iserver/reauthenticate?force=true",
			"/v1/portal/iserver/reauthenticate?force=true",
		} {
			resp, err = c.do(ctx, http.MethodPost, p, h)
			if err == nil {
				_ = resp.Body.Close()
				break
			}
		}
		// 3) status (GET) – try API first, then Portal
		if ok, _ := c.probeStatus(ctx); ok {
			// persist cookies for next runs
			c.saveSession()
			return nil
		}
		// Handle 204/empty or transient false → wait and retry
		time.Sleep(1500 * time.Millisecond)
	}
	return errors.New("brokerage session did not authenticate after validate/reauth/status sequence")
}

func (c *Client) Connect(ctx context.Context) error {
	// Load cookies and try minimal status first
	c.loadSession()
	// Probe status via API then Portal
	ok, err := c.probeStatus(ctx)
	if err != nil {
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
    	resp, err := c.do(ctx, http.MethodGet, "/v1/api/portfolio/accounts", nil)

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("accounts status %d", resp.StatusCode)
	}
	var results []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", errors.New("no accounts found")
	}
	acct, ok := results[0]["accountId"].(string)
	if !ok || acct == "" {
		return "", errors.New("invalid accountId")
	}
	c.acctId = acct
	return acct, nil
}

// Minimal secdef search to map symbol→conid (STK). Picks the first STK result.
func (c *Client) ConidForSymbol(ctx context.Context, symbol string) (int64, error) {
	q := url.QueryEscape(symbol)
	resp, err := c.do(ctx, http.MethodGet, "/v1/api/iserver/secdef/search?symbol="+q, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("secdef search status %d", resp.StatusCode)
	}
	var results []struct {
		Conid   int64  `json:"conid"`
		SecType string `json:"secType"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return 0, err
	}
	for _, r := range results {
		if r.SecType == "STK" {
			return r.Conid, nil
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