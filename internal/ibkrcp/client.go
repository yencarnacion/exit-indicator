package ibkrcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Client struct {
	baseURL string
	jar     *cookiejar.Jar
    acctId  string
	httpc   *http.Client
	logger  *slog.Logger

	sessionPath string
}

func NewClient(baseURL, sessionStorePath string, logger *slog.Logger) *Client {
	jar, _ := cookiejar.New(nil)
	// CP Gateway on 127.0.0.1: self-signed cert; allow insecure for local dev
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 local gateway
	}
	httpc := &http.Client{Jar: jar, Transport: tr, Timeout: 15 * time.Second}
	return &Client{
		baseURL:     baseURL,
		jar:         jar,
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
	u, _ := url.Parse(c.baseURL)
	c.jar.SetCookies(u, dump.Cookies)
}

func (c *Client) saveSession() {
	u, _ := url.Parse(c.baseURL)
	cks := c.jar.Cookies(u)
	b, _ := json.MarshalIndent(cookieDump{Cookies: cks}, "", "  ")
	_ = os.MkdirAll(filepath.Dir(c.sessionPath), fs.ModePerm)
	_ = os.WriteFile(c.sessionPath, b, 0o600)
}

type cookieDump struct {
	Cookies []*http.Cookie `json:"cookies"`
}

func (c *Client) url(p string) string {
	return fmt.Sprintf("%s%s", c.baseURL, p)
}

// add below existing imports in client.go
// "net/http"
// "url"
// "time"

func (c *Client) do(ctx context.Context, method, path string, hdr http.Header) (*http.Response, error) {
    req, _ := http.NewRequestWithContext(ctx, method, c.url(path), nil)
    for k, vv := range hdr {
        for _, v := range vv { req.Header.Add(k, v) }
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
        // 2) reauthenticate brokerage (POST)
        resp, err = c.do(ctx, http.MethodPost, "/v1/portal/iserver/reauthenticate?force=true", h)
        if err == nil {
            _ = resp.Body.Close()
        }

        // 3) status (GET)
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/api/iserver/auth/status"), nil)
        resp, err = c.httpc.Do(req)
        if err != nil {
            time.Sleep(1500 * time.Millisecond)
            continue
        }
        var v map[string]any
        dec := json.NewDecoder(resp.Body)
        _ = dec.Decode(&v)
        _ = resp.Body.Close()

        if ok, _ := v["authenticated"].(bool); ok {
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

    // status probe (some builds return 204/401 until validated)
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/api/iserver/auth/status"), nil)
    resp, err := c.httpc.Do(req)
    if err != nil {
        return fmt.Errorf("gateway unreachable: %w", err)
    }
    if resp.StatusCode >= 500 {
        resp.Body.Close()
        return fmt.Errorf("gateway status %d", resp.StatusCode)
    }
    var stat map[string]any
    _ = json.NewDecoder(resp.Body).Decode(&stat)
    resp.Body.Close()

    if ok, _ := stat["authenticated"].(bool); ok {
        c.saveSession()
        return nil
    }

    // Not authenticated yet → perform the validate → reauth → status dance
    if err := c.ensureBrokerageSession(ctx); err != nil {
        return fmt.Errorf("not authenticated in Client Portal Gateway: %w", err)
    }
    return nil
}

// GetAccountID fetches and caches the first available accountId from the
// Client Portal Gateway. Many WS subscription topics require it.
func (c *Client) GetAccountID(ctx context.Context) (string, error) {
    if c.acctId != "" {
        return c.acctId, nil
    }
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/api/portfolio/accounts"), nil)
    resp, err := c.httpc.Do(req)
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/api/iserver/secdef/search?symbol="+q), nil)
	resp, err := c.httpc.Do(req)
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
func (c *Client) BaseURL() string          { return c.baseURL }


