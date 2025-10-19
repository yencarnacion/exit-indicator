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

func (c *Client) Connect(ctx context.Context) error {
	// Load cookies from disk and test status
	c.loadSession()

	// hit /v1/api/iserver/auth/status – returns { "authenticated": bool, ... }
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/v1/api/iserver/auth/status"), nil)
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("gateway unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("gateway status %d", resp.StatusCode)
	}

	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return fmt.Errorf("decode auth status: %w", err)
	}
	auth, _ := v["authenticated"].(bool)
	if !auth {
		return errors.New("not authenticated in Client Portal Gateway. Open the Gateway UI and sign in, then retry")
	}

	c.saveSession()
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


