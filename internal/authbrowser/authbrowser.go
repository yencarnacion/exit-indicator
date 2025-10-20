package authbrowser

import (
	"context"
	"errors"
	"fmt"
    "crypto/tls"
    "encoding/json"
    "log/slog"
	"os"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// pollGatewayStatus uses the provided cookie jar to hit /auth/status until it returns authenticated:true or timeout.
func pollGatewayStatus(ctx context.Context, baseURL string, jar *cookiejar.Jar, timeout time.Duration) (bool, error) {
    // Same TLS + timeout semantics as the main client
    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // local self-signed
    httpc := &http.Client{Jar: jar, Transport: tr, Timeout: 8 * time.Second}

    deadline := time.Now().Add(timeout)
    for time.Now().Before(deadline) {
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/api/iserver/auth/status", nil)
        resp, err := httpc.Do(req)
        if err == nil {
            var v map[string]any
            if resp.Body != nil {
                _ = json.NewDecoder(resp.Body).Decode(&v)
                resp.Body.Close()
            }
            if ok, _ := v["authenticated"].(bool); ok {
                return true, nil
            }
        }
        time.Sleep(2 * time.Second)
    }
    return false, nil
}

func loginWait() time.Duration {
	if s := os.Getenv("EXIT_INDICATOR_LOGIN_WAIT_SECONDS"); s != "" {
		if d, err := time.ParseDuration(s + "s"); err == nil && d > 0 {
			return d
		}
	}
	return 8 * time.Minute // default bigger window for 2FA
}

type Options struct {
	BaseURL      string        // e.g. https://localhost:5001
	RL           int           // 1=live, 2=paper
	Headless     bool          // false => show window for 2FA
	Wait         time.Duration // overall timeout (e.g., 2-5 minutes)
	UserDataDir  string        // optional Chrome profile dir; empty => temp
    Logger       *slog.Logger  // optional: route chromedp logs to slog
    Quiet        bool          // if true, suppress chromedp debug/log output
}

func AcquireSessionCookie(ctx context.Context, httpJar *cookiejar.Jar, opts Options) error {
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return fmt.Errorf("bad base url: %w", err)
	}
	if opts.RL != 1 && opts.RL != 2 {
		opts.RL = 2 // default to paper
	}
	wait := opts.Wait
	if wait <= 0 { wait = loginWait() }

	// Chrome context
	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("allow-insecure-localhost", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-features", "BlockInsecurePrivateNetworkRequests"),
	}
	if opts.Headless {
		allocOpts = append(allocOpts, chromedp.Headless)
	} else {
		allocOpts = append(allocOpts, chromedp.Flag("headless", false))
	}
	if opts.UserDataDir != "" {
		allocOpts = append(allocOpts, chromedp.UserDataDir(opts.UserDataDir))
	}

	actx, acancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer acancel()
    // Optionally wire chromedp logging to slog or silence it
    var ctxOpts []chromedp.ContextOption
    if opts.Quiet {
        ctxOpts = append(ctxOpts,
            chromedp.WithLogf(func(string, ...any) {}),
            chromedp.WithDebugf(func(string, ...any) {}),
            chromedp.WithErrorf(func(string, ...any) {}),
        )
    } else if opts.Logger != nil {
        ctxOpts = append(ctxOpts,
            chromedp.WithLogf(func(f string, a ...any) { opts.Logger.Info(fmt.Sprintf(f, a...)) }),
            chromedp.WithDebugf(func(f string, a ...any) { opts.Logger.Debug(fmt.Sprintf(f, a...)) }),
            chromedp.WithErrorf(func(f string, a ...any) { opts.Logger.Warn(fmt.Sprintf(f, a...)) }),
        )
    }
    cctx, cancel := chromedp.NewContext(actx, ctxOpts...) // creates a new browser tab
	defer cancel()

	// Give the whole flow a max time
	cctx, timeoutCancel := context.WithTimeout(cctx, wait)
	defer timeoutCancel()

    loginURL := fmt.Sprintf("%s/sso/Login?forwardTo=22&RL=%d&ip2loc=on", opts.BaseURL, opts.RL)
    validateURL := opts.BaseURL + "/v1/portal/sso/validate"
    tickleURL   := opts.BaseURL + "/v1/api/tickle"
    // Prefer the /v1/api route, but fall back to /v1/portal if needed
    reauthURLPrimary  := opts.BaseURL + "/v1/api/iserver/reauthenticate?force=true"
    reauthURLFallback := opts.BaseURL + "/v1/portal/iserver/reauthenticate?force=true"
    statusURL1 := opts.BaseURL + "/v1/api/iserver/auth/status"
    statusURL2 := opts.BaseURL + "/v1/portal/iserver/auth/status"

	// Enable network domain to fetch HttpOnly cookies
	if err := chromedp.Run(cctx, network.Enable()); err != nil {
		return err
	}

	// 1) Navigate to login
	if err := chromedp.Run(cctx, chromedp.Navigate(loginURL)); err != nil {
		return fmt.Errorf("navigate login: %w", err)
	}

    // 2) Perform tickle + validate→reauth→status (API & Portal) in page context (uses browser cookies).
    jsFlow := fmt.Sprintf(`
(async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const check = async (u) => {
    try {
      const r = await fetch(u, { credentials: 'include' });
      if (!r.ok) return '';
      const t = await r.text();
      try { const j = JSON.parse(t); if (j && j.authenticated === true) return t; } catch (_) {}
    } catch(_) {}
    return '';
  };
  try {
    // seed session
    try { await fetch('%s', { credentials: 'include' }); } catch(_) {}
    for (let k=0;k<4;k++) {
      await fetch('%s', { credentials: 'include' });           // validate
      let ok = false;
      try {
        const r1 = await fetch('%s', { method: 'POST', credentials: 'include' });
        ok = r1 && (r1.ok || r1.status === 204);
      } catch (_) {}
      if (!ok) {
        try {
          const r2 = await fetch('%s', { method: 'POST', credentials: 'include' });
          ok = r2 && (r2.ok || r2.status === 204);
        } catch (_) {}
      }
      for (let i=0;i<24;i++) { // ~36s per outer try
        let t = await check('%s'); if (!t) t = await check('%s');
        if (t) return t;
        await sleep(1500);
      }
    }
    return '';
  } catch(e) {
    return '';
  }
})()
`, jsEscape(tickleURL), jsEscape(validateURL), jsEscape(reauthURLPrimary), jsEscape(reauthURLFallback), jsEscape(statusURL1), jsEscape(statusURL2))

    var finalJSON string
    // 4) Run the flow once; if it doesn't flip yet, we keep nudging it a few more times.
    for i := 0; i < 6; i++ { // ~6 * 5s ≈ 30s; outer context still has long timeout
        _ = chromedp.Run(cctx, chromedp.Evaluate(jsFlow, &finalJSON))
        if strings.Contains(finalJSON, `"authenticated":true`) {
            break
        }
        time.Sleep(5 * time.Second)
    }
    if !strings.Contains(finalJSON, `"authenticated":true`) {
        return errors.New("browser flow did not reach authenticated:true (finish 2FA, or extend EXIT_INDICATOR_LOGIN_WAIT_SECONDS)")
    }

    // 3) Export cookies from Chrome and inject into our Go http jar for the base host.
    syncCookies := func() error {
        cks, err := network.GetCookies().WithURLs([]string{opts.BaseURL}).Do(cctx)
        if err != nil {
            return fmt.Errorf("get cookies: %w", err)
        }
        var httpCookies []*http.Cookie
        for _, ck := range cks {
            httpCookies = append(httpCookies, &http.Cookie{
                Name:     ck.Name,
                Value:    ck.Value,
                Path:     ck.Path,
                Secure:   ck.Secure,
                HttpOnly: ck.HTTPOnly,
                Expires: func() time.Time {
                    if ck.Expires == 0 { return time.Time{} }
                    return time.Unix(int64(ck.Expires), 0)
                }(),
            })
        }
        httpJar.SetCookies(u, httpCookies)
        return nil
    }

    // First sync once
    if err := syncCookies(); err != nil {
        return err
    }

    // 4) Final assurance: poll /auth/status from Go using the synced cookies.
    // Give this a short window (e.g., 2 minutes or whatever remains from 'wait').
    remain := time.Until(time.Now().Add(2 * time.Minute))
    if remain <= 0 { remain = 2 * time.Minute }

    ok, _ := pollGatewayStatus(cctx, opts.BaseURL, httpJar, remain)
    if ok {
        return nil
    }

    // If still false, do a few more sync+poll rounds in case the page set late cookies.
    for i := 0; i < 5; i++ {
        _ = syncCookies()
        if ok, _ = pollGatewayStatus(cctx, opts.BaseURL, httpJar, 15*time.Second); ok {
            return nil
        }
    }

    return errors.New("browser flow did not reach authenticated:true (finish 2FA, or extend EXIT_INDICATOR_LOGIN_WAIT_SECONDS)")
}

// helper to make the JS string safe
func jsEscape(s string) string {
	r := strings.ReplaceAll(s, `\`, `\\`)
	r = strings.ReplaceAll(r, `"`, `\"`)
	return r
}
