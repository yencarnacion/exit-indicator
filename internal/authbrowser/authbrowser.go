package authbrowser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type Options struct {
	BaseURL      string        // e.g. https://localhost:5001
	RL           int           // 1=live, 2=paper
	Headless     bool          // false => show window for 2FA
	Wait         time.Duration // overall timeout (e.g., 2-5 minutes)
	UserDataDir  string        // optional Chrome profile dir; empty => temp
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
	if wait <= 0 { wait = 3 * time.Minute }

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
	cctx, cancel := chromedp.NewContext(actx) // creates a new browser tab
	defer cancel()

	// Give the whole flow a max time
	cctx, timeoutCancel := context.WithTimeout(cctx, wait)
	defer timeoutCancel()

	loginURL := fmt.Sprintf("%s/sso/Login?forwardTo=22&RL=%d&ip2loc=on", opts.BaseURL, opts.RL)
	validateURL := opts.BaseURL + "/v1/portal/sso/validate"
	reauthURL := opts.BaseURL + "/v1/portal/iserver/reauthenticate?force=true"
	statusURL := opts.BaseURL + "/v1/api/iserver/auth/status"

	// Enable network domain to fetch HttpOnly cookies
	if err := chromedp.Run(cctx, network.Enable()); err != nil {
		return err
	}

	// 1) Navigate to login
	if err := chromedp.Run(cctx, chromedp.Navigate(loginURL)); err != nil {
		return fmt.Errorf("navigate login: %w", err)
	}

	// 2) Wait for user to complete 2FA: we poll status via XHRs in page context.
	//    We'll call validate→reauth from the page context (fetch with credentials)
	//    to ensure browser session is used, then we’ll export cookies to Go jar.

	// Helper JS executed in page: perform validate → reauth → status and return final JSON text
	jsFlow := fmt.Sprintf(`
(async () => {
  try {
    // validate
    await fetch('%s', { credentials: 'include' });
    // reauth
    await fetch('%s', { method: 'POST', credentials: 'include' });
    // poll status a few times
    let out = null;
    for (let i=0;i<10;i++) {
      const r = await fetch('%s', { credentials: 'include' });
      if (r.ok) {
        const t = await r.text();
        try {
          const j = JSON.parse(t);
          if (j && j.authenticated === true) { out = t; break; }
        } catch(_) {}
      }
      await new Promise(res => setTimeout(res, 1500));
    }
    return out || '';
  } catch(e) {
    return '';
  }
})()
`, jsEscape(validateURL), jsEscape(reauthURL), jsEscape(statusURL))

	var finalJSON string
	// We loop: user completes 2FA in visible browser → our JS succeeds
	for i := 0; i < 30; i++ { // up to ~45s polling here; outer context has full timeout
		if err := chromedp.Run(cctx,
			// Try running the JS flow; it silently returns '' until login actually finished
			chromedp.Evaluate(jsFlow, &finalJSON),
		); err != nil {
			// ignore transient errors; small wait then retry
		}
		if strings.Contains(finalJSON, `"authenticated":true`) {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if !strings.Contains(finalJSON, `"authenticated":true`) {
		return errors.New("browser flow did not reach authenticated:true (did you finish 2FA?)")
	}

    // 3) Export cookies from Chrome and inject into our Go http jar for the base host.
    // Use GetCookies (works across cdproto versions); scope by URL.
    cks, err := network.GetCookies().WithUrls([]string{opts.BaseURL}).Do(cctx)
    if err != nil {
        return fmt.Errorf("get cookies: %w", err)
    }

    var httpCookies []*http.Cookie
    for _, ck := range cks {
        // Scope cookies to the exact request URL host (leave Domain empty).
        httpCookies = append(httpCookies, &http.Cookie{
            Name:     ck.Name,
            Value:    ck.Value,
            Path:     ck.Path,
            Secure:   ck.Secure,
            HttpOnly: ck.HTTPOnly,
			// In your chromedp/cdproto, Expires is a float64 (seconds since epoch). 0 => session cookie.
			Expires: func() time.Time {
				if ck.Expires == 0 {
					return time.Time{}
				}
				return time.Unix(int64(ck.Expires), 0)
			}(),
        })
    }
    httpJar.SetCookies(u, httpCookies)
    return nil
}

// helper to make the JS string safe
func jsEscape(s string) string {
	r := strings.ReplaceAll(s, `\`, `\\`)
	r = strings.ReplaceAll(r, `"`, `\"`)
	return r
}
