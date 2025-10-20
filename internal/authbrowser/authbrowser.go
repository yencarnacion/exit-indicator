package authbrowser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

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

    // 2) Wait for the interactive SSO to complete.
    // We poll location until we leave the login page/dispatcher; then we run validate→reauth→status.
    var loc string
    for i := 0; i < 200; i++ { // ~200 * 2s = ~400s inside the overall 'wait'
        _ = chromedp.Run(cctx, chromedp.Evaluate(`window.location.pathname || ""`, &loc))
        // once user finished 2FA, the page is no longer the /sso/Login route; often via /sso/Dispatcher then UI
        if !strings.Contains(loc, "/sso/Login") {
            break
        }
        time.Sleep(2 * time.Second)
    }

    // 3) Now perform validate→reauth→status in page context (uses browser cookies).
    jsFlow := fmt.Sprintf(`
(async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  try {
    for (let k=0;k<3;k++) { // a couple of tries
      await fetch('%s', { credentials: 'include' });
      await fetch('%s', { method: 'POST', credentials: 'include' });
      for (let i=0;i<20;i++) { // up to ~30s (20 * 1500ms)
        const r = await fetch('%s', { credentials: 'include' });
        if (r.ok) {
          const t = await r.text();
          try {
            const j = JSON.parse(t);
            if (j && j.authenticated === true) return t;
          } catch (_) {}
        }
        await sleep(1500);
      }
    }
    return '';
  } catch(e) {
    return '';
  }
})()
`, jsEscape(validateURL), jsEscape(reauthURL), jsEscape(statusURL))

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
