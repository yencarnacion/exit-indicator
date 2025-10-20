package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"exit-indicator/internal/config"
    "exit-indicator/internal/cookies"
	"exit-indicator/internal/depth"
	"exit-indicator/internal/ibkrcp"
	"exit-indicator/internal/server"
	"exit-indicator/internal/sound"
	"exit-indicator/internal/state"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load() // best-effort: .env is optional

	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config.yaml: %v\n", err)
		os.Exit(1)
	}

	logger := config.NewLogger(cfg.LogLevel)

	logger.Info("exit-indicator starting",
		slog.Int("port", cfg.Port),
		slog.Int("default_threshold_shares", cfg.DefaultThresholdShares),
		slog.String("ibkr_gateway_url", cfg.IBKRGatewayURL),
	)

    // Optional: import cookies from a local browser, like yt-dlp:
    //
    //   go run ./cmd/exit-indicator/main.go --cookies-from-browser chrome https://localhost:5001
    //
    var importBrowser string
    var importBaseURL string
    args := os.Args[1:]
    for i := 0; i < len(args); i++ {
        if args[i] == "--cookies-from-browser" && i+2 < len(args) {
            importBrowser = args[i+1]
            importBaseURL = args[i+2]
            i += 2
        }
    }
    if importBaseURL != "" {
        // If user passed a URL, prefer it over config.yaml's ibkr_gateway_url.
        cfg.IBKRGatewayURL = importBaseURL
    }

	// State
	st := state.NewState(time.Duration(cfg.CooldownSeconds)*time.Second, cfg.DefaultThresholdShares)

	// Sound / hashed URL
	snd, err := sound.NewManager(cfg.SoundFile)
	if err != nil {
		logger.Warn("sound manager init", slog.String("err", err.Error()))
	}

    // IBKR client + feed
    client := ibkrcp.NewClient(cfg.IBKRGatewayURL, cfg.SessionStorePath, logger)

    // If requested, import cookies from a local browser (Chrome/Edge/Brave/Chromium).
    if importBrowser != "" && cfg.IBKRGatewayURL != "" {
        if cookies, err := cookies.ExtractFromBrowser(importBrowser, cfg.IBKRGatewayURL); err != nil {
            logger.Error("cookie import failed", slog.String("err", err.Error()))
        } else {
            client.InjectCookies(cookies)
            logger.Info("imported cookies from browser",
                slog.String("browser", importBrowser),
                slog.Int("count", len(cookies)),
                slog.String("base_url", cfg.IBKRGatewayURL),
                slog.String("session_store", cfg.SessionStorePath),
            )
        }
    }

    feed := ibkrcp.NewGatewayDepthFeed(client, logger)

	// Optional: one-shot login mode to acquire/refresh session and exit.
	for _, a := range os.Args[1:] {
		if a == "--login" {
			ctx, cancelLogin := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancelLogin()
			if err := client.Connect(ctx); err != nil {
				logger.Error("login failed", slog.String("err", err.Error()))
				os.Exit(1)
			}
			logger.Info("login successful (authenticated:true); session saved")
			return
		}
	}

	// Aggregator (pure)
	aggregator := depth.NewAggregator(st, cfg.LevelsToScan)

	// HTTP server + WS hub
	srv := server.NewHTTPServer(cfg, st, snd, feed, aggregator, logger)

	// Context & signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start feed (connect loop)
	go feed.Run(ctx, func(connected bool) {
		st.SetConnected(connected)
		// Push status to browser
		srv.BroadcastStatus()
	})

	// Pipe feed → aggregator → hub
	go func() {
		for {
			select {
			case up, ok := <-feed.Updates():
				if !ok {
					return
				}
				// Compute aggregated book + alerts
				book, alerts := aggregator.ProcessSnapshot(up)
				if len(book) > 0 {
					srv.BroadcastBook(book)
				}
				for _, a := range alerts {
					srv.BroadcastAlert(a)
				}
			case err := <-feed.Errors():
				if err != nil {
					logger.Error("depth feed error", slog.String("err", err.Error()))
					srv.BroadcastError(err.Error())
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// HTTP serving
	httpSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: srv.Router(),
	}

	done := make(chan struct{})
	go func() {
		logger.Info("HTTP server listening", slog.Int("port", cfg.Port))
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", slog.String("err", err.Error()))
			cancel()
		}
		close(done)
	}()

	// Graceful shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	<-sigc

	logger.Info("shutting down...")
	shCtx, shCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer shCancel()

	_ = httpSrv.Shutdown(shCtx)
	feed.Close()
	<-done
	logger.Info("bye")
}


