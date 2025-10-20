package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"exit-indicator/internal/cookies"
)

func main() {
	from := flag.String("from-browser", "chrome", "browser name (hint; all supported browsers are scanned)")
	forURL := flag.String("for", "", "URL to dump cookies for (e.g., https://localhost:5001)")
	out := flag.String("out", "./data/session.json", "output JSON path for session cookies")
	flag.Parse()

	if *forURL == "" {
		log.Fatal("--for URL is required")
	}
	_ = from // reserved for future: narrowing to a specific browser

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cs, err := cookies.ForURL(ctx, *forURL)
	if err != nil {
		log.Fatalf("read cookies: %v", err)
	}
	if err := cookies.WriteDump(*out, cs); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	fmt.Printf("Wrote %d cookies for %s to %s\n", len(cs), *forURL, *out)
}
