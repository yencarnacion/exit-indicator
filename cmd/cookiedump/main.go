package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"exit-indicator/internal/cookies"
)

func main() {
	var (
		from = flag.String("from-browser", "chrome", `browser: chrome|chromium|edge|brave|opera (optionally append :/path/to/profile)`)
		forURL = flag.String("for", "", "base URL whose cookies to extract (e.g., https://localhost:5001)")
		out  = flag.String("out", "./data/session.json", "output file path (exit-indicator session.json format)")
	)
	flag.Parse()

	if *forURL == "" {
		log.Fatal("required: --for <baseURL>, e.g. --for https://localhost:5001")
	}
	if _, err := url.ParseRequestURI(*forURL); err != nil {
		log.Fatalf("bad --for URL: %v", err)
	}

	cks, err := cookies.ExtractFromBrowser(*from, *forURL)
	if err != nil {
		log.Fatalf("extract: %v", err)
	}

	if err := cookies.SaveAsSessionJSON(*out, cks); err != nil {
		log.Fatalf("save: %v", err)
	}

	fmt.Printf("Saved %d cookies for %s to %s\n", len(cks), *forURL, *out)
}
