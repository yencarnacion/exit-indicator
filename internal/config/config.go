package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port                   int    `yaml:"port"`
	DefaultThresholdShares int    `yaml:"default_threshold_shares"`
	SoundFile              string `yaml:"sound_file"`
	CooldownSeconds        int    `yaml:"cooldown_seconds"`
	SmartDepth             bool   `yaml:"smart_depth"`
	LevelsToScan           int    `yaml:"levels_to_scan"`
	PriceReference         string `yaml:"price_reference"`
	LogLevel               string `yaml:"log_level"`
	IBKRGatewayURL         string `yaml:"ibkr_gateway_url"`
	SessionStorePath       string `yaml:"session_store_path"`
}

func defaults() Config {
	return Config{
		Port:                   8086,
		DefaultThresholdShares: 20000,
		SoundFile:              "./web/sounds/hey.mp3",
		CooldownSeconds:        1,
		SmartDepth:             true,
		LevelsToScan:           10,
		PriceReference:         "best_ask",
		LogLevel:               "info",
		IBKRGatewayURL:         "https://127.0.0.1:5000",
		SessionStorePath:       "./data/session.json",
	}
}

func Load(path string) (Config, error) {
	cfg := defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse yaml: %w", err)
	}
	// Validation & normalization
	if cfg.LevelsToScan != 10 {
		return cfg, errors.New("levels_to_scan must be 10")
	}
	switch strings.ToLower(cfg.PriceReference) {
	case "best_ask":
		cfg.PriceReference = "best_ask"
	default:
		return cfg, errors.New(`price_reference must be "best_ask"`)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return cfg, errors.New("invalid port")
	}
	if cfg.DefaultThresholdShares < 1 {
		return cfg, errors.New("default_threshold_shares must be >=1")
	}
	return cfg, nil
}

func NewLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}


