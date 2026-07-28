package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"banner-fingerprint/internal/api"
	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/rules"
)

func main() {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	var err error
	switch command {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (expected serve or healthcheck)", command)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rulesPath := envString("RULES_PATH", "configs/fingerprints.json")
	ruleSet, err := rules.LoadFile(rulesPath)
	if err != nil {
		return err
	}
	engine := fingerprint.NewEngine(ruleSet)

	limits := api.Limits{
		MaxBodyBytes:   envInt64("MAX_BODY_BYTES", 4<<20),
		MaxBatchSize:   envInt("MAX_BATCH_SIZE", 1000),
		MaxBannerBytes: envInt("MAX_BANNER_BYTES", 64<<10),
	}
	handler := api.NewHandler(engine, logger, limits).Routes()
	server := &http.Server{
		Addr:              envString("LISTEN_ADDR", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	shutdownSignals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("server starting", "address", server.Addr, "rules", engine.RuleCount())
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-shutdownSignals.Done():
		logger.Info("server shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			_ = server.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

func healthcheck(arguments []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := flags.String("url", "http://127.0.0.1:8080/health", "health endpoint URL")
	timeout := flags.Duration("timeout", 3*time.Second, "request timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	client := &http.Client{Timeout: *timeout}
	response, err := client.Get(*url)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	var result struct {
		Status      string `json:"status"`
		RulesLoaded int    `json:"rules_loaded"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode health response: %w", err)
	}
	if result.Status != "ok" || result.RulesLoaded < 1 {
		return fmt.Errorf("server is not ready: status=%q rules_loaded=%d", result.Status, result.RulesLoaded)
	}
	return nil
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := envString(name, strconv.Itoa(fallback))
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envInt64(name string, fallback int64) int64 {
	value := envString(name, strconv.FormatInt(fallback, 10))
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
