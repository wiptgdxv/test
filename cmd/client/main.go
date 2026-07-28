package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	fingerprintclient "banner-fingerprint/internal/client"
)

func main() {
	input := flag.String("input", "", "path to the input JSON file (required)")
	serverURL := flag.String("server", envString("SERVER_URL", "http://127.0.0.1:8080"), "fingerprint server base URL")
	outputPath := flag.String("output", "", "optional output JSON file; stdout when omitted")
	timeout := flag.Duration("timeout", 15*time.Second, "overall request timeout")
	pretty := flag.Bool("pretty", true, "pretty-print JSON output")
	flag.Parse()

	output, closeOutput, err := outputWriter(*outputPath)
	if err != nil {
		fail(err)
	}
	defer closeOutput()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	httpClient := &http.Client{Timeout: *timeout}
	err = fingerprintclient.Run(ctx, httpClient, fingerprintclient.Config{
		InputPath: *input,
		ServerURL: *serverURL,
		Pretty:    *pretty,
	}, output)
	if err != nil {
		fail(err)
	}
}

func outputWriter(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open output file: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
