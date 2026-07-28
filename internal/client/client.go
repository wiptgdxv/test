package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"banner-fingerprint/internal/model"
)

const maxResponseBytes = 32 << 20

// Config contains all client behavior that differs by invocation.
type Config struct {
	InputPath string
	ServerURL string
	Pretty    bool
}

// Run reads a local batch, calls the server, and writes the returned results.
func Run(ctx context.Context, httpClient *http.Client, cfg Config, output io.Writer) error {
	if strings.TrimSpace(cfg.InputPath) == "" {
		return errors.New("input path is required")
	}
	endpoint, err := fingerprintEndpoint(cfg.ServerURL)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}
	inputs, err := decodeInputFile(data)
	if err != nil {
		return fmt.Errorf("parse input file: %w", err)
	}
	payload, err := json.Marshal(inputs)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	response, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call fingerprint server: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read server response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return errors.New("server response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("server returned %s: %s", response.Status, compactError(body))
	}

	var results []model.Fingerprint
	if err := json.Unmarshal(body, &results); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	if len(results) != len(inputs) {
		return fmt.Errorf("server returned %d results for %d inputs", len(results), len(inputs))
	}

	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if cfg.Pretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	return nil
}

func fingerprintEndpoint(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("server URL must use http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("server URL must include a host")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/fingerprint"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func decodeInputFile(data []byte) ([]model.ScanInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var inputs []model.ScanInput
	if err := decoder.Decode(&inputs); err != nil {
		return nil, err
	}
	if inputs == nil {
		return nil, errors.New("input must be a JSON array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("input contains multiple JSON values")
		}
		return nil, err
	}
	return inputs, nil
}

func compactError(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 512 {
		return text[:512] + "..."
	}
	if text == "" {
		return "empty response"
	}
	return text
}
