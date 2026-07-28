package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"banner-fingerprint/internal/model"
)

func TestRunReadsCallsAndWrites(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "input.json")
	input := []byte(`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_9.0"}]`)
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/fingerprint" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]model.Fingerprint{{
			IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.0", Confidence: 0.95,
		}})
	}))
	defer server.Close()

	var output bytes.Buffer
	err := Run(context.Background(), server.Client(), Config{InputPath: inputPath, ServerURL: server.URL, Pretty: true}, &output)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !strings.Contains(output.String(), `"product": "OpenSSH"`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestRunRejectsServerErrorAndBadConfiguration(t *testing.T) {
	if err := Run(context.Background(), http.DefaultClient, Config{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected missing input error")
	}

	inputPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inputPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	err := Run(context.Background(), server.Client(), Config{InputPath: inputPath, ServerURL: server.URL}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected server status error, got %v", err)
	}
}
