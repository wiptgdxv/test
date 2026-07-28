package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

func TestHealth(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"ok"`) || !strings.Contains(response.Body.String(), `"rules_loaded":`) {
		t.Fatalf("unexpected health response: %d %s", response.Code, response.Body.String())
	}
}

func TestFingerprintBatch(t *testing.T) {
	inputs := []model.ScanInput{
		{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu"},
		{IP: "1.2.3.5", Port: 9999, Banner: "no match"},
	}
	body, _ := json.Marshal(inputs)
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewReader(body))
	response := httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d %s", response.Code, response.Body.String())
	}
	var results []model.Fingerprint
	if err := json.Unmarshal(response.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Product != "OpenSSH" || results[1].Protocol != "unknown" {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestFingerprintRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
		code int
	}{
		{name: "malformed", body: `[`, code: http.StatusBadRequest},
		{name: "not array", body: `null`, code: http.StatusBadRequest},
		{name: "unknown field", body: `[{"ip":"x","port":1,"banner":"x","extra":1}]`, code: http.StatusBadRequest},
		{name: "invalid port", body: `[{"ip":"x","port":70000,"banner":"x"}]`, code: http.StatusBadRequest},
		{name: "too many", body: `[{"ip":"a","port":1,"banner":""},{"ip":"b","port":2,"banner":""},{"ip":"c","port":3,"banner":""}]`, code: http.StatusRequestEntityTooLarge},
		{name: "banner too long", body: `[{"ip":"x","port":1,"banner":"123456789"}]`, code: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(tt.body))
			response := httptest.NewRecorder()
			testHandlerWithLimits(t, Limits{MaxBodyBytes: 1024, MaxBatchSize: 2, MaxBannerBytes: 8}).ServeHTTP(response, request)
			if response.Code != tt.code {
				t.Fatalf("got %d, want %d: %s", response.Code, tt.code, response.Body.String())
			}
		})
	}
}

func TestFingerprintBodyLimitAndMethod(t *testing.T) {
	largeBody := `[{"ip":"x","port":1,"banner":"` + strings.Repeat("x", 200) + `"}]`
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(largeBody))
	response := httptest.NewRecorder()
	testHandlerWithLimits(t, Limits{MaxBodyBytes: 32, MaxBatchSize: 2, MaxBannerBytes: 8}).ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit status = %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/fingerprint", nil)
	response = httptest.NewRecorder()
	testHandler(t).ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status = %d", response.Code)
	}
}

func testHandler(t *testing.T) http.Handler {
	return testHandlerWithLimits(t, Limits{MaxBodyBytes: 1 << 20, MaxBatchSize: 100, MaxBannerBytes: 1 << 16})
}

func testHandlerWithLimits(t *testing.T, limits Limits) http.Handler {
	t.Helper()
	set, err := rules.LoadFile(filepath.Join("..", "..", "configs", "fingerprints.json"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(fingerprint.NewEngine(set), logger, limits).Routes()
}
