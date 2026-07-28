package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"banner-fingerprint/internal/fingerprint"
	"banner-fingerprint/internal/model"
)

// Limits bounds resource consumption for public API requests.
type Limits struct {
	MaxBodyBytes   int64
	MaxBatchSize   int
	MaxBannerBytes int
}

// Handler owns the HTTP API dependencies.
type Handler struct {
	engine *fingerprint.Engine
	logger *slog.Logger
	limits Limits
}

// NewHandler creates a production API handler with explicit safety limits.
func NewHandler(engine *fingerprint.Engine, logger *slog.Logger, limits Limits) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{engine: engine, logger: logger, limits: limits}
}

// Routes returns the complete API surface.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /fingerprint", h.fingerprint)
	return h.middleware(mux)
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"rules_loaded": h.engine.RuleCount(),
	})
}

func (h *Handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.limits.MaxBodyBytes)
	defer r.Body.Close()

	inputs, err := decodeInputs(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON request: "+err.Error())
		return
	}
	if len(inputs) > h.limits.MaxBatchSize {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("batch exceeds maximum of %d records", h.limits.MaxBatchSize))
		return
	}

	for i, input := range inputs {
		if input.Port < 0 || input.Port > 65535 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("record %d has invalid port", i))
			return
		}
		if len(input.Banner) > h.limits.MaxBannerBytes {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("record %d banner exceeds maximum of %d bytes", i, h.limits.MaxBannerBytes))
			return
		}
		if !utf8.ValidString(input.Banner) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("record %d banner is not valid UTF-8", i))
			return
		}
	}

	writeJSON(w, http.StatusOK, h.engine.IdentifyBatch(inputs))
}

func decodeInputs(r io.Reader) ([]model.ScanInput, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	var inputs []model.ScanInput
	if err := decoder.Decode(&inputs); err != nil {
		return nil, err
	}
	if inputs == nil {
		return nil, errors.New("request must be a JSON array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("request contains multiple JSON values")
		}
		return nil, fmt.Errorf("invalid trailing data: %w", err)
	}
	return inputs, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Error("write JSON response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
