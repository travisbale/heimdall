package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// respondJSON sends a JSON response with the given status code
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
	}
}

// respondError sends a JSON error response
func respondError(w http.ResponseWriter, status int, message string, err error) {
	// Log the error but don't return it to the user
	slog.Error(message, "error", err)

	respondJSON(w, status, map[string]string{
		"error": message,
	})
}

// decodeJSON decodes JSON from the request body
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			slog.Error("failed to close request body")
		}
	}()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	return nil
}
