package http

import (
	"context"
	"net/http"
	"time"
)

type HealthHandler struct {
	DB database
}

// HandleHealth handles health check requests
func (h *HealthHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	// Check database connectivity with 2 second timeout
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.DB.Health(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}
