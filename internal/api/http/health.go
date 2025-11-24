package http

import (
	"context"
	"net/http"
	"time"

	"github.com/travisbale/heimdall/sdk"
)

type HealthHandler struct {
	db database
}

func NewHealthHandler(config *Config) *HealthHandler {
	return &HealthHandler{
		db: config.Database,
	}
}

// HandleHealth handles health check requests
func (h *HealthHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	// Check database connectivity with 2 second timeout
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.db.Health(ctx); err != nil {
		respondJSON(w, http.StatusServiceUnavailable, &sdk.HealthResponse{
			Status: "unhealthy",
		})
		return
	}

	respondJSON(w, http.StatusOK, &sdk.HealthResponse{
		Status: "healthy",
	})
}
