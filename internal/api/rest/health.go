package rest

import (
	"context"
	"net/http"
	"time"

	"github.com/travisbale/heimdall/sdk"
)

func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
	defer cancel()

	if err := r.DB.Health(ctx); err != nil {
		r.writeError(ctx, w, http.StatusServiceUnavailable, "Database unavailable", err)
		return
	}

	r.writeJSON(w, http.StatusOK, sdk.HealthResponse{Status: "OK"})
}
