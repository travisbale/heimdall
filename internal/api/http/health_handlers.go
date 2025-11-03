package http

import (
	"net/http"

	"github.com/travisbale/heimdall/sdk"
)

// HandleHealth handles health check requests
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, &sdk.HealthResponse{
		Status: "OK",
	})
}
