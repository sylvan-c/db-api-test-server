package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"net/http"
)

type Handler struct {
	App *app.App
}

func NewHandler(a *app.App) *Handler {
	return &Handler{App: a}
}

func respondJSON(w http.ResponseWriter, payload any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
