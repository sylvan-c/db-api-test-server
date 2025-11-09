package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"errors"
	"net/http"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token   string `json:"token,omitempty"`
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}

	userID, err := h.App.AuthenticateUser(req.Username, req.Password)
	if errors.Is(err, app.ErrInvalidCredentials) {
		respondJSON(w, loginResponse{Success: false, Message: "invalid credentials"}, http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	token, err := h.App.Auth.GenerateToken(userID)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	respondJSON(w, loginResponse{Token: token, Success: true, Message: "password verified"}, http.StatusOK)
}
