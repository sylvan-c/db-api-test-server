package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type loginResponse struct {
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
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
		respondJSON(w, loginResponse{}, http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	accessToken, err := h.App.Auth.GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}
	refreshToken, err := h.App.GenerateRefreshToken(userID)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}
	respondJSON(w, loginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, http.StatusOK)
}

func (h *Handler) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	accessToken, err := h.App.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	respondJSON(w, loginResponse{AccessToken: accessToken}, http.StatusOK)
}

func (h *Handler) LogOut(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	err := h.App.RevokeRefreshToken(req.RefreshToken)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to revoke refresh token", http.StatusInternalServerError)
		return
	}

	respondJSON(w, nil, http.StatusOK)
}
