package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
)

type loginRequest struct {
	Email      string    `json:"email"`
	Password   string    `json:"password"`
	DeviceUUID uuid.UUID `json:"deviceUUID"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type loginResponse struct {
	AccessToken  string     `json:"accessToken,omitempty"`
	RefreshToken string     `json:"refreshToken,omitempty"`
	DeviceUUID   *uuid.UUID `json:"deviceUUID,omitempty"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

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

	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}

	deviceUUID := req.DeviceUUID
	var err error
	if deviceUUID == uuid.Nil {
		deviceUUID, err = uuid.NewV7()
		if err != nil {
			log.Printf("error generating device uuid - %s", err.Error())
			http.Error(w, "internal server error", http.StatusBadRequest)
		}
	}

	userID, err := h.Auth.AuthenticateUser(ctx, req.Email, req.Password)
	if errors.Is(err, app.ErrInvalidCredentials) {
		respondJSON(w, loginResponse{}, http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	accessToken, err := h.Auth.GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}
	refreshToken, err := h.Auth.GenerateRefreshToken(ctx, userID, deviceUUID)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}
	respondJSON(w, loginResponse{AccessToken: accessToken, RefreshToken: refreshToken, DeviceUUID: &deviceUUID}, http.StatusOK)
}

func (h *AuthHandler) RefreshAccessToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "refreshToken is required", http.StatusBadRequest)
		return
	}

	accessToken, err := h.Auth.RefreshAccessToken(ctx, req.RefreshToken)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to generate access token", http.StatusInternalServerError)
		return
	}

	respondJSON(w, loginResponse{AccessToken: accessToken}, http.StatusOK)
}

func (h *AuthHandler) LogOut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "refreshToken is required", http.StatusBadRequest)
		return
	}

	err := h.Auth.RevokeRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to revoke refresh token", http.StatusInternalServerError)
		return
	}

	respondJSON(w, nil, http.StatusOK)
}

func (h *AuthHandler) LogOutAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "refreshToken is required", http.StatusBadRequest)
		return
	}

	err := h.Auth.RevokeAllRefreshTokens(ctx, req.RefreshToken)
	if err != nil {
		log.Printf("%v", err.Error())
		http.Error(w, "failed to revoke refresh tokens", http.StatusInternalServerError)
		return
	}

	respondJSON(w, nil, http.StatusOK)
}

func (h *AuthHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req app.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	userID, err := h.Auth.CreateUser(ctx, &req)
	if err != nil {
		if err == app.ErrPasswordInvalidFormat {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			log.Printf("Error creating user - %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/api/users/%s", userID))
	respondJSON(w, map[string]uuid.UUID{"userID": userID}, http.StatusCreated)
}
