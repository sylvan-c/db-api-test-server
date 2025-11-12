package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"net/http"
)

type EmptyHandler struct{}

func NewEmptyHandler() *EmptyHandler {
	return &EmptyHandler{}
}

type AuthHandler struct {
	Auth app.AuthService
}

func NewAuthHandler(a app.AuthService) *AuthHandler {
	return &AuthHandler{Auth: a}
}

type UserHandler struct {
	User app.UserService
}

func NewUserHandler(u app.UserService) *UserHandler {
	return &UserHandler{User: u}
}

func respondJSON(w http.ResponseWriter, payload any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
