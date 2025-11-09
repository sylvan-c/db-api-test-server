package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func (h *Handler) Users(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listUsers(w, r)
	case http.MethodPost:
		h.createUser(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) listUsers(w http.ResponseWriter, _ *http.Request) {
	usersList, err := h.App.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	respondJSON(w, usersList, http.StatusOK)
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req app.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || req.Email == "" || req.FirstName == "" || req.LastName == "" {
		http.Error(w, "Username, password, email, first name and last name are required", http.StatusBadRequest)
		return
	}

	user, err := h.App.CreateUser(&req)
	if err != nil {
		if err == app.ErrPasswordInvalidFormat {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			log.Printf("Error creating user - %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/api/users/%d", user.Id))
	respondJSON(w, user, http.StatusCreated)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.App.GetUserByID(userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	respondJSON(w, user, http.StatusOK)
}
