package handlers

import (
	"db-api-test-server/internal/api/contextkeys"
	"db-api-test-server/internal/app"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req app.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || req.Email == "" || req.FirstName == "" || req.LastName == "" {
		http.Error(w, "Username, password, email, first name and last name are required", http.StatusBadRequest)
		return
	}

	user, err := h.User.CreateUser(&req)
	if err != nil {
		if err == app.ErrPasswordInvalidFormat {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			log.Printf("Error creating user - %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Location", fmt.Sprintf("/api/users/%d", user.ID))
	respondJSON(w, user, http.StatusCreated)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	userID, err := strconv.Atoi(idStr)
	if err != nil || userID <= 0 {
		http.Error(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.User.GetUserByID(userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	respondJSON(w, user, http.StatusOK)
}

func (h *UserHandler) GetMeRedirect(w http.ResponseWriter, r *http.Request) {
	idVal := r.Context().Value(contextkeys.UserID)
	if idVal == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, ok := idVal.(int)
	if !ok {
		http.Error(w, "invalid user id type", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("/api/users/%d", userID)

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}
