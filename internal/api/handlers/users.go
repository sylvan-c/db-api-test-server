package handlers

import (
	"db-api-test-server/internal/api/contextkeys"
	"db-api-test-server/internal/app"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		http.Error(w, "invalid user id", http.StatusNotFound)
		return
	}

	user, err := h.User.GetUserByID(ctx, userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	respondJSON(w, user, http.StatusOK)
}

func (h *UserHandler) GetMeRedirect(w http.ResponseWriter, r *http.Request) {
	idVal := r.Context().Value(contextkeys.UserID)
	if idVal == nil {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	userID, ok := idVal.(uuid.UUID)
	if !ok {
		log.Printf("invalid user id type. user id: %v", idVal)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("/api/users/%s", userID)

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var updates map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	log.Print(updates)
	allowed := map[string]bool{
		"firstName": true,
		"lastName":  true,
	}
	for k := range updates {
		if !allowed[k] {
			http.Error(w, fmt.Sprintf("invalid option: %s", k), http.StatusBadRequest)
			return
		}
	}
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		http.Error(w, "invalid user id", http.StatusNotFound)
		return
	}

	user, err := h.User.UpdateProfile(ctx, userID, updates)
	if errors.Is(err, app.ErrUnmappedKey) {
		http.Error(w, "invalid key in request", http.StatusBadRequest)
		return
	} else if err != nil {
		log.Printf("UpdateProfile failed: %s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, user, http.StatusOK)
}
