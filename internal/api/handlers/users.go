package handlers

import (
	"db-api-test-server/internal/api/contextkeys"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vars := mux.Vars(r)
	userPubID := vars["id"]

	userID, err := h.User.GetUserIDByPublicID(ctx, userPubID)
	if err != nil {
		log.Printf("invalid public id. public id: %s", userPubID)
		http.Error(w, "user not found", http.StatusNotFound)
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
	ctx := r.Context()

	idVal := r.Context().Value(contextkeys.UserID)
	if idVal == nil {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}

	userID, ok := idVal.(int)
	if !ok {
		log.Printf("invalid user id type. user id: %v", idVal)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	userPubID, err := h.User.GetPublicIDForUser(ctx, userID)
	if err != nil {
		log.Printf("could not find public id for user id: %d", userID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("/api/users/%s", userPubID)

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
	if len(updates) == 0 {
		log.Printf("Nothing to update")
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	for k := range updates {
		if !allowed[k] {
			http.Error(w, fmt.Sprintf("invalid option: %s", k), http.StatusBadRequest)
			return
		}
	}
	vars := mux.Vars(r)
	userPubID := vars["id"]
	userID, err := h.User.GetUserIDByPublicID(ctx, userPubID)
	if err != nil {
		log.Printf("invalid public id. public id: %s", userPubID)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	user, err := h.User.UpdateProfile(ctx, userID, updates)
	if err != nil {
		log.Printf("UpdateProfile failed: %s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, user, http.StatusOK)
}
