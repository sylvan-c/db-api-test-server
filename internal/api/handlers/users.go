package handlers

import (
	"db-api-test-server/internal/api/contextkeys"
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
