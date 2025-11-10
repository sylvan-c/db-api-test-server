package router

import (
	"db-api-test-server/internal/api/handlers"
	"db-api-test-server/internal/api/middleware"
	"db-api-test-server/internal/app"
	"net/http"

	"github.com/gorilla/mux"
)

func NewRouter(app *app.App) http.Handler {
	h := handlers.NewHandler(app)
	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/login", h.Login).Methods("POST")
	api.HandleFunc("/createuser", h.CreateUser).Methods("POST")
	api.HandleFunc("/refresh", h.RefreshAccessToken).Methods("POST")
	api.HandleFunc("/logout", h.LogOut).Methods("POST")
	api.HandleFunc("/logout/all", h.LogOutAll).Methods("POST")
	api.HandleFunc("/health", h.Health).Methods("GET")
	api.HandleFunc("/test", h.Test).Methods("GET", "POST")

	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.JWTMiddleware(h))
	protected.HandleFunc("/users/me", h.GetMeRedirect).Methods("GET")
	protected.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	protected.HandleFunc("/users", h.Users).Methods("GET")

	return r
}
