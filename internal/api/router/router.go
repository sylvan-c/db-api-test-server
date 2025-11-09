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

	r.HandleFunc("/health", h.Health).Methods("GET")
	r.HandleFunc("/test", h.Test).Methods("GET", "POST")
	r.HandleFunc("/login", h.Login).Methods("POST")

	// r.HandleFunc("/login", h.Login).Methods("POST")

	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.JWTMiddleware(h))
	protected.HandleFunc("/health", h.Health).Methods("GET")
	protected.HandleFunc("/users/{id}", h.GetUser).Methods("GET")
	protected.HandleFunc("/users", h.Users).Methods("GET", "POST")
	return r
}
