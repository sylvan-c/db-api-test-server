package router

import (
	"db-api-test-server/internal/api/handlers"
	"db-api-test-server/internal/api/middleware"
	"db-api-test-server/internal/app"
	"net/http"

	"github.com/gorilla/mux"
)

func NewRouter(app *app.App) http.Handler {
	emptyHandler := handlers.NewEmptyHandler()
	authHandler := handlers.NewAuthHandler(app)
	userHandler := handlers.NewUserHandler(app)
	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/login", authHandler.Login).Methods("POST")
	api.HandleFunc("/createuser", userHandler.CreateUser).Methods("POST")
	api.HandleFunc("/refresh", authHandler.RefreshAccessToken).Methods("POST")
	api.HandleFunc("/logout", authHandler.LogOut).Methods("POST")
	api.HandleFunc("/logout/all", authHandler.LogOutAll).Methods("POST")
	api.HandleFunc("/health", emptyHandler.Health).Methods("GET")

	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.JWTMiddleware(authHandler))
	protected.HandleFunc("/users/me", userHandler.GetMeRedirect).Methods("GET")
	protected.HandleFunc("/users/{id}", userHandler.GetUser).Methods("GET")

	return r
}
