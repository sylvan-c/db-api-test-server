package main

import (
	"fmt"
	"log"
	"net/http"

	"db-api-test-server/internal/api/router"
	"db-api-test-server/internal/app"
	"db-api-test-server/internal/auth"
	"db-api-test-server/internal/config"
	"db-api-test-server/internal/db"
	"db-api-test-server/internal/external"
)

func main() {
	cfg := config.Load()

	conn, err := db.Connect(cfg.DBDsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer conn.Close()

	authAdapter := auth.AuthAdapter{
		Tokens:    auth.NewJWTAuth(cfg.JWTSecret),
		Passwords: auth.NewPasswordAuth(),
	}
	apiClient := external.NewClient(cfg.ExternalAPIBaseURL)

	application := app.New(conn, &authAdapter, apiClient)
	router := router.NewRouter(application)

	fmt.Println("Server running on :" + cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, router))
}
