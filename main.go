package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"db-api-test-server/internal/db"
	"db-api-test-server/internal/handlers"
)

func main() {
	dsn := fmt.Sprintf(
		"host=db user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
	)

	conn, err := db.Connect(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %v", err)
	}
	defer conn.Close()

	h := handlers.NewHandler(conn)

	http.HandleFunc("/health", h.Health)
	http.HandleFunc("/test", h.Test)

	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
