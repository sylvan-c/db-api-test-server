package config

import (
	"fmt"
	"os"
)

type Config struct {
	Port               string
	DBDsn              string
	JWTSecret          string
	ExternalAPIBaseURL string
}

func Load() Config {
	return Config{
		Port: getEnv("PORT", "8080"),
		DBDsn: fmt.Sprintf(
			"host=db user=%s password=%s dbname=%s sslmode=disable",
			os.Getenv("POSTGRES_USER"),
			os.Getenv("POSTGRES_PASSWORD"),
			os.Getenv("POSTGRES_DB"),
		),
		JWTSecret:          getEnv("JWT_SECRET", "supersecret"),
		ExternalAPIBaseURL: getEnv("EXTERNAL_API_URL", "https://api.example.com"),
	}
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
