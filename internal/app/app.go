package app

import (
	"database/sql"
	"db-api-test-server/internal/auth"
	"db-api-test-server/internal/external"
)

type App struct {
	DB     *sql.DB
	Auth   *auth.JWTService
	Client *external.Client
}

func New(db *sql.DB, auth *auth.JWTService, client *external.Client) *App {
	return &App{
		DB:     db,
		Auth:   auth,
		Client: client,
	}
}
