package app

import (
	"db-api-test-server/internal/auth"
	"db-api-test-server/internal/db"
	"db-api-test-server/internal/external"
)

type App struct {
	DB     db.DBAdapter
	Auth   auth.AuthAdapter
	Client external.ClientService
}

func New(db db.DBAdapter, auth auth.AuthAdapter, client external.ClientService) *App {
	return &App{
		DB:     db,
		Auth:   auth,
		Client: client,
	}
}
