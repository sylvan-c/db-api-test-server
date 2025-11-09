package app

import (
	"database/sql"
	"db-api-test-server/internal/auth"
	"errors"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

func (a *App) AuthenticateUser(username, password string) (int, error) {
	var userID int
	var passwordHash string

	err := a.DB.QueryRow(`SELECT id, password_hash FROM users WHERE username=$1`, username).
		Scan(&userID, &passwordHash)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalidCredentials
	} else if err != nil {
		return 0, err
	}

	if err := auth.AuthenticateUser(passwordHash, password); err != nil {
		return 0, ErrInvalidCredentials
	}

	return userID, nil
}
