package app

import (
	"crypto/rand"
	"database/sql"
	"db-api-test-server/internal/auth"
	"encoding/base64"
	"errors"
	"log"

	"github.com/google/uuid"
)

type AuthService interface {
	AuthenticateUser(email, password string) (int, error)
	GenerateRefreshToken(userID int, deviceUUID string) (string, error)
	RefreshAccessToken(refreshToken string) (string, error)
	RevokeRefreshToken(refreshToken string) error
	RevokeAllRefreshTokens(refreshToken string) error
	GenerateDeviceUUID() string
	GenerateAccessToken(userID int) (string, error)
	ValidateAccessToken(tokenStr string) (*auth.Claims, error)
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

func (a *App) AuthenticateUser(email, password string) (int, error) {
	var userID int
	var passwordHash string

	err := a.DB.QueryRow(`SELECT id, password_hash FROM users WHERE email=$1`, email).
		Scan(&userID, &passwordHash)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalidCredentials
	} else if err != nil {
		return 0, err
	}

	if err := a.Auth.Passwords.AuthenticateUser(passwordHash, password); err != nil {
		return 0, ErrInvalidCredentials
	}

	return userID, nil
}

func (a *App) GenerateRefreshToken(userID int, deviceUUID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	res, err := a.DB.Exec(`INSERT INTO refresh_tokens (user_id, device_uuid, token, expiry_tst, revoked) VALUES ($1, $2, $3, now()+INTERVAL '30 days', false)`, userID, deviceUUID, a.Auth.Tokens.HashToken(token))
	if err != nil {
		return "", err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	log.Printf("%d rows inserted", count)

	return token, nil
}

func (a *App) getUserIDForRefreshToken(refreshToken string) (int, error) {
	var userID int
	err := a.DB.QueryRow(`SELECT user_id FROM refresh_tokens WHERE token = $1 and not revoked and expiry_tst > now()`, a.Auth.Tokens.HashToken(refreshToken)).
		Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalidRefreshToken
	} else if err != nil {
		return 0, err
	}
	return userID, nil
}

func (a *App) RefreshAccessToken(refreshToken string) (string, error) {
	userID, err := a.getUserIDForRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}
	accessToken, err := a.Auth.Tokens.GenerateAccessToken(userID)
	if err != nil {
		return "", nil
	}
	return accessToken, nil
}

func (a *App) RevokeRefreshToken(refreshToken string) error {
	res, err := a.DB.Exec(`UPDATE refresh_tokens SET revoked = true WHERE token = $1`, a.Auth.Tokens.HashToken(refreshToken))
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	log.Printf("%d rows updated", count)
	return nil
}

func (a *App) RevokeAllRefreshTokens(refreshToken string) error {
	userID, err := a.getUserIDForRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	res, err := a.DB.Exec(`UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	log.Printf("%d rows updated", count)
	return nil
}

func (a *App) GenerateDeviceUUID() string {
	return uuid.New().String()
}

//auth methods

func (a *App) GenerateAccessToken(userID int) (string, error) {
	return a.Auth.Tokens.GenerateAccessToken(userID)
}

func (a *App) ValidateAccessToken(tokenStr string) (*auth.Claims, error) {
	return a.Auth.Tokens.ValidateAccessToken(tokenStr)
}
