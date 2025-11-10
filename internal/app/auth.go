package app

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"db-api-test-server/internal/auth"
	"encoding/base64"
	"errors"
	"log"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

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

func (a *App) hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(sum[:])
}

func (a *App) GenerateRefreshToken(userID int) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	tx, err := a.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var refreshTokenID int
	err = a.DB.QueryRow(`INSERT INTO refresh_tokens (user_id, token, expiry_tst, revoked) VALUES ($1, $2, now()+INTERVAL '30 days', false) RETURNING id`, userID, a.hashToken(token)).
		Scan(&refreshTokenID)
	if err != nil {
		return "", err
	}

	res, err := a.DB.Exec(`UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 and id != $2`, userID, refreshTokenID)
	if err != nil {
		return "", err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	log.Printf("%d rows updated", count)

	err = tx.Commit()
	if err != nil {
		return "", err
	}

	return token, nil
}

func (a *App) getUserIDForRefreshToken(refreshToken string) (int, error) {
	var userID int
	err := a.DB.QueryRow(`SELECT user_id FROM refresh_tokens WHERE token = $1 and not revoked and expiry_tst > now()`, a.hashToken(refreshToken)).
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
	accessToken, err := a.Auth.GenerateAccessToken(userID)
	if err != nil {
		return "", nil
	}
	return accessToken, nil
}

func (a *App) RevokeRefreshToken(refreshToken string) error {
	res, err := a.DB.Exec(`UPDATE refresh_tokens SET revoked = true WHERE token = $1`, a.hashToken(refreshToken))
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
