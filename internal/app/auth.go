package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"db-api-test-server/internal/auth"
	"encoding/base64"
	"errors"
	"log"
	"unicode"

	"github.com/google/uuid"
)

type AuthService interface {
	AuthenticateUser(ctx context.Context, email, password string) (int, error)
	GenerateRefreshToken(ctx context.Context, userID int, deviceUUID string) (string, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (string, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	RevokeAllRefreshTokens(ctx context.Context, refreshToken string) error
	GenerateDeviceUUID() string
	CreateUser(ctx context.Context, req *CreateUserRequest) (string, error)
	GenerateAccessToken(userID int) (string, error)
	ValidateAccessToken(tokenStr string) (*auth.Claims, error)
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

func (a *App) AuthenticateUser(ctx context.Context, email, password string) (int, error) {
	var userID int
	var passwordHash string

	err := a.DB.QueryRowContext(ctx, `SELECT id, password_hash FROM users WHERE email=$1`, email).
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

func (a *App) GenerateRefreshToken(ctx context.Context, userID int, deviceUUID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	res, err := a.DB.ExecContext(ctx, `INSERT INTO refresh_tokens (user_id, device_uuid, token, expiry_tst, revoked) VALUES ($1, $2, $3, now()+INTERVAL '30 days', false)`, userID, deviceUUID, a.Auth.Tokens.HashToken(token))
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

func (a *App) getUserIDForRefreshToken(ctx context.Context, refreshToken string) (int, error) {
	var userID int
	err := a.DB.QueryRowContext(ctx, `SELECT user_id FROM refresh_tokens WHERE token = $1 and not revoked and expiry_tst > now()`, a.Auth.Tokens.HashToken(refreshToken)).
		Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalidRefreshToken
	} else if err != nil {
		return 0, err
	}
	return userID, nil
}

func (a *App) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	userID, err := a.getUserIDForRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", err
	}
	accessToken, err := a.Auth.Tokens.GenerateAccessToken(userID)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func (a *App) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	res, err := a.DB.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = true WHERE token = $1`, a.Auth.Tokens.HashToken(refreshToken))
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

func (a *App) RevokeAllRefreshTokens(ctx context.Context, refreshToken string) error {
	userID, err := a.getUserIDForRefreshToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	res, err := a.DB.ExecContext(ctx, `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`, userID)
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

func (a *App) CreateUser(ctx context.Context, req *CreateUserRequest) (string, error) {
	if err := a.validatePassword(req.Password); err != nil {
		return "", err
	}

	hash, err := a.Auth.Passwords.HashPasswordSecure(req.Password)
	if err != nil {
		return "", err
	}

	var userID int
	var publicID string
	err = a.DB.QueryRowContext(
		ctx,
		"INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, public_id",
		req.Email,
		hash,
	).Scan(&userID, &publicID)
	if err != nil {
		return "", err
	}

	return publicID, nil
}

func (a *App) validatePassword(password string) error {
	type params struct {
		number  bool
		upper   bool
		special bool
		nChars  int
	}
	var p params
	p.nChars = 0
	for _, c := range password {
		switch {
		case unicode.IsNumber(c):
			p.number = true
		case unicode.IsUpper(c):
			p.upper = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			p.special = true
		default:
		}
		p.nChars++
	}
	if !p.number || !p.upper || !p.special || p.nChars < 8 || p.nChars > 64 {
		return ErrPasswordInvalidFormat
	}
	return nil
}

//auth methods

func (a *App) GenerateAccessToken(userID int) (string, error) {
	return a.Auth.Tokens.GenerateAccessToken(userID)
}

func (a *App) ValidateAccessToken(tokenStr string) (*auth.Claims, error) {
	return a.Auth.Tokens.ValidateAccessToken(tokenStr)
}
