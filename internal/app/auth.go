package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"db-api-test-server/internal/auth"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"unicode"

	"github.com/google/uuid"
)

type AuthService interface {
	AuthenticateUser(ctx context.Context, email, password string) (uuid.UUID, error)
	GenerateRefreshToken(ctx context.Context, userID uuid.UUID, deviceUUID uuid.UUID) (string, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (map[string]string, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	RevokeAllRefreshTokens(ctx context.Context, refreshToken string) error
	CreateUser(ctx context.Context, req *CreateUserRequest) (uuid.UUID, error)
	GenerateAccessToken(userID uuid.UUID, deviceUUID uuid.UUID) (string, error)
	ValidateAccessToken(tokenStr string) (*auth.Claims, error)
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")
var ErrInvalidPasswordFormat = errors.New("invalid password format")

func (a *App) AuthenticateUser(ctx context.Context, email, password string) (uuid.UUID, error) {
	var userID uuid.UUID
	var passwordHash string

	err := a.DB.QueryRowContext(ctx, `SELECT id, password_hash FROM users WHERE email=$1`, email).
		Scan(&userID, &passwordHash)

	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, ErrInvalidCredentials
	} else if err != nil {
		return uuid.Nil, err
	}

	if err := a.Auth.Passwords.AuthenticateUser(passwordHash, password); err != nil {
		return uuid.Nil, ErrInvalidCredentials
	}

	return userID, nil
}

func (a *App) GenerateRefreshToken(ctx context.Context, userID uuid.UUID, deviceUUID uuid.UUID) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)

	rTokenID, err := uuid.NewV7()
	if err != nil {
		log.Printf("app.GenerateRefreshToken > uuid.NewV7: %s", err.Error())
		return "", err
	}
	res, err := a.DB.ExecContext(ctx, `INSERT INTO refresh_tokens (id, user_id, device_uuid, token, expiry_tst, revoked) VALUES ($1, $2, $3, $4, now()+INTERVAL '30 days', false)`, rTokenID, userID, deviceUUID, a.Auth.Tokens.HashToken(token))
	if err != nil {
		log.Printf("app.GenerateRefreshToken > a.DB.ExecContext: %s", err.Error())
		return "", err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	log.Printf("%d rows inserted", count)

	return token, nil
}

func (a *App) getRefreshTokenDetails(ctx context.Context, refreshToken string) (uuid.UUID, uuid.UUID, error) {
	var userID uuid.UUID
	var deviceUUID uuid.UUID
	err := a.DB.QueryRowContext(ctx, `SELECT user_id, device_uuid FROM refresh_tokens WHERE token = $1 and not revoked and expiry_tst > now()`, a.Auth.Tokens.HashToken(refreshToken)).
		Scan(&userID, &deviceUUID)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrInvalidRefreshToken
	} else if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, deviceUUID, nil
}

func (a *App) RefreshAccessToken(ctx context.Context, refreshToken string) (map[string]string, error) {
	userID, deviceUUID, err := a.getRefreshTokenDetails(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	accessToken, err := a.Auth.Tokens.GenerateAccessToken(userID, deviceUUID)
	if err != nil {
		return nil, err
	}
	if err := a.RevokeRefreshToken(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	newRefreshToken, err := a.GenerateRefreshToken(ctx, userID, deviceUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	tokenStruct := map[string]string{
		"accessToken":  accessToken,
		"refreshToken": newRefreshToken,
	}
	return tokenStruct, nil
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
	userID, _, err := a.getRefreshTokenDetails(ctx, refreshToken)
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

func (a *App) CreateUser(ctx context.Context, req *CreateUserRequest) (uuid.UUID, error) {
	isValid, err := a.validatePassword(req.Password)
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not validate password: %w", err)
	}
	if !isValid {
		return uuid.Nil, ErrInvalidPasswordFormat
	}

	hash, err := a.Auth.Passwords.HashPasswordSecure(req.Password)
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not hash password: %w", err)
	}

	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not begin transaction: %w", err)
	}

	defer tx.Rollback()

	userID, err := uuid.NewV7()
	if err != nil {
		log.Printf("app.CreateUser > uuid.NewV7: %s", err.Error())
		return uuid.Nil, err
	}

	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
		userID,
		req.Email,
		hash,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert user failed: %w", err)
	}

	userDetailsID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("uuid generation failed: %w", err)
	}

	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO user_details (id, user_id) VALUES ($1, $2)",
		userDetailsID,
		userID,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert user details failed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("could not commit transaction: %w", err)
	}

	return userID, nil
}

func (a *App) validatePassword(password string) (bool, error) {
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
		return false, ErrPasswordInvalidFormat
	}
	return true, nil
}

//auth methods

func (a *App) GenerateAccessToken(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) {
	return a.Auth.Tokens.GenerateAccessToken(userID, deviceUUID)
}

func (a *App) ValidateAccessToken(tokenStr string) (*auth.Claims, error) {
	return a.Auth.Tokens.ValidateAccessToken(tokenStr)
}
