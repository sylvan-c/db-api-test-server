package app

import (
	"context"
	"database/sql"
	"errors"
)

type UserService interface {
	GetUserByID(ctx context.Context, userID int) (*User, error)
	GetPublicIDForUser(ctx context.Context, userID int) (string, error)
	GetUserIDByPublicID(ctx context.Context, userPubID string) (int, error)
}

type User struct {
	ID        int    `json:"id"`
	PublicID  string `json:"publicID"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

var ErrPasswordInvalidFormat = errors.New("password in invalid format")
var ErrInvalidID = errors.New("invalid user public id")

func (a *App) GetUserByID(ctx context.Context, userID int) (*User, error) {
	var user User

	err := a.DB.QueryRowContext(ctx, `SELECT U.id, U.public_id, U.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = $1`, userID).
		Scan(&user.ID, &user.PublicID, &user.Email, &user.FirstName, &user.LastName)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *App) GetPublicIDForUser(ctx context.Context, userID int) (string, error) {
	var userPubID string
	err := a.DB.QueryRowContext(ctx, `SELECT public_id FROM users WHERE id = $1`, userID).
		Scan(&userPubID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidID
	} else if err != nil {
		return "", err
	}
	return userPubID, nil
}

func (a *App) GetUserIDByPublicID(ctx context.Context, userPubID string) (int, error) {
	var userID int
	err := a.DB.QueryRowContext(ctx, `SELECT id FROM users WHERE public_id = $1`, userPubID).
		Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}
