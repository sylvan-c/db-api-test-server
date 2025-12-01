package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
)

type UserService interface {
	GetUserByID(ctx context.Context, userID int) (*User, error)
	GetPublicIDForUser(ctx context.Context, userID int) (string, error)
	GetUserIDByPublicID(ctx context.Context, userPubID string) (int, error)
	UpdateProfile(ctx context.Context, userID int, updates map[string]any) (*User, error)
}

type User struct {
	ID        int    `json:"id"`
	PublicID  string `json:"publicID"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var ErrPasswordInvalidFormat = errors.New("password in invalid format")
var ErrInvalidID = errors.New("invalid user public id")
var ErrInvalidInput = errors.New("invalid input")
var ErrUpdateFailed = errors.New("update failed")

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

func (a *App) UpdateProfile(ctx context.Context, userID int, updates map[string]any) (*User, error) {
	if len(updates) == 0 {
		return a.GetUserByID(ctx, userID)
	}

	setClauses := []string{}
	args := []any{}
	i := 1
	var colName string
	for k, v := range updates {
		switch k {
		case "firstName":
			colName = "first_name"
		case "lastName":
			colName = "last_name"
		}

		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", colName, i))
		args = append(args, v)
		i++
	}
	if errs := a.validateUserProfile(updates); errs != nil {
		for _, e := range errs {
			log.Printf("%s: %s", e.Field, e.Message)
		}
		return nil, ErrInvalidInput
	}
	args = append(args, userID)
	query := fmt.Sprintf(`UPDATE user_details SET %s WHERE user_id = $%d RETURNING first_name, last_name`,
		strings.Join(setClauses, ", "),
		i)

	log.Print(query)

	row := a.DB.QueryRowContext(ctx, query, args...)
	var user User
	if err := row.Scan(&user.FirstName, &user.LastName); err != nil {
		return nil, ErrUpdateFailed
	}

	return a.GetUserByID(ctx, userID)
}

func (a *App) validateUserProfile(updates map[string]any) []ValidationError {
	var errs []ValidationError

	for k, v := range updates {
		switch k {
		case "firstName", "lastName":
			val, ok := v.(string)
			if !ok {
				errs = append(errs, ValidationError{
					Field:   k,
					Message: "incorrect type",
				})
			}
			if len(val) < 2 || len(val) > 50 {
				errs = append(errs, ValidationError{
					Field:   k,
					Message: "incorrect length - must be between 2 and 50 characters",
				})
			}
		}
	}

	return errs
}
