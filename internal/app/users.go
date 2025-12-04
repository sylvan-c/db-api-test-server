package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
)

type UserService interface {
	GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]any) (*User, error)
}

type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var ErrPasswordInvalidFormat = errors.New("password in invalid format")
var ErrInvalidInput = errors.New("invalid input")
var ErrUpdateFailed = errors.New("update failed")
var ErrUnmappedKey = errors.New("unmapped key")

func (a *App) GetUserByID(ctx context.Context, userID uuid.UUID) (*User, error) {
	var user User
	var firstNameNull sql.NullString
	var lastNameNull sql.NullString

	log.Printf("%s", userID.String())
	err := a.DB.QueryRowContext(
		ctx,
		`SELECT U.id, U.email, UD.first_name, UD.last_name
		FROM Users U
		LEFT JOIN User_Details UD ON U.id = UD.user_id
		WHERE U.id = $1`,
		userID,
	).Scan(&user.ID, &user.Email, &firstNameNull, &lastNameNull)
	if err != nil {
		log.Printf("GetUserByID - %s", err.Error())
		return nil, err
	}

	user.FirstName = firstNameNull.String
	if !firstNameNull.Valid {
		user.FirstName = ""
	}
	user.LastName = lastNameNull.String
	if !lastNameNull.Valid {
		user.LastName = ""
	}

	return &user, nil
}

func (a *App) UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]any) (*User, error) {
	if len(updates) == 0 {
		return a.GetUserByID(ctx, userID)
	}

	if errs := a.validateUserProfile(updates); len(errs) > 0 {
		for _, e := range errs {
			log.Printf("Validation Error: %s: %s", e.Field, e.Message)
		}
		return nil, ErrInvalidInput
	}

	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var user User
	err = tx.QueryRowContext(ctx, "SELECT id, email FROM users WHERE id = $1", userID).
		Scan(&user.ID, &user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user for update: %w", err)
	}

	setClauses := []string{}
	args := []any{}
	bindCount := 1
	var jsonColMap = map[string]string{
		"firstName": "first_name",
		"lastName":  "last_name",
	}
	for k, v := range updates {
		colName, ok := jsonColMap[k]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnmappedKey, k)
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", colName, bindCount))
		args = append(args, v)
		bindCount++
	}

	args = append(args, userID)

	updateQuery := fmt.Sprintf(`
			UPDATE user_details 
			SET %s 
			WHERE user_id = $%d 
			RETURNING first_name, last_name`,
		strings.Join(setClauses, ", "),
		bindCount)

	row := tx.QueryRowContext(ctx, updateQuery, args...)

	if err := row.Scan(&user.FirstName, &user.LastName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: user details row not found for ID %s", ErrUpdateFailed, userID)
		}
		return nil, fmt.Errorf("%w: scan failed after update: %w", ErrUpdateFailed, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return &user, nil
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
