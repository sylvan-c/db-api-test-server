package app

import (
	"database/sql"
	"errors"
	"unicode"
)

type UserService interface {
	GetUserByID(userID int) (*User, error)
	CreateUser(req *CreateUserRequest) (*User, error)
	GetPublicIDForUser(userID int) (string, error)
	GetUserIDByPublicID(userPubID string) (int, error)
}

type User struct {
	ID        int    `json:"id"`
	PublicID  string `json:"publicID"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type CreateUserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

var ErrPasswordInvalidFormat = errors.New("password in invalid format")
var ErrInvalidID = errors.New("invalid user public id")

func (a *App) GetUserByID(userID int) (*User, error) {
	var user User

	err := a.DB.QueryRow(`SELECT U.id, U.public_id, U.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = $1`, userID).
		Scan(&user.ID, &user.PublicID, &user.Email, &user.FirstName, &user.LastName)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *App) CreateUser(req *CreateUserRequest) (*User, error) {
	if err := a.validatePassword(req.Password); err != nil {
		return nil, err
	}

	hash, err := a.Auth.Passwords.HashPasswordSecure(req.Password)
	if err != nil {
		return nil, err
	}

	tx, err := a.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var userID int
	err = a.DB.QueryRow(
		"INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
		req.Email,
		hash,
	).Scan(&userID)
	if err != nil {
		return nil, err
	}

	var userDetailsID int
	err = a.DB.QueryRow(
		"INSERT INTO user_details (user_id, first_name, last_name) VALUES ($1, $2, $3) RETURNING id",
		userID,
		req.FirstName,
		req.LastName,
	).Scan(&userDetailsID)
	if err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return a.GetUserByID(userID)
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

func (a *App) GetPublicIDForUser(userID int) (string, error) {
	var userPubID string
	err := a.DB.QueryRow(`SELECT public_id FROM users WHERE id = $1`, userID).
		Scan(&userPubID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInvalidID
	} else if err != nil {
		return "", err
	}
	return userPubID, nil
}

func (a *App) GetUserIDByPublicID(userPubID string) (int, error) {
	var userID int
	err := a.DB.QueryRow(`SELECT id FROM users WHERE public_id = $1`, userPubID).
		Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}
