package app

import (
	"db-api-test-server/internal/auth"
	"errors"
	"unicode"
)

type User struct {
	Id        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type CreateUserRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

var ErrPasswordInvalidFormat = errors.New("password in invalid format")

func (a *App) GetUserByID(userID int) (*User, error) {
	var user User

	err := a.DB.QueryRow(`SELECT U.id, U.username, UD.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = $1`, userID).
		Scan(&user.Id, &user.Username, &user.Email, &user.FirstName, &user.LastName)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *App) ListUsers() (*[]User, error) {
	rows, err := a.DB.Query(`SELECT U.id, U.username, UD.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id`)
	if err != nil {
		return nil, err
	}

	var usersList []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.FirstName, &user.LastName); err != nil {
			return nil, err
		}
		usersList = append(usersList, user)
	}
	return &usersList, nil
}

func (a *App) CreateUser(req *CreateUserRequest) (*User, error) {
	if err := a.validatePassword(req.Password); err != nil {
		return nil, err
	}

	hash, err := auth.HashPasswordSecure(req.Password)
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
		"INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
		req.Username,
		hash,
	).Scan(&userID)
	if err != nil {
		return nil, err
	}

	var userDetailsID int
	err = a.DB.QueryRow(
		"INSERT INTO user_details (user_id, email, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING id",
		userID,
		req.Email,
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
