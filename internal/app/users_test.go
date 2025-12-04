package app

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGetUserByID(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	a := &App{DB: db}

	dummyUserUUID, _ := uuid.NewV7()

	t.Run("success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "email", "first_name", "last_name"}).
			AddRow(dummyUserUUID, "alice@mail.com", "Alice", "Smith")
		mock.ExpectQuery(`SELECT U.id, U.email, UD.first_name, UD.last_name FROM Users U LEFT JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
			WithArgs(dummyUserUUID).
			WillReturnRows(rows)

		user, err := a.GetUserByID(context.Background(), dummyUserUUID)
		assert.NoError(t, err)
		assert.Equal(t, dummyUserUUID, user.ID)
		assert.Equal(t, "Alice", user.FirstName)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT U.id, U.email, UD.first_name, UD.last_name FROM Users U LEFT JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
			WithArgs(dummyUserUUID).
			WillReturnError(sql.ErrNoRows)

		user, err := a.GetUserByID(context.Background(), dummyUserUUID)
		assert.Error(t, err)
		assert.Nil(t, user)
	})
}

func TestUpdateProfile(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	a := &App{DB: db}

	dummyUserUUID, _ := uuid.NewV7()
	t.Run("success update both names", func(t *testing.T) {
		mock.ExpectBegin()

		mock.ExpectQuery(`SELECT id, email FROM users WHERE id = \$1`).
			WithArgs(dummyUserUUID).
			WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).AddRow(dummyUserUUID, "AliceSmith@fakemail.com"))

		mock.ExpectQuery(`UPDATE user_details SET first_name = \$1, last_name = \$2 WHERE user_id = \$3 RETURNING first_name, last_name`).
			WithArgs("Alice", "Smith", dummyUserUUID).
			WillReturnRows(sqlmock.NewRows([]string{"first_name", "last_name"}).AddRow("Alice", "Smith"))

		mock.ExpectCommit()

		user, err := a.UpdateProfile(context.Background(), dummyUserUUID, map[string]any{"firstName": "Alice", "lastName": "Smith"})
		assert.NoError(t, err)
		assert.Equal(t, "Alice", user.FirstName)
		assert.Equal(t, "Smith", user.LastName)
	})

	t.Run("update failed - scan error", func(t *testing.T) {
		mock.ExpectBegin()

		mock.ExpectQuery(`SELECT id, email FROM users WHERE id = \$1`).
			WithArgs(dummyUserUUID).
			WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).AddRow(dummyUserUUID, "AliceSmith@fakemail.com"))

		mock.ExpectQuery(`UPDATE user_details SET first_name = \$1 WHERE user_id = \$2 RETURNING first_name, last_name`).
			WithArgs("Alice", dummyUserUUID).
			WillReturnError(errors.New("scan error"))

		_, err := a.UpdateProfile(context.Background(), dummyUserUUID, map[string]any{"firstName": "Alice"})
		assert.ErrorIs(t, err, ErrUpdateFailed)
	})

	t.Run("input validation", func(t *testing.T) {
		validationTests := []struct {
			name      string
			input     map[string]any
			wantError error
			mockGet   bool // whether GetUserByID will be called (empty map)
		}{
			{"first name too short", map[string]any{"firstName": "A"}, ErrInvalidInput, false},
			{"last name too long", map[string]any{"lastName": string(make([]byte, 51))}, ErrInvalidInput, false},
			{"wrong type for first name", map[string]any{"firstName": 123}, ErrInvalidInput, false},
			{"multiple errors", map[string]any{"firstName": "A", "lastName": 123}, ErrInvalidInput, false},
			{"empty map", map[string]any{}, nil, true},
		}

		for _, tt := range validationTests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.mockGet {
					mock.ExpectQuery(`SELECT U.id, U.email, UD.first_name, UD.last_name FROM Users U LEFT JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
						WithArgs(dummyUserUUID).
						WillReturnRows(sqlmock.NewRows([]string{"id", "email", "first_name", "last_name"}).
							AddRow(dummyUserUUID, "alice@mail.com", "Alice", "Smith"))
				}

				user, err := a.UpdateProfile(context.Background(), dummyUserUUID, tt.input)
				if tt.wantError != nil {
					assert.ErrorIs(t, err, tt.wantError)
					assert.Nil(t, user)
				} else {
					assert.NoError(t, err)
					assert.NotNil(t, user)
					assert.Equal(t, "Alice", user.FirstName)
					assert.Equal(t, "Smith", user.LastName)
				}
			})
		}
	})
}
