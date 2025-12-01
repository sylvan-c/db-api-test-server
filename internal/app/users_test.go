package app

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestGetUserByID(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	a := &App{DB: db}

	t.Run("success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "public_id", "email", "first_name", "last_name"}).
			AddRow(1, "pub-1", "alice@mail.com", "Alice", "Smith")
		mock.ExpectQuery(`SELECT U.id, U.public_id, U.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
			WithArgs(1).
			WillReturnRows(rows)

		user, err := a.GetUserByID(context.Background(), 1)
		assert.NoError(t, err)
		assert.Equal(t, 1, user.ID)
		assert.Equal(t, "Alice", user.FirstName)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT U.id, U.public_id, U.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
			WithArgs(2).
			WillReturnError(sql.ErrNoRows)

		user, err := a.GetUserByID(context.Background(), 2)
		assert.Error(t, err)
		assert.Nil(t, user)
	})
}

func TestGetPublicIDForUser(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	a := &App{DB: db}

	t.Run("success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"public_id"}).AddRow("pub-1")
		mock.ExpectQuery(`SELECT public_id FROM users WHERE id = \$1`).WithArgs(1).WillReturnRows(rows)

		pubID, err := a.GetPublicIDForUser(context.Background(), 1)
		assert.NoError(t, err)
		assert.Equal(t, "pub-1", pubID)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT public_id FROM users WHERE id = \$1`).WithArgs(2).WillReturnError(sql.ErrNoRows)

		pubID, err := a.GetPublicIDForUser(context.Background(), 2)
		assert.ErrorIs(t, err, ErrInvalidID)
		assert.Equal(t, "", pubID)
	})
}

func TestGetUserIDByPublicID(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	a := &App{DB: db}

	t.Run("success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id"}).AddRow(42)
		mock.ExpectQuery(`SELECT id FROM users WHERE public_id = \$1`).WithArgs("pub-1").WillReturnRows(rows)

		id, err := a.GetUserIDByPublicID(context.Background(), "pub-1")
		assert.NoError(t, err)
		assert.Equal(t, 42, id)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id FROM users WHERE public_id = \$1`).WithArgs("bad-pub").WillReturnError(sql.ErrNoRows)

		id, err := a.GetUserIDByPublicID(context.Background(), "bad-pub")
		assert.Error(t, err)
		assert.Equal(t, 0, id)
	})
}

func TestUpdateProfile(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	a := &App{DB: db}

	t.Run("success update both names", func(t *testing.T) {
		mock.ExpectQuery(`UPDATE user_details SET first_name = \$1, last_name = \$2 WHERE user_id = \$3 RETURNING first_name, last_name`).
			WithArgs("Alice", "Smith", 1).
			WillReturnRows(sqlmock.NewRows([]string{"first_name", "last_name"}).AddRow("Alice", "Smith"))

		mock.ExpectQuery(`SELECT U.id, U.public_id, U.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
			WithArgs(1).
			WillReturnRows(sqlmock.NewRows([]string{"id", "public_id", "email", "first_name", "last_name"}).
				AddRow(1, "pub-1", "alice@mail.com", "Alice", "Smith"))

		user, err := a.UpdateProfile(context.Background(), 1, map[string]any{"firstName": "Alice", "lastName": "Smith"})
		assert.NoError(t, err)
		assert.Equal(t, "Alice", user.FirstName)
		assert.Equal(t, "Smith", user.LastName)
	})

	t.Run("update failed - scan error", func(t *testing.T) {
		mock.ExpectQuery(`UPDATE user_details SET first_name = \$1 WHERE user_id = \$2 RETURNING first_name, last_name`).
			WithArgs("Alice", 1).
			WillReturnError(errors.New("scan error"))

		_, err := a.UpdateProfile(context.Background(), 1, map[string]any{"firstName": "Alice"})
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
					mock.ExpectQuery(`SELECT U.id, U.public_id, U.email, UD.first_name, UD.last_name FROM Users U JOIN User_Details UD ON U.id = UD.user_id WHERE U.id = \$1`).
						WithArgs(1).
						WillReturnRows(sqlmock.NewRows([]string{"id", "public_id", "email", "first_name", "last_name"}).
							AddRow(1, "pub-1", "alice@mail.com", "Alice", "Smith"))
				}

				user, err := a.UpdateProfile(context.Background(), 1, tt.input)
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
