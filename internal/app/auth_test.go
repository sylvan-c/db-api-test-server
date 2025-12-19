package app

import (
	"context"
	"database/sql"
	"db-api-test-server/internal/auth"
	"errors"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// ------------------- Mock Implementations -------------------

type mockPasswords struct {
	AuthenticateUserFunc   func(hash, password string) error
	HashPasswordSecureFunc func(password string) (string, error)
}

func (m *mockPasswords) AuthenticateUser(hash, password string) error {
	if m.AuthenticateUserFunc != nil {
		return m.AuthenticateUserFunc(hash, password)
	}
	return nil
}

func (m *mockPasswords) HashPasswordSecure(password string) (string, error) {
	if m.HashPasswordSecureFunc != nil {
		return m.HashPasswordSecureFunc(password)
	}
	return password, nil
}

type mockTokens struct {
	HashTokenFunc           func(token string) string
	GenerateAccessTokenFunc func(userID uuid.UUID, deviceUUID uuid.UUID) (string, error)
	ValidateAccessTokenFunc func(token string) (*auth.Claims, error)
}

func (m *mockTokens) HashToken(token string) string {
	if m.HashTokenFunc != nil {
		return m.HashTokenFunc(token)
	}
	return token
}

func (m *mockTokens) GenerateAccessToken(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) {
	if m.GenerateAccessTokenFunc != nil {
		return m.GenerateAccessTokenFunc(userID, deviceUUID)
	}
	return "access-token", nil
}

func (m *mockTokens) ValidateAccessToken(token string) (*auth.Claims, error) {
	if m.ValidateAccessTokenFunc != nil {
		return m.ValidateAccessTokenFunc(token)
	}
	dummyUserUUID, _ := uuid.NewV7()
	return &auth.Claims{UserID: dummyUserUUID}, nil
}

// ------------------- Tests -------------------

func TestAuthenticateUser(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	dummyUserUUID, _ := uuid.NewV7()

	authMock := &auth.AuthAdapter{
		Passwords: &mockPasswords{
			AuthenticateUserFunc: func(storedHash, password string) error {
				if password == "correct" {
					return nil
				}
				return errors.New("bad password")
			},
			HashPasswordSecureFunc: func(p string) (string, error) { return "hashed-" + p, nil },
		},
		Tokens: &mockTokens{
			HashTokenFunc:           func(token string) string { return token },
			GenerateAccessTokenFunc: func(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) { return "token", nil },
			ValidateAccessTokenFunc: func(token string) (*auth.Claims, error) {
				return &auth.Claims{UserID: dummyUserUUID}, nil
			},
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "password_hash"}).AddRow(dummyUserUUID.String(), "hash")
		mock.ExpectQuery(`SELECT id, password_hash FROM users WHERE email=\$1`).WithArgs("a@mail.com").WillReturnRows(rows)

		userID, err := a.AuthenticateUser(context.Background(), "a@mail.com", "correct")
		assert.NoError(t, err)
		assert.Equal(t, dummyUserUUID, userID)
	})

	t.Run("wrong password", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "password_hash"}).AddRow(dummyUserUUID.String(), "hash")
		mock.ExpectQuery(`SELECT id, password_hash FROM users WHERE email=\$1`).WithArgs("a@mail.com").WillReturnRows(rows)

		_, err := a.AuthenticateUser(context.Background(), "a@mail.com", "wrong")
		assert.ErrorIs(t, err, ErrInvalidCredentials)
	})

	t.Run("user not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id, password_hash FROM users WHERE email=\$1`).WithArgs("a@mail.com").WillReturnError(sql.ErrNoRows)

		_, err := a.AuthenticateUser(context.Background(), "a@mail.com", "anything")
		assert.ErrorIs(t, err, ErrInvalidCredentials)
	})

	t.Run("db error", func(t *testing.T) {
		mock.ExpectQuery(`SELECT id, password_hash FROM users WHERE email=\$1`).WithArgs("a@mail.com").WillReturnError(errors.New("db fail"))

		_, err := a.AuthenticateUser(context.Background(), "a@mail.com", "correct")
		assert.Error(t, err)
		assert.EqualError(t, err, "db fail")
	})
}

func TestGenerateRefreshToken(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	dummyUserUUID, _ := uuid.NewV7()
	dummyDeviceUuid, _ := uuid.NewV7()

	authMock := &auth.AuthAdapter{
		Tokens: &mockTokens{
			HashTokenFunc: func(token string) string { return "hashed-" + token },
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO refresh_tokens .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		token, err := a.GenerateRefreshToken(context.Background(), dummyUserUUID, dummyDeviceUuid)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("exec fails", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO refresh_tokens .*`).WillReturnError(errors.New("db error"))
		_, err := a.GenerateRefreshToken(context.Background(), dummyUserUUID, dummyDeviceUuid)
		assert.Error(t, err)
	})
}

func TestGetRefreshTokenDetails(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	dummyUserUUID, _ := uuid.NewV7()
	dummyDeviceUUID, _ := uuid.NewV7()

	authMock := &auth.AuthAdapter{
		Tokens: &mockTokens{
			HashTokenFunc: func(token string) string { return token },
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"user_id", "device_uuid"}).AddRow(dummyUserUUID, dummyDeviceUUID)
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnRows(rows)

		id, deviceUUID, err := a.getRefreshTokenDetails(context.Background(), "rtoken")
		assert.NoError(t, err)
		assert.Equal(t, dummyUserUUID, id)
		assert.Equal(t, dummyDeviceUUID, deviceUUID)
	})

	t.Run("not found", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("badtoken").WillReturnError(sql.ErrNoRows)

		_, _, err := a.getRefreshTokenDetails(context.Background(), "badtoken")
		assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	})

	t.Run("db error", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnError(errors.New("db fail"))

		_, _, err := a.getRefreshTokenDetails(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "db fail")
	})
}

func TestRefreshAccessToken(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	dummyUserUUID, _ := uuid.NewV7()
	dummyDeviceUUID, _ := uuid.NewV7()

	authMock := &auth.AuthAdapter{
		Tokens: &mockTokens{
			HashTokenFunc:           func(token string) string { return token },
			GenerateAccessTokenFunc: func(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) { return "new-access", nil },
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnRows(sqlmock.NewRows([]string{"user_id", "device_uuid"}).AddRow(dummyUserUUID, dummyDeviceUUID))
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE token`).WithArgs("rtoken").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`INSERT INTO refresh_tokens .*`).WillReturnResult(sqlmock.NewResult(1, 1))
		token, err := a.RefreshAccessToken(context.Background(), "rtoken")
		assert.NoError(t, err)
		assert.Equal(t, "new-access", token["accessToken"])
		assert.IsType(t, map[string]string{}, token)
	})

	t.Run("get user id fails", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnError(errors.New("db error"))
		_, err := a.RefreshAccessToken(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "db error")
	})

	t.Run("token generation fails", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnRows(sqlmock.NewRows([]string{"user_id", "device_uuid"}).AddRow(dummyUserUUID, dummyDeviceUUID))
		authMock.Tokens = &mockTokens{GenerateAccessTokenFunc: func(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) { return "", errors.New("token error") }}
		_, err := a.RefreshAccessToken(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "token error")
	})
}

func TestRevokeRefreshToken(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	authMock := &auth.AuthAdapter{
		Tokens: &mockTokens{
			HashTokenFunc: func(token string) string { return token },
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE token`).WithArgs("rtoken").WillReturnResult(sqlmock.NewResult(0, 1))
		err := a.RevokeRefreshToken(context.Background(), "rtoken")
		assert.NoError(t, err)
	})

	t.Run("exec fails", func(t *testing.T) {
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE token`).WithArgs("rtoken").WillReturnError(errors.New("exec error"))
		err := a.RevokeRefreshToken(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "exec error")
	})

	t.Run("rows affected fails", func(t *testing.T) {
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE token`).WithArgs("rtoken").
			WillReturnResult(sqlmock.NewErrorResult(errors.New("rows affected error")))
		err := a.RevokeRefreshToken(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "rows affected error")
	})
}

func TestRevokeAllRefreshTokens(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	dummyUserUUID, _ := uuid.NewV7()

	authMock := &auth.AuthAdapter{
		Tokens: &mockTokens{
			HashTokenFunc: func(token string) string { return token },
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnRows(sqlmock.NewRows([]string{"user_id", "device_uuid"}).AddRow(dummyUserUUID, uuid.Nil))
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE user_id`).WithArgs(dummyUserUUID).WillReturnResult(sqlmock.NewResult(0, 3))
		err := a.RevokeAllRefreshTokens(context.Background(), "rtoken")
		assert.NoError(t, err)
	})

	t.Run("get user id fails", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnError(errors.New("db query error"))
		err := a.RevokeAllRefreshTokens(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "db query error")
	})

	t.Run("exec fails", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnRows(sqlmock.NewRows([]string{"user_id", "device_uuid"}).AddRow(dummyUserUUID, uuid.Nil))
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE user_id`).WithArgs(dummyUserUUID).WillReturnError(errors.New("exec error"))
		err := a.RevokeAllRefreshTokens(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "exec error")
	})

	t.Run("rows affected fails", func(t *testing.T) {
		mock.ExpectQuery(`SELECT user_id, device_uuid FROM refresh_tokens .*`).WithArgs("rtoken").WillReturnRows(sqlmock.NewRows([]string{"user_id", "device_uuid"}).AddRow(dummyUserUUID, uuid.Nil))
		mock.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE user_id`).WithArgs(dummyUserUUID).
			WillReturnResult(sqlmock.NewErrorResult(errors.New("rows affected error")))
		err := a.RevokeAllRefreshTokens(context.Background(), "rtoken")
		assert.Error(t, err)
		assert.EqualError(t, err, "rows affected error")
	})
}

func TestCreateUser(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	authMock := &auth.AuthAdapter{
		Passwords: &mockPasswords{
			HashPasswordSecureFunc: func(p string) (string, error) { return "hashed-" + p, nil },
		},
	}

	a := &App{
		DB:   db,
		Auth: authMock,
	}

	t.Run("success", func(t *testing.T) {
		mock.ExpectBegin()

		mock.ExpectExec("INSERT INTO users").
			WithArgs(sqlmock.AnyArg(), "a@mail.com", "hashed-Abc123!@").
			WillReturnResult(sqlmock.NewResult(1, 1))

		mock.ExpectExec("INSERT INTO user_details").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		mock.ExpectCommit()

		userID, err := a.CreateUser(context.Background(), &CreateUserRequest{Email: "a@mail.com", Password: "Abc123!@"})

		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, userID)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("invalid password", func(t *testing.T) {
		_, err := a.CreateUser(context.Background(), &CreateUserRequest{Email: "a@mail.com", Password: "short"})
		assert.Error(t, err)
		assert.Equal(t, fmt.Errorf("could not validate password: %w", ErrPasswordInvalidFormat), err)
	})

	t.Run("hashing fails", func(t *testing.T) {
		a.Auth.Passwords = &mockPasswords{HashPasswordSecureFunc: func(p string) (string, error) {
			return "", errors.New("hash error")
		}}
		_, err := a.CreateUser(context.Background(), &CreateUserRequest{Email: "a@mail.com", Password: "Abc123!@"})
		assert.Error(t, err)
		assert.EqualError(t, err, fmt.Sprintf("could not hash password: %s", "hash error"))
	})

	t.Run("db insert fails", func(t *testing.T) {
		a.Auth.Passwords = &mockPasswords{HashPasswordSecureFunc: func(p string) (string, error) {
			return "hashed-Abc123!@", nil
		}}

		mock.ExpectBegin()

		mock.ExpectExec("INSERT INTO users").
			WithArgs(sqlmock.AnyArg(), "a@mail.com", "hashed-Abc123!@").
			WillReturnError(errors.New("db insert error"))

		_, err := a.CreateUser(context.Background(), &CreateUserRequest{Email: "a@mail.com", Password: "Abc123!@"})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "insert user failed: db insert error")
	})
}

func TestValidatePassword(t *testing.T) {
	a := &App{}

	tests := []struct {
		password  string
		wantError bool
	}{
		{"Abc123!@", false},
		{"abc123!@", true},  // missing uppercase
		{"Abcdef!@", true},  // missing number
		{"Abc123456", true}, // missing special
		{"A1!", true},       // too short
	}

	for _, tt := range tests {
		isValid, err := a.validatePassword(tt.password)
		assert.Equal(t, tt.wantError, !isValid)
		if tt.wantError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestAccessTokenMethods(t *testing.T) {
	dummyUserUUID, _ := uuid.NewV7()
	dummyDeviceUUID, _ := uuid.NewV7()
	authMock := &auth.AuthAdapter{
		Tokens: &mockTokens{
			GenerateAccessTokenFunc: func(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) { return "token", nil },
			ValidateAccessTokenFunc: func(token string) (*auth.Claims, error) { return &auth.Claims{UserID: dummyUserUUID}, nil },
		},
	}

	a := &App{
		Auth: authMock,
	}

	t.Run("GenerateAccessToken success", func(t *testing.T) {
		token, err := a.GenerateAccessToken(dummyUserUUID, dummyDeviceUUID)
		assert.NoError(t, err)
		assert.Equal(t, "token", token)
	})

	t.Run("ValidateAccessToken success", func(t *testing.T) {
		claims, err := a.ValidateAccessToken("token")
		assert.NoError(t, err)
		assert.Equal(t, dummyUserUUID, claims.UserID)
	})

	t.Run("GenerateAccessToken error", func(t *testing.T) {
		a.Auth.Tokens = &mockTokens{GenerateAccessTokenFunc: func(userID uuid.UUID, deviceUUID uuid.UUID) (string, error) { return "", errors.New("generate error") }}
		_, err := a.GenerateAccessToken(dummyUserUUID, dummyDeviceUUID)
		assert.Error(t, err)
		assert.EqualError(t, err, "generate error")
	})

	t.Run("ValidateAccessToken error", func(t *testing.T) {
		a.Auth.Tokens = &mockTokens{ValidateAccessTokenFunc: func(token string) (*auth.Claims, error) { return nil, errors.New("validate error") }}
		_, err := a.ValidateAccessToken("token")
		assert.Error(t, err)
		assert.EqualError(t, err, "validate error")
	})
}
