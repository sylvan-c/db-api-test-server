package handlers

import (
	"context"
	"db-api-test-server/internal/app"
	"db-api-test-server/internal/auth"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockAuthService struct {
	AuthenticateUserFunc       func(ctx context.Context, email, password string) (int, error)
	GenerateRefreshTokenFunc   func(ctx context.Context, userID int, deviceUUID string) (string, error)
	RefreshAccessTokenFunc     func(ctx context.Context, refreshToken string) (string, error)
	RevokeRefreshTokenFunc     func(ctx context.Context, refreshToken string) error
	RevokeAllRefreshTokensFunc func(ctx context.Context, refreshToken string) error
	GenerateDeviceUUIDFunc     func() string
	GenerateAccessTokenFunc    func(userID int) (string, error)
	ValidateAccessTokenFunc    func(tokenStr string) (*auth.Claims, error)
}

func (a *mockAuthService) AuthenticateUser(ctx context.Context, email, password string) (int, error) {
	return a.AuthenticateUserFunc(ctx, email, password)
}

func (a *mockAuthService) GenerateRefreshToken(ctx context.Context, userID int, deviceUUID string) (string, error) {
	return a.GenerateRefreshTokenFunc(ctx, userID, deviceUUID)
}

func (a *mockAuthService) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	return a.RefreshAccessTokenFunc(ctx, refreshToken)
}

func (a *mockAuthService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	return a.RevokeRefreshTokenFunc(ctx, refreshToken)
}

func (a *mockAuthService) RevokeAllRefreshTokens(ctx context.Context, refreshToken string) error {
	return a.RevokeAllRefreshTokensFunc(ctx, refreshToken)
}

func (a *mockAuthService) GenerateDeviceUUID() string {
	return a.GenerateDeviceUUIDFunc()
}

func (a *mockAuthService) GenerateAccessToken(userID int) (string, error) {
	return a.GenerateAccessTokenFunc(userID)
}

func (a *mockAuthService) ValidateAccessToken(tokenStr string) (*auth.Claims, error) {
	return a.ValidateAccessTokenFunc(tokenStr)
}

func TestLoginHandler(t *testing.T) {
	tests := []struct {
		name                    string
		body                    string
		uuid                    string
		userID                  int
		accessToken             string
		refreshToken            string
		authenticateUserErr     error
		generateAccessTokenErr  error
		generateRefreshTokenErr error
		expectedStatus          int
	}{
		// pass
		{
			name:           "pass with uuid",
			body:           `{"email":"valid-user@mail.com","password":"valid-password","deviceUUID":"input-uuid"}`,
			uuid:           "generated-uuid",
			userID:         1,
			accessToken:    "valid-access-token",
			refreshToken:   "valid-refresh-token",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "pass without uuid",
			body:           `{"email":"valid-user@mail.com","password":"valid-password"}`,
			uuid:           "generated-uuid",
			userID:         1,
			accessToken:    "valid-access-token",
			refreshToken:   "valid-refresh-token",
			expectedStatus: http.StatusOK,
		},
		// fail
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing password",
			body:           `{"email":"valid-user@mail.com"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing email",
			body:           `{"password":"password"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:                "invalid creds",
			body:                `{"email":"invalid-user@mail.com","password":"invalid-password"}`,
			userID:              0,
			authenticateUserErr: app.ErrInvalidCredentials,
			expectedStatus:      http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		uuidFuncCalled := false
		usedUUID := ""
		returnedUserID := 0
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := &mockAuthService{
				GenerateDeviceUUIDFunc: func() string {
					uuidFuncCalled = true
					return tt.uuid
				},
				AuthenticateUserFunc: func(ctx context.Context, email, password string) (int, error) {
					returnedUserID = tt.userID
					return tt.userID, tt.authenticateUserErr
				},
				GenerateAccessTokenFunc: func(userID int) (string, error) {
					return tt.accessToken, tt.generateAccessTokenErr
				},
				GenerateRefreshTokenFunc: func(ctx context.Context, userID int, deviceUUID string) (string, error) {
					if deviceUUID != "" {
						usedUUID = deviceUUID
					}
					return tt.refreshToken, tt.generateRefreshTokenErr
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h := NewAuthHandler(mockSvc)
			h.Login(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)

			var body map[string]string
			if w.Code == 200 {
				err := json.Unmarshal(bodyBytes, &body)
				assert.NoError(t, err)
			}

			if tt.name == "pass with uuid" {
				assert.False(t, uuidFuncCalled, "GenerateDeviceUUID should not be called when request includes UUID")
				assert.Equal(t, "input-uuid", usedUUID, "handler should use input UUID")
				assert.Equal(t, 1, returnedUserID, "returned user id should be 1")
				assert.Equal(t, "valid-access-token", body["accessToken"], "returned access token should be valid-access-token")
				assert.Equal(t, "valid-refresh-token", body["refreshToken"], "returned refresh token should be valid-refresh-token")
			}
			if tt.name == "pass without uuid" {
				assert.True(t, uuidFuncCalled, "GenerateDeviceUUID should be called when request does not include UUID")
				assert.Equal(t, "generated-uuid", usedUUID, "handler should use generated UUID")
				assert.Equal(t, 1, returnedUserID, "returned user id should be 1")
				assert.Equal(t, "valid-access-token", body["accessToken"], "returned access token should be valid-access-token")
				assert.Equal(t, "valid-refresh-token", body["refreshToken"], "returned refresh token should be valid-refresh-token")
			}
			if tt.name == "invalid creds" {
				assert.Equal(t, 0, returnedUserID, "returned user id should be 0")
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestRefreshAccessTokenHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		token          string
		err            error
		expectedStatus int
	}{
		// pass
		{
			name:           "pass",
			body:           `{"refreshToken":"valid-token"}`,
			token:          "new-token",
			err:            nil,
			expectedStatus: http.StatusOK,
		},
		// fail
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing refresh token",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "service error",
			body:           `{"refreshToken":"bad-token"}`,
			err:            fmt.Errorf("failed to generate token"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := &mockAuthService{
				RefreshAccessTokenFunc: func(ctx context.Context, token string) (string, error) {
					return tt.token, tt.err
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/logout", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h := NewAuthHandler(mockSvc)
			h.RefreshAccessToken(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)

			var body map[string]string
			if w.Code == 200 {
				err := json.Unmarshal(bodyBytes, &body)
				assert.NoError(t, err)
			}

			if tt.name == "pass" {
				assert.Equal(t, "new-token", body["accessToken"])
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestLogoutHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		err            error
		expectedStatus int
	}{
		// pass
		{
			name:           "pass",
			body:           `{"refreshToken":"valid-token"}`,
			err:            nil,
			expectedStatus: http.StatusOK,
		},
		// fail
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing refresh token",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "service error",
			body:           `{"refreshToken":"bad-token"}`,
			err:            fmt.Errorf("failed to revoke refresh token"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := &mockAuthService{
				RevokeRefreshTokenFunc: func(ctx context.Context, token string) error {
					return tt.err
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/logout", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h := NewAuthHandler(mockSvc)
			h.LogOut(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestLogoutAllHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		err            error
		expectedStatus int
	}{
		// pass
		{
			name:           "pass",
			body:           `{"refreshToken":"valid-token"}`,
			err:            nil,
			expectedStatus: http.StatusOK,
		},
		// fail
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing refresh token",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "service error",
			body:           `{"refreshToken":"bad-token"}`,
			err:            fmt.Errorf("failed to revoke refresh token"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := &mockAuthService{
				RevokeAllRefreshTokensFunc: func(ctx context.Context, token string) error {
					return tt.err
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/logout/all", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			h := NewAuthHandler(mockSvc)
			h.LogOutAll(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
