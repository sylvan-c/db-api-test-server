package handlers

import (
	"context"
	"db-api-test-server/internal/app"
	"db-api-test-server/internal/auth"
	"encoding/json"
	"errors"
	"fmt"
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
	CreateUserFunc             func(ctx context.Context, req *app.CreateUserRequest) (string, error)
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
	if a.GenerateDeviceUUIDFunc == nil {
		return "default-uuid"
	}
	return a.GenerateDeviceUUIDFunc()
}

func (a *mockAuthService) CreateUser(ctx context.Context, req *app.CreateUserRequest) (string, error) {
	return a.CreateUserFunc(ctx, req)
}

func (a *mockAuthService) GenerateAccessToken(userID int) (string, error) {
	return a.GenerateAccessTokenFunc(userID)
}

func (a *mockAuthService) ValidateAccessToken(tokenStr string) (*auth.Claims, error) {
	return a.ValidateAccessTokenFunc(tokenStr)
}

// ------------------- Login Tests -------------------

func TestLoginHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		mockSetup      func() *mockAuthService
		verify         func(t *testing.T, w *httptest.ResponseRecorder, usedUUID string, returnedUserID int)
	}{
		{
			name: "pass with uuid",
			body: `{"email":"valid-user@mail.com","password":"valid-password","deviceUUID":"input-uuid"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					GenerateDeviceUUIDFunc: func() string { return "generated-uuid" },
					AuthenticateUserFunc: func(ctx context.Context, email, password string) (int, error) {
						return 1, nil
					},
					GenerateAccessTokenFunc: func(userID int) (string, error) {
						return "valid-access-token", nil
					},
					GenerateRefreshTokenFunc: func(ctx context.Context, userID int, deviceUUID string) (string, error) {
						return "valid-refresh-token", nil
					},
				}
			},
			expectedStatus: http.StatusOK,
			verify: func(t *testing.T, w *httptest.ResponseRecorder, usedUUID string, returnedUserID int) {
				assert.Equal(t, "input-uuid", usedUUID)
				assert.Equal(t, 1, returnedUserID)
				var body map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &body)
				assert.NoError(t, err)
				assert.Equal(t, "valid-access-token", body["accessToken"])
				assert.Equal(t, "valid-refresh-token", body["refreshToken"])
			},
		},
		{
			name: "pass without uuid",
			body: `{"email":"valid-user@mail.com","password":"valid-password"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					GenerateDeviceUUIDFunc: func() string { return "generated-uuid" },
					AuthenticateUserFunc: func(ctx context.Context, email, password string) (int, error) {
						return 1, nil
					},
					GenerateAccessTokenFunc: func(userID int) (string, error) {
						return "valid-access-token", nil
					},
					GenerateRefreshTokenFunc: func(ctx context.Context, userID int, deviceUUID string) (string, error) {
						return "valid-refresh-token", nil
					},
				}
			},
			expectedStatus: http.StatusOK,
			verify: func(t *testing.T, w *httptest.ResponseRecorder, usedUUID string, returnedUserID int) {
				assert.Equal(t, "generated-uuid", usedUUID)
				assert.Equal(t, 1, returnedUserID)
				var body map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &body)
				assert.NoError(t, err)
				assert.Equal(t, "valid-access-token", body["accessToken"])
				assert.Equal(t, "valid-refresh-token", body["refreshToken"])
			},
		},
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing email",
			body:           `{"password":"Password123!"}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing password",
			body:           `{"email":"user@mail.com"}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid creds",
			body: `{"email":"user@mail.com","password":"wrong"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					AuthenticateUserFunc: func(ctx context.Context, email, password string) (int, error) {
						return 0, app.ErrInvalidCredentials
					},
				}
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "GenerateAccessToken fails",
			body: `{"email":"user@mail.com","password":"valid"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					AuthenticateUserFunc: func(ctx context.Context, email, password string) (int, error) {
						return 1, nil
					},
					GenerateAccessTokenFunc: func(userID int) (string, error) {
						return "", errors.New("token error")
					},
					GenerateRefreshTokenFunc: func(ctx context.Context, userID int, deviceUUID string) (string, error) {
						return "refresh", nil
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name: "GenerateRefreshToken fails",
			body: `{"email":"user@mail.com","password":"valid"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					AuthenticateUserFunc: func(ctx context.Context, email, password string) (int, error) {
						return 1, nil
					},
					GenerateAccessTokenFunc: func(userID int) (string, error) {
						return "access", nil
					},
					GenerateRefreshTokenFunc: func(ctx context.Context, userID int, deviceUUID string) (string, error) {
						return "", errors.New("refresh error")
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := tt.mockSetup()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var usedUUID string
			var returnedUserID int
			// Wrap GenerateRefreshToken to capture UUID & userID
			if mockSvc.GenerateRefreshTokenFunc != nil {
				orig := mockSvc.GenerateRefreshTokenFunc
				mockSvc.GenerateRefreshTokenFunc = func(ctx context.Context, userID int, uuid string) (string, error) {
					usedUUID = uuid
					returnedUserID = userID
					return orig(ctx, userID, uuid)
				}
			}

			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/login", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h := NewAuthHandler(mockSvc)
			h.Login(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.verify != nil {
				tt.verify(t, w, usedUUID, returnedUserID)
			}
		})
	}
}

// ------------------- Refresh Access Token Tests -------------------

func TestRefreshAccessTokenHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		mockSetup      func() *mockAuthService
		verify         func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "pass",
			body: `{"refreshToken":"valid-token"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					RefreshAccessTokenFunc: func(ctx context.Context, token string) (string, error) {
						return "new-token", nil
					},
				}
			},
			expectedStatus: http.StatusOK,
			verify: func(t *testing.T, w *httptest.ResponseRecorder) {
				var body map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &body)
				assert.NoError(t, err)
				assert.Equal(t, "new-token", body["accessToken"])
			},
		},
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing refresh token",
			body:           `{}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"refreshToken":"bad-token"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					RefreshAccessTokenFunc: func(ctx context.Context, token string) (string, error) {
						return "", fmt.Errorf("failed to generate token")
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := tt.mockSetup()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/refresh", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h := NewAuthHandler(mockSvc)
			h.RefreshAccessToken(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.verify != nil {
				tt.verify(t, w)
			}
		})
	}
}

// ------------------- Logout Tests -------------------

func TestLogoutHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		mockSetup      func() *mockAuthService
	}{
		{
			name: "pass",
			body: `{"refreshToken":"valid-token"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					RevokeRefreshTokenFunc: func(ctx context.Context, token string) error { return nil },
				}
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing refresh token",
			body:           `{}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"refreshToken":"bad-token"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					RevokeRefreshTokenFunc: func(ctx context.Context, token string) error {
						return errors.New("failed to revoke")
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := tt.mockSetup()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/logout", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h := NewAuthHandler(mockSvc)
			h.LogOut(w, req)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// ------------------- LogoutAll Tests -------------------

func TestLogoutAllHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		mockSetup      func() *mockAuthService
	}{
		{
			name: "pass",
			body: `{"refreshToken":"valid-token"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					RevokeAllRefreshTokensFunc: func(ctx context.Context, token string) error { return nil },
				}
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing refresh token",
			body:           `{}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"refreshToken":"bad-token"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					RevokeAllRefreshTokensFunc: func(ctx context.Context, token string) error {
						return errors.New("failed to revoke all")
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := tt.mockSetup()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/logout/all", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h := NewAuthHandler(mockSvc)
			h.LogOutAll(w, req)
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// ------------------- SignUp Tests -------------------

func TestSignUpHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		mockSetup      func() *mockAuthService
		verify         func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "pass",
			body: `{"email":"user2@mail.com","password":"Password123!"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					CreateUserFunc: func(ctx context.Context, req *app.CreateUserRequest) (string, error) {
						return "uuid", nil
					},
				}
			},
			expectedStatus: http.StatusCreated,
			verify: func(t *testing.T, w *httptest.ResponseRecorder) {
				var body map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &body)
				assert.NoError(t, err)
				assert.Equal(t, "uuid", body["publicID"])
			},
		},
		{
			name:           "invalid JSON",
			body:           `invalid-json`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing email",
			body:           `{"password":"Password123!"}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing password",
			body:           `{"email":"user2@mail.com"}`,
			mockSetup:      func() *mockAuthService { return &mockAuthService{} },
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "service error",
			body: `{"email":"user2@mail.com","password":"Password123!"}`,
			mockSetup: func() *mockAuthService {
				return &mockAuthService{
					CreateUserFunc: func(ctx context.Context, req *app.CreateUserRequest) (string, error) {
						return "", errors.New("duplicate email")
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := tt.mockSetup()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/auth/signup", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h := NewAuthHandler(mockSvc)
			h.CreateUser(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.verify != nil {
				tt.verify(t, w)
			}
		})
	}
}
