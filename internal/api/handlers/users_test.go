package handlers

import (
	"context"
	"db-api-test-server/internal/app"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"db-api-test-server/internal/api/contextkeys"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

type mockUserService struct {
	GetUserByIDFunc         func(ctx context.Context, userID int) (*app.User, error)
	GetPublicIDForUserFunc  func(ctx context.Context, userID int) (string, error)
	GetUserIDByPublicIDFunc func(ctx context.Context, userPubID string) (int, error)
	UpdateProfileFunc       func(ctx context.Context, userID int, updates map[string]any) (*app.User, error)
}

func (u *mockUserService) GetUserByID(ctx context.Context, userID int) (*app.User, error) {
	return u.GetUserByIDFunc(ctx, userID)
}

func (u *mockUserService) GetPublicIDForUser(ctx context.Context, userID int) (string, error) {
	return u.GetPublicIDForUserFunc(ctx, userID)
}

func (u *mockUserService) GetUserIDByPublicID(ctx context.Context, userPubID string) (int, error) {
	return u.GetUserIDByPublicIDFunc(ctx, userPubID)
}

func (u *mockUserService) UpdateProfile(ctx context.Context, userID int, updates map[string]any) (*app.User, error) {
	return u.UpdateProfileFunc(ctx, userID, updates)
}

// ------------------- GetUser Tests -------------------

func TestGetUserHandler(t *testing.T) {
	tests := []struct {
		name           string
		publicID       string
		mockSetup      func() *mockUserService
		expectedStatus int
		expectedFirst  string
		expectedLast   string
		expectedEmail  string
	}{
		{
			name:     "success",
			publicID: "valid-public-id",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 1, nil
					},
					GetUserByIDFunc: func(ctx context.Context, userID int) (*app.User, error) {
						return &app.User{
							ID:        1,
							Email:     "user@mail.com",
							FirstName: "John",
							LastName:  "Doe",
						}, nil
					},
				}
			},
			expectedStatus: http.StatusOK,
			expectedFirst:  "John",
			expectedLast:   "Doe",
			expectedEmail:  "user@mail.com",
		},
		{
			name:     "invalid public id",
			publicID: "bad-id",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 0, app.ErrInvalidID
					},
				}
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:     "GetUserByID fails",
			publicID: "valid-public-id",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 1, nil
					},
					GetUserByIDFunc: func(ctx context.Context, userID int) (*app.User, error) {
						return nil, errors.New("db error")
					},
				}
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mux.NewRouter()
			h := NewUserHandler(tt.mockSetup())
			r.HandleFunc("/users/{id}", h.GetUser).Methods("GET")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/users/"+tt.publicID, nil)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if w.Code == http.StatusOK {
				bodyBytes, _ := io.ReadAll(w.Body)
				var user app.User
				err := json.Unmarshal(bodyBytes, &user)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedFirst, user.FirstName)
				assert.Equal(t, tt.expectedLast, user.LastName)
				assert.Equal(t, tt.expectedEmail, user.Email)
			}
		})
	}
}

// ------------------- GetMeRedirect Tests -------------------

func TestGetMeRedirectHandler(t *testing.T) {
	mockSvc := &mockUserService{
		GetPublicIDForUserFunc: func(ctx context.Context, userID int) (string, error) {
			if userID == 1 {
				return "public123", nil
			}
			return "", errors.New("not found")
		},
	}
	handler := NewUserHandler(mockSvc)

	t.Run("authenticated redirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/me", nil)
		ctx := context.WithValue(req.Context(), contextkeys.UserID, 1)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.GetMeRedirect(w, req)
		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/api/users/public123", w.Header().Get("Location"))
	})

	t.Run("unauthorized missing context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/me", nil)
		w := httptest.NewRecorder()
		handler.GetMeRedirect(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("GetPublicIDForUser fails", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/me", nil)
		ctx := context.WithValue(req.Context(), contextkeys.UserID, 2)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.GetMeRedirect(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ------------------- UpdateProfile Tests -------------------

func TestUpdateProfileHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		publicID       string
		mockSetup      func() *mockUserService
		expectedStatus int
	}{
		{
			name:     "valid first and last name",
			body:     `{"firstName":"Alice","lastName":"Smith"}`,
			publicID: "valid",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 1, nil
					},
					UpdateProfileFunc: func(ctx context.Context, id int, updates map[string]any) (*app.User, error) {
						return &app.User{ID: 1, FirstName: "Alice", LastName: "Smith"}, nil
					},
				}
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "invalid json",
			body:     "invalid-json",
			publicID: "valid",
			mockSetup: func() *mockUserService {
				return &mockUserService{}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "invalid field",
			body:     `{"hack":"bad"}`,
			publicID: "valid",
			mockSetup: func() *mockUserService {
				return &mockUserService{}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "empty body",
			body:     `{}`,
			publicID: "valid",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 1, nil
					},
				}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "GetUserIDByPublicID fails",
			body:     `{"firstName":"Alice"}`,
			publicID: "invalid",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 0, errors.New("not found")
					},
				}
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:     "UpdateProfile fails",
			body:     `{"firstName":"Alice"}`,
			publicID: "valid",
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserIDByPublicIDFunc: func(ctx context.Context, pubID string) (int, error) {
						return 1, nil
					},
					UpdateProfileFunc: func(ctx context.Context, id int, updates map[string]any) (*app.User, error) {
						return nil, errors.New("db error")
					},
				}
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mux.NewRouter()
			h := NewUserHandler(tt.mockSetup())
			r.HandleFunc("/users/{id}", h.UpdateProfile).Methods("PATCH")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req := httptest.NewRequestWithContext(ctx, http.MethodPatch, "/users/"+tt.publicID, strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if w.Code == http.StatusOK {
				bodyBytes, _ := io.ReadAll(w.Body)
				var user app.User
				err := json.Unmarshal(bodyBytes, &user)
				assert.NoError(t, err)
			}
		})
	}
}
