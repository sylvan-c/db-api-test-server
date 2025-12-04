package handlers

import (
	"context"
	"db-api-test-server/internal/api/contextkeys"
	"db-api-test-server/internal/app"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

type mockUserService struct {
	GetUserByIDFunc   func(ctx context.Context, userID uuid.UUID) (*app.User, error)
	UpdateProfileFunc func(ctx context.Context, userID uuid.UUID, updates map[string]any) (*app.User, error)
}

func (u *mockUserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*app.User, error) {
	return u.GetUserByIDFunc(ctx, userID)
}

func (u *mockUserService) UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]any) (*app.User, error) {
	return u.UpdateProfileFunc(ctx, userID, updates)
}

// ------------------- GetUser Tests -------------------

func TestGetUserHandler(t *testing.T) {
	dummyUserUUID, _ := uuid.NewV7()
	tests := []struct {
		name           string
		id             uuid.UUID
		mockSetup      func() *mockUserService
		expectedStatus int
		expectedFirst  string
		expectedLast   string
		expectedEmail  string
	}{
		{
			name: "success",
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserByIDFunc: func(ctx context.Context, userID uuid.UUID) (*app.User, error) {
						return &app.User{
							ID:        dummyUserUUID,
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
			name: "GetUserByID fails",
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{
					GetUserByIDFunc: func(ctx context.Context, userID uuid.UUID) (*app.User, error) {
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
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/users/"+tt.id.String(), nil)

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
	dummyUserUUID, _ := uuid.NewV7()
	mockSvc := &mockUserService{}
	handler := NewUserHandler(mockSvc)

	t.Run("authenticated redirect", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/me", nil)
		ctx := context.WithValue(req.Context(), contextkeys.UserID, dummyUserUUID)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		handler.GetMeRedirect(w, req)
		assert.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/api/users/"+dummyUserUUID.String(), w.Header().Get("Location"))
	})

	t.Run("unauthorized missing context", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/me", nil)
		w := httptest.NewRecorder()
		handler.GetMeRedirect(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ------------------- UpdateProfile Tests -------------------

func TestUpdateProfileHandler(t *testing.T) {
	dummyUserUUID, _ := uuid.NewV7()
	tests := []struct {
		name           string
		body           string
		id             uuid.UUID
		mockSetup      func() *mockUserService
		expectedStatus int
	}{
		{
			name: "valid first and last name",
			body: `{"firstName":"Alice","lastName":"Smith"}`,
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{
					UpdateProfileFunc: func(ctx context.Context, id uuid.UUID, updates map[string]any) (*app.User, error) {
						return &app.User{ID: dummyUserUUID, Email: "alicesmith@fakemail.com", FirstName: "Alice", LastName: "Smith"}, nil
					},
				}
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "empty body",
			body: `{}`,
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{
					UpdateProfileFunc: func(ctx context.Context, userID uuid.UUID, updates map[string]any) (*app.User, error) {
						return &app.User{ID: dummyUserUUID, Email: "testuser@fakemail.com", FirstName: "test", LastName: "user"}, nil
					},
				}
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid json",
			body: "invalid-json",
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid field",
			body: `{"hack":"bad"}`,
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{}
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "UpdateProfile fails",
			body: `{"firstName":"Alice"}`,
			id:   dummyUserUUID,
			mockSetup: func() *mockUserService {
				return &mockUserService{
					UpdateProfileFunc: func(ctx context.Context, id uuid.UUID, updates map[string]any) (*app.User, error) {
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

			req := httptest.NewRequestWithContext(ctx, http.MethodPatch, "/users/"+tt.id.String(), strings.NewReader(tt.body))
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
