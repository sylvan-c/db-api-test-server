package handlers

import (
	"db-api-test-server/internal/app"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

type mockUserService struct {
	GetUserByIDFunc func(userID int) (*app.User, error)
	CreateUserFunc  func(req *app.CreateUserRequest) (*app.User, error)
}

func (u *mockUserService) GetUserByID(userID int) (*app.User, error) {
	return u.GetUserByIDFunc(userID)
}

func (u *mockUserService) CreateUser(req *app.CreateUserRequest) (*app.User, error) {
	return u.CreateUserFunc(req)
}

func TestUsersIDHandler(t *testing.T) {
	tests := []struct {
		name           string
		id             int
		endpoint       string
		username       string
		email          string
		firstName      string
		lastName       string
		err            error
		expectedStatus int
	}{
		// pass
		{
			name:           "pass",
			id:             1,
			username:       "user1",
			email:          "user1@mail.com",
			firstName:      "user",
			lastName:       "one",
			err:            nil,
			expectedStatus: http.StatusOK,
		},
		// fail
		{
			name:           "invalid id (non-numeric)",
			endpoint:       "/users/abc",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid id (negative)",
			endpoint:       "/users/-1",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "internal error",
			id:             1,
			err:            fmt.Errorf("user not found"),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mux.NewRouter()
			mockSvc := &mockUserService{
				GetUserByIDFunc: func(userID int) (*app.User, error) {
					return &app.User{
						ID:        tt.id,
						Username:  tt.username,
						Email:     tt.email,
						FirstName: tt.firstName,
						LastName:  tt.lastName,
					}, tt.err
				},
			}

			w := httptest.NewRecorder()

			h := NewUserHandler(mockSvc)
			r.HandleFunc("/users/{id}", h.GetUser).Methods("GET")

			endpoint := tt.endpoint
			if endpoint == "" {
				endpoint = fmt.Sprintf("/users/%d", tt.id)
			}
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			r.ServeHTTP(w, req)

			resp := w.Result()
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)

			var body app.User
			if w.Code == 200 {
				err := json.Unmarshal(bodyBytes, &body)
				assert.NoError(t, err)
			}

			if tt.name == "pass" {
				assert.Equal(t, 1, body.ID)
				assert.Equal(t, "user1", body.Username)
				assert.Equal(t, "user1@mail.com", body.Email)
				assert.Equal(t, "user", body.FirstName)
				assert.Equal(t, "one", body.LastName)
			}

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
