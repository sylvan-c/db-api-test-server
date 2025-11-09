package middleware

import (
	"context"
	"db-api-test-server/internal/api/contextkeys"
	"db-api-test-server/internal/api/handlers"
	"net/http"
	"strings"
)

func JWTMiddleware(h *handlers.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing Authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
				return
			}

			tokenStr := parts[1]
			claims, err := h.App.Auth.ValidateToken(tokenStr)
			if err != nil {
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextkeys.UserID, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
