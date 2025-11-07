package handlers

import "database/sql"

// Handler holds dependencies like DB connection
type Handler struct {
	DB *sql.DB
}

// NewHandler constructs Handler with DB
func NewHandler(db *sql.DB) *Handler {
	return &Handler{DB: db}
}
