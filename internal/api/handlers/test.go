package handlers

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getTest(w, r)
	case http.MethodPost:
		h.postTest(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) getTest(w http.ResponseWriter, _ *http.Request) {
	rows, err := h.App.DB.Query("SELECT test_column FROM test_table")
	if err != nil {
		http.Error(w, "Failed to query test table", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var testData []map[string]any
	for rows.Next() {
		var testColumn string
		if err := rows.Scan(&testColumn); err != nil {
			http.Error(w, "Failed to read row", http.StatusInternalServerError)
			return
		}
		testData = append(testData, map[string]any{
			"test_column": testColumn,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(testData)
}

type PostTestRequest struct {
	TestColumn string `json:"test_column"`
}

func (h *Handler) postTest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PostTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.TestColumn == "" {
		http.Error(w, "test_column is required", http.StatusBadRequest)
		return
	}

	// Insert into DB
	var id int
	err := h.App.DB.QueryRow(
		"INSERT INTO test_table (test_column) VALUES ($1) RETURNING id",
		req.TestColumn,
	).Scan(&id)
	if err != nil {
		http.Error(w, "Failed to post test data", http.StatusInternalServerError)
		return
	}

	// Respond with new user ID
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":          id,
		"test_column": req.TestColumn,
	})
}
