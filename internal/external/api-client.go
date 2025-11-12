package external

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ClientService interface {
	FetchData() (string, error)
}

type Client struct {
	BaseURL string
}

func NewClient(baseURL string) ClientService {
	return &Client{BaseURL: baseURL}
}

func (c *Client) FetchData() (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/data", c.BaseURL))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Value, nil
}
