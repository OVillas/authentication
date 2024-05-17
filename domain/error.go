package domain

import "time"

type ErrorResponse struct {
	Error     string    `json:"error"`
	Message   string    `json:"message"`
	TimeStamp time.Time `json:"timeStamp"`
	Path      string    `json:"path"`
}
