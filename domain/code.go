package domain

import (
	"time"
)

type ConfirmationCode struct {
	Code       string
	ExpiryTime time.Time
}

type ConfirmCode struct {
	Email string `json:"email,omitempty" validate:"required,email"`
	Code  string `json:"code,omitempty" validate:"required"`
}

type ConfirmationCodeService interface {
	SendConfirmationCode(email string) error
	ConfirmCode(confirmCode ConfirmCode) (*User, error)
}
