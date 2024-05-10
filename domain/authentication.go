package models

import (
	"errors"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

var (
	ErrPasswordNotMatch        = errors.New("invalid password")
	ErrGenToken                = errors.New("error to generate new token jwt")
	ErrUnexpectedSigningMethod = errors.New("unexpected signature method")
	ErrInvalidToken            = errors.New("token invalid")
	ErrIdNotFoundInPermissions = errors.New("error to get id in token")
	ErrIdIsNotAString          = errors.New("'id' field value is not a string")
	ErrUpdatePassword          = errors.New("error to update password")
	ErrToSendConfirmationCode  = errors.New("error to send confirmation code")
	ErrInvalidOTP              = errors.New("wrong or expired OTP")
	ErrOTPNotFound             = errors.New("not found OTP from email")
	ErrUserIDMismatch          = errors.New("user ID mismatch")
)

type Login struct {
	Username string `json:"username,omitempty" validate:"required,min=6"`
	Password string `json:"password,omitempty" validate:"required"`
}

type UpdatePassword struct {
	Current string `json:"current,omitempty" validate:"required,min=6,containsany=!@#&?"`
	New     string `json:"new,omitempty" validate:"required,min=6,containsany=!@#&?"`
}

type ResetPassword struct {
	New     string `json:"new,omitempty" validate:"required,min=6,containsany=!@#&?"`
	Confirm string `json:"confirm,omitempty" validate:"required,min=6,containsany=!@#&?"`
}

type ConfirmationCode struct {
	Code       string
	ExpiryTime time.Time
}

type ConfirmCode struct {
	Email string `json:"email,omitempty" validate:"required,email"`
	Code  string `json:"code,omitempty" validate:"required"`
}

type RequestResetPassword struct {
	Email string `json:"email,omitempty" validate:"required,email"`
}

func (l *Login) Validate() error {
	validate := validator.New()
	return validate.Struct(l)
}

func (rrp *RequestResetPassword) Validate() error {
	validate := validator.New()
	return validate.Struct(rrp)
}

func (up *UpdatePassword) Validate() error {
	validate := validator.New()
	return validate.Struct(up)
}

func (ce *ConfirmCode) Validate() error {
	validate := validator.New()
	return validate.Struct(ce)
}

func (rp *ResetPassword) Validate() error {
	validate := validator.New()
	return validate.Struct(rp)
}

type AuthenticationHandler interface {
	Login(c echo.Context) error
	UpdatePassword(c echo.Context) error
	ConfirmEmail(c echo.Context) error
	ForgotPassword(c echo.Context) error
	ConfirmResetPasswordCode(c echo.Context) error
	ResetPassword(c echo.Context) error
}

type AuthenticationService interface {
	Login(login Login) (string, error)
	UpdatePassword(id string, updatePassword UpdatePassword) error
	SendConfirmationCode(email string) error
	ConfirmEmail(confirmCode ConfirmCode) error
	ConfirmResetPasswordCode(confirmCode ConfirmCode) (string, error)
	ResetPassword(userId string, resetPassword ResetPassword) error
	CheckUserIDMatch(idFromToken string) error
}
