package domain

import (
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type RequestResetPassword struct {
	Email string `json:"email,omitempty" validate:"required,email"`
}

type UpdatePassword struct {
	Current string `json:"current,omitempty" validate:"required,min=6,containsany=!@#&?"`
	New     string `json:"new,omitempty" validate:"required,min=6,containsany=!@#&?"`
}

type ResetPassword struct {
	New     string `json:"new,omitempty" validate:"required,min=6,containsany=!@#&?"`
	Confirm string `json:"confirm,omitempty" validate:"required,min=6,containsany=!@#&?"`
}

func (rrp *RequestResetPassword) Validate() error {
	validate := validator.New()
	return validate.Struct(rrp)
}
func (up *UpdatePassword) Validate() error {
	validate := validator.New()
	return validate.Struct(up)
}

func (rp *ResetPassword) Validate() error {
	validate := validator.New()
	return validate.Struct(rp)
}

type UserPasswordHandler interface {
	UpdatePassword(ctx echo.Context) error
	ForgotPassword(ctx echo.Context) error
	ConfirmResetPasswordCode(ctx echo.Context) error
	ResetPassword(ctx echo.Context) error
}

type UserPasswordService interface {
	ConfirmResetPasswordCode(confirmCode ConfirmCode) (string, error)
	ResetPassword(userId string, resetPassword ResetPassword) error
	UpdatePassword(id string, updatePassword UpdatePassword) error
}
