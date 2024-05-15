package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/util"
	"github.com/labstack/echo/v4"
	"github.com/samber/do"
)

type userPasswordHandler struct {
	i                       *do.Injector
	userPasswordService     domain.UserPasswordService
	confirmationCodeService domain.ConfirmationCodeService
}

func NewUserPasswordHandler(i *do.Injector) domain.UserPasswordHandler {
	userPasswordService := do.MustInvoke[domain.UserPasswordService](i)
	confimatioCodeService := do.MustInvoke[domain.ConfirmationCodeService](i)
	return &userPasswordHandler{
		i:                       i,
		userPasswordService:     userPasswordService,
		confirmationCodeService: confimatioCodeService,
	}
}

func (uph *userPasswordHandler) UpdatePassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "UpdatePassword"),
		slog.String("handler", "authentication"))

	log.Info("UpdatePassword service initiated")

	userId := c.Param("id")

	if err := util.IsValidUUID(userId); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, err)
	}

	userIdFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("err to get user if from token")
		return c.JSON(http.StatusUnauthorized, err)
	}

	if userId != userIdFromToken {
		log.Warn("you cannot update the data of a user other than yourself")
		return c.NoContent(http.StatusForbidden)
	}

	var updatePassword domain.UpdatePassword
	if err := c.Bind(&updatePassword); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := updatePassword.Validate(); err != nil {
		log.Warn("invalid user data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	err = uph.userPasswordService.UpdatePassword(userId, updatePassword)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Error("Error: ", err)
		return c.JSON(http.StatusNotFound, err)
	}

	if err != nil && errors.Is(err, domain.ErrPasswordNotMatch) {
		log.Error("Error: ", err)
		return c.JSON(http.StatusUnauthorized, err)
	}

	log.Info("UpdatePassword executed successfully")
	return c.NoContent(http.StatusNoContent)
}

func (uph *userPasswordHandler) ForgotPassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ForgotPassword"),
		slog.String("handler", "authentication"))

	log.Info("ForgotPassword service initiated")

	var requestResetPassword domain.RequestResetPassword
	if err := c.Bind(&requestResetPassword); err != nil {
		log.Warn("Failed to bind requestResetPassword data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := requestResetPassword.Validate(); err != nil {
		log.Warn("Invalid requestResetPassword data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := uph.confirmationCodeService.SendConfirmationCode(requestResetPassword.Email); err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("Confirmation send successfully")
	return c.NoContent(http.StatusOK)
}

func (uph *userPasswordHandler) ConfirmResetPasswordCode(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ConfirmResetPasswordCode"),
		slog.String("handler", "authentication"))

	log.Info("ConfirmResetPasswordCode service initiated")

	var confirmCode domain.ConfirmCode
	if err := c.Bind(&confirmCode); err != nil {
		log.Warn("Failed to bind confirmCode data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := confirmCode.Validate(); err != nil {
		log.Warn("Invalid confirmCode data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	token, err := uph.userPasswordService.ConfirmResetPasswordCode(confirmCode)

	if err != nil && errors.Is(err, domain.ErrOTPNotFound) {
		log.Warn("OTP not found")
		return c.NoContent(http.StatusNotFound)
	}

	if err != nil && errors.Is(err, domain.ErrInvalidOTP) {
		log.Warn("Expired token or wrong token")
		return c.NoContent(http.StatusUnauthorized)
	}

	if err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("Reset password code confirmed successfully")
	return c.JSON(http.StatusOK, token)
}

func (uph *userPasswordHandler) ResetPassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ResetPassword"),
		slog.String("handler", "authentication"))

	log.Info("ResetPassword service initiated")

	userIdFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("err to get user if from token")
		return c.JSON(http.StatusUnauthorized, err)
	}

	var resetPassword domain.ResetPassword
	if err := c.Bind(&resetPassword); err != nil {
		log.Warn("Failed to bind resetPassword data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := resetPassword.Validate(); err != nil {
		log.Warn("Invalid resetPassword data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	err = uph.userPasswordService.ResetPassword(userIdFromToken, resetPassword)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found with this email")
		return c.NoContent(http.StatusNotFound)
	}

	if err != nil && errors.Is(err, domain.ErrPasswordNotMatch) {
		log.Warn("Password and confirm password do not match")
		return c.NoContent(http.StatusUnprocessableEntity)
	}

	if err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("Password reset successfully")
	return c.NoContent(http.StatusOK)
}
