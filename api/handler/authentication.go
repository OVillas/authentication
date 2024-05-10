package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/util"
	"github.com/labstack/echo/v4"
)

type authenticationHandler struct {
	authenticationService domain.AuthenticationService
}

func NewAuthenticationHandler(authService domain.AuthenticationService) domain.AuthenticationHandler {
	return &authenticationHandler{
		authenticationService: authService,
	}
}

func (a *authenticationHandler) Login(c echo.Context) error {
	log := slog.With(
		slog.String("func", "Login"),
		slog.String("handler", "authentication"))

	log.Info("Login service initiated")

	var login domain.Login
	if err := c.Bind(&login); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := login.Validate(); err != nil {
		log.Warn("Invalid login data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	token, err := a.authenticationService.Login(login)
	if err != nil && errors.Is(err, domain.ErrPasswordNotMatch) {
		log.Warn("username or password invalid")
		return c.NoContent(http.StatusForbidden)

	}

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found with username: " + login.Username)
		return c.NoContent(http.StatusNotFound)

	}

	if err != nil {
		log.Error("Error trying to call login service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("login executed successfully")
	return c.JSON(http.StatusOK, token)
}

func (a *authenticationHandler) UpdatePassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "UpdatePassword"),
		slog.String("handler", "authentication"))

	log.Info("UpdatePassword service initiated")

	userId := c.Param("userId")

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

	err = a.authenticationService.UpdatePassword(userId, updatePassword)

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

func (a *authenticationHandler) ConfirmEmail(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ConfirmEmail"),
		slog.String("handler", "authentication"))

	log.Info("ConfirmEmail service initiated")

	var confirmCodeEmail domain.ConfirmCode
	if err := c.Bind(&confirmCodeEmail); err != nil {
		log.Warn("Failed to bind confirmCodeData data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := confirmCodeEmail.Validate(); err != nil {
		log.Warn("Invalid confirmCodeEmail data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	err := a.authenticationService.ConfirmEmail(confirmCodeEmail)

	if err != nil && errors.Is(err, domain.ErrInvalidOTP) {
		log.Warn("Expired token or wrong token")
		return c.NoContent(http.StatusUnauthorized)
	}

	if err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("e-mail confirmed successfully")
	return c.NoContent(http.StatusOK)
}

func (a *authenticationHandler) ForgotPassword(c echo.Context) error {
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

	if err := a.authenticationService.SendConfirmationCode(requestResetPassword.Email); err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("Confirmation send successfully")
	return c.NoContent(http.StatusOK)
}

func (a *authenticationHandler) ConfirmResetPasswordCode(c echo.Context) error {
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

	token, err := a.authenticationService.ConfirmResetPasswordCode(confirmCode)

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

func (a *authenticationHandler) ResetPassword(c echo.Context) error {
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

	err = a.authenticationService.ResetPassword(userIdFromToken, resetPassword)

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
