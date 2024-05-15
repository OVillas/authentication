package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

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

func NewUserPasswordHandler(i *do.Injector) (domain.UserPasswordHandler, error) {
	userPasswordService := do.MustInvoke[domain.UserPasswordService](i)
	confimatioCodeService := do.MustInvoke[domain.ConfirmationCodeService](i)
	return &userPasswordHandler{
		i:                       i,
		userPasswordService:     userPasswordService,
		confirmationCodeService: confimatioCodeService,
	}, nil
}

// UpdatePassword godoc
// @Summary Update password user
// @Description Update password for authenticated users
// @Tags users
// @Accept json
// @Produce json
// @Param updatePassword body domain.UpdatePassword true "Update Password Payload"
// @Success 200 {object} string "JWT Token"
// @Failure 422 {object} domain.ErrorResponse
// @Failure 403
// @Failure 404 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/password/{id} [patch]
// @Security bearerToken
func (uph *userPasswordHandler) UpdatePassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "UpdatePassword"),
		slog.String("handler", "authentication"))

	log.Info("UpdatePassword service initiated")

	userId := c.Param("id")

	if err := util.IsValidUUID(userId); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Bad Request",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	userIdFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("err to get user if from token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if userId != userIdFromToken {
		log.Warn("you cannot update the data of a user other than yourself")
		return c.NoContent(http.StatusForbidden)
	}

	var updatePassword domain.UpdatePassword
	if err := c.Bind(&updatePassword); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := updatePassword.Validate(); err != nil {
		log.Warn("invalid user data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Invalid user data",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	err = uph.userPasswordService.UpdatePassword(userId, updatePassword)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Error("Error: ", err)
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not found user",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil && errors.Is(err, domain.ErrPasswordNotMatch) {
		log.Error("Error: ", err)
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Uncorrect password",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("UpdatePassword executed successfully")
	return c.NoContent(http.StatusNoContent)
}

// ForgotPassword godoc
// @Summary Forgot user password
// @Description Send an OTP code to redeem your password
// @Tags authentication
// @Accept json
// @Produce json
// @Param confirmCode body domain.ConfirmCode true "Confirmation Code Payload"
// @Success 200 {object} string "JWT Token"
// @Failure 422 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/auth/password [post]
func (uph *userPasswordHandler) ForgotPassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ForgotPassword"),
		slog.String("handler", "authentication"))

	log.Info("ForgotPassword service initiated")

	var requestResetPassword domain.RequestResetPassword
	if err := c.Bind(&requestResetPassword); err != nil {
		log.Warn("Failed to bind requestResetPassword data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := requestResetPassword.Validate(); err != nil {
		log.Warn("Invalid requestResetPassword data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := uph.confirmationCodeService.SendConfirmationCode(requestResetPassword.Email); err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Confirmation send successfully")
	return c.NoContent(http.StatusOK)
}

// ConfirmResetPasswordCode godoc
// @Summary Confirm reset password code
// @Description Confirm the reset password code sent to the user's email
// @Tags authentication
// @Accept json
// @Produce json
// @Param confirmCode body domain.ConfirmCode true "Confirmation Code"
// @Success 200 {string} string "JWT Token"
// @Failure 404 {object} domain.ErrorResponse "Not Found"
// @Failure 401 {object} domain.ErrorResponse "Unauthorized"
// @Failure 500 {object} domain.ErrorResponse "Internal Server Error"
// @Router /v1/auth/password/confirm [post]
func (uph *userPasswordHandler) ConfirmResetPasswordCode(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ConfirmResetPasswordCode"),
		slog.String("handler", "authentication"))

	log.Info("ConfirmResetPasswordCode initiated")

	var confirmCode domain.ConfirmCode
	if err := c.Bind(&confirmCode); err != nil {
		log.Warn("Failed to bind confirmCode data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := confirmCode.Validate(); err != nil {
		log.Warn("Invalid confirmCode data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	token, err := uph.userPasswordService.ConfirmResetPasswordCode(confirmCode)

	if err != nil && errors.Is(err, domain.ErrOTPNotFound) {
		log.Warn("OTP not found")
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not Found",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil && errors.Is(err, domain.ErrInvalidOTP) {
		log.Warn("Expired token or wrong token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Reset password code confirmed successfully")
	return c.JSON(http.StatusOK, token)
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Reset the password for the authenticated user
// @Tags authentication
// @Accept json
// @Produce json
// @Param resetPassword body domain.ResetPassword true "Reset Password Data"
// @Success 204
// @Failure 401 {object} domain.ErrorResponse "Unauthorized"
// @Failure 422 {object} domain.ErrorResponse "Unprocessable Entity"
// @Failure 404 {object} domain.ErrorResponse "Not Found"
// @Failure 500 {object} domain.ErrorResponse "Internal Server Error"
// @Router /v1/users/password/reset [patch]
// @Security bearerToken
func (uph *userPasswordHandler) ResetPassword(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ResetPassword"),
		slog.String("handler", "authentication"))

	log.Info("ResetPassword service initiated")

	userIdFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("err to get user if from token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	var resetPassword domain.ResetPassword
	if err := c.Bind(&resetPassword); err != nil {
		log.Warn("Failed to bind resetPassword data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := resetPassword.Validate(); err != nil {
		log.Warn("Invalid resetPassword data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	err = uph.userPasswordService.ResetPassword(userIdFromToken, resetPassword)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found with this email")
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not Found",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil && errors.Is(err, domain.ErrPasswordNotMatch) {
		log.Warn("Password and confirm password do not match")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Errors: ", err)
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Password reset successfully")
	return c.NoContent(http.StatusOK)
}
