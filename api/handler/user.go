package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/util"
	"github.com/badoux/checkmail"
	"github.com/labstack/echo/v4"
	"github.com/samber/do"
)

type userHandler struct {
	i                      *do.Injector
	userService            domain.UserService
	confirmatioCodeService domain.ConfirmationCodeService
}

func NewUserHandler(i *do.Injector) (domain.UserHandler, error) {
	userService := do.MustInvoke[domain.UserService](i)
	confimatioCodeService := do.MustInvoke[domain.ConfirmationCodeService](i)
	return &userHandler{
		i:                      i,
		userService:            userService,
		confirmatioCodeService: confimatioCodeService,
	}, nil
}

func (uh *userHandler) Create(c echo.Context) error {
	log := slog.With(
		slog.String("func", "Create"),
		slog.String("handler", "user"))

	log.Info("Create initiated")

	var userPayLoad domain.UserPayLoad
	if err := c.Bind(&userPayLoad); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if err := userPayLoad.Validate(); err != nil {
		log.Warn("Invalid user data")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	err := uh.userService.Create(userPayLoad)

	if err != nil && errors.Is(err, domain.ErrUserAlreadyRegistered) {
		log.Warn("There is already a registered user with this email: " + userPayLoad.Email)
		return c.JSON(http.StatusConflict, err)
	}

	if err != nil {
		log.Error("Error trying to call Create user service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	err = uh.confirmatioCodeService.SendConfirmationCode(userPayLoad.Email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("User created successfully")
	return c.NoContent(http.StatusCreated)
}

func (uh *userHandler) GetAll(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetALl"),
		slog.String("handler", "user"))

	userResponse, err := uh.userService.GetAll()
	if err != nil {
		log.Error("Error trying to call get users service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("Users successfully rescued")

	if userResponse == nil {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

func (uh *userHandler) GetById(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetById"),
		slog.String("handler", "user"))

	id := c.Param("id")

	if err := util.IsValidUUID(id); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, err)
	}

	userResponse, err := uh.userService.GetById(id)
	if err != nil {
		log.Error("Error trying to call get user by id service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("User successfully rescued")

	if userResponse == nil {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

func (uh *userHandler) GetByNameOrUsername(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetByName"),
		slog.String("handler", "user"))

	name := c.QueryParam("n")

	if name == "" {
		log.Warn("empty entry of name query params")
		return c.String(http.StatusBadRequest, "The 'name' parameter is required")
	}

	userResponse, err := uh.userService.GetByNameOrUsername(name)
	if err != nil {
		log.Error("Error trying to call get user by name service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("User successfully rescued")

	if userResponse == nil {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

func (uh *userHandler) GetByEmail(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetByEmail"),
		slog.String("handler", "user"))

	email := c.QueryParam("e")

	if email == "" {
		log.Warn("empty entry of email query params")
		return c.String(http.StatusBadRequest, "The 'email' parameter is required")
	}

	if err := checkmail.ValidateFormat(email); err != nil {
		log.Warn("invalid entry of email query params")
		return c.String(http.StatusBadRequest, "The 'email' parameter is invalid")
	}

	userResponse, err := uh.userService.GetByEmail(email)
	if err != nil {
		log.Error("Error trying to call get user by email service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("User successfully rescued")

	if userResponse == nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, userResponse)
}

func (uh *userHandler) Update(c echo.Context) error {
	log := slog.With(
		slog.String("func", "update"),
		slog.String("handler", "user"))

	id := c.Param("id")
	if err := util.IsValidUUID(id); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, err)
	}

	idFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("err to get user if from token")
		return c.JSON(http.StatusUnauthorized, err)
	}

	if id != idFromToken {
		log.Warn("you cannot update the data of a user other than yourself")
		return c.NoContent(http.StatusForbidden)
	}

	var userUpdatePayLoad domain.UserUpdatePayLoad
	if err := c.Bind(&userUpdatePayLoad); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, err)
	}

	if userUpdatePayLoad.Email == "" && userUpdatePayLoad.Name == "" {
		log.Warn("Both name and email are empty")
		return c.JSON(http.StatusBadRequest, "Both name and email cannot be empty")
	}

	if userUpdatePayLoad.Name != "" {
		if err := userUpdatePayLoad.Validate(); err != nil {
			log.Warn("Invalid user data")
			return c.JSON(http.StatusUnprocessableEntity, err)
		}
	}

	if userUpdatePayLoad.Email != "" {
		if err := checkmail.ValidateFormat(userUpdatePayLoad.Email); err != nil {
			log.Warn("Invalid user data")
			return c.JSON(http.StatusUnprocessableEntity, err)
		}
	}

	err = uh.userService.Update(id, userUpdatePayLoad)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("user not found to update your information's")
		return c.JSON(http.StatusNotFound, err)
	}

	if err != nil && errors.Is(err, domain.ErrSameEmail) {
		log.Warn("user not found to update your information's")
		return c.JSON(http.StatusNotFound, err)
	}

	if err != nil {
		log.Error("Error trying to call update user service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("Update executed successfully")
	return c.NoContent(http.StatusNoContent)
}

func (uh *userHandler) Delete(c echo.Context) error {
	log := slog.With(
		slog.String("func", "delete"),
		slog.String("handler", "user"))

	id := c.Param("id")
	if err := util.IsValidUUID(id); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, err)
	}

	idFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("err to get user if from token")
		return c.JSON(http.StatusUnauthorized, err)
	}

	if id != idFromToken {
		log.Warn("you cannot delete the data of a user other than yourself")
		return c.NoContent(http.StatusForbidden)
	}

	err = uh.userService.Delete(id)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found to delete")
		return c.JSON(http.StatusNotFound, err)
	}

	if err != nil {
		log.Error("Error trying to call delete service.")
		return c.JSON(http.StatusInternalServerError, err)
	}

	log.Info("User successfully deleted")

	return c.NoContent(http.StatusNoContent)
}

func (uh *userHandler) Login(c echo.Context) error {
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

	token, err := uh.userService.Login(login)
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

func (uh *userHandler) ConfirmEmail(c echo.Context) error {
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

	err := uh.userService.ConfirmEmail(confirmCodeEmail)

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
