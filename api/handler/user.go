package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

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

// Create godoc
// @Summary Create a new user
// @Description Create a new user in the system
// @Tags users
// @Accept json
// @Produce json
// @Param user body domain.UserPayLoad true "User Payload"
// @Success 201
// @Failure 422 {object} domain.ErrorResponse
// @Failure 409 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users [post]
func (uh *userHandler) Create(c echo.Context) error {
	log := slog.With(
		slog.String("func", "Create"),
		slog.String("handler", "user"))

	log.Info("Create initiated")

	var userPayLoad domain.UserPayLoad
	if err := c.Bind(&userPayLoad); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Failed to bind user data",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := userPayLoad.Validate(); err != nil {
		log.Warn("Invalid user data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Invalid user data",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	err := uh.userService.Create(userPayLoad)

	if err != nil && errors.Is(err, domain.ErrUserAlreadyRegistered) {
		log.Warn("There is already a registered user with this email: " + userPayLoad.Email)
		return c.JSON(http.StatusConflict, domain.ErrorResponse{
			Error:     "User already registered",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Error trying to call Create user service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal server error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	err = uh.confirmatioCodeService.SendConfirmationCode(userPayLoad.Email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Failed to send confirmation code",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("User created successfully")
	return c.NoContent(http.StatusCreated)
}

// GetAll godoc
// @Summary Get all users
// @Description Get all users in the system
// @Tags users
// @Produce json
// @Success 200 {array} domain.UserResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users [get]
// @Security bearerToken
func (uh *userHandler) GetAll(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetAll"),
		slog.String("handler", "user"))

	userResponse, err := uh.userService.GetAll()
	if err != nil {
		log.Error("Error trying to call get users service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Error retrieving users",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Users successfully retrieved")

	if len(userResponse) == 0 {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

// GetById godoc
// @Summary Get user by ID
// @Description Get a user by ID
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} domain.UserResponse
// @Failure 400 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/{id} [get]
// @Security bearerToken
func (uh *userHandler) GetById(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetById"),
		slog.String("handler", "user"))

	id := c.Param("id")

	if err := util.IsValidUUID(id); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Invalid parameters",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	userResponse, err := uh.userService.GetById(id)
	if err != nil {
		log.Error("Error trying to call get user by id service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Error retrieving user by ID",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("User successfully retrieved")

	if userResponse == nil {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

// GetById godoc
// @Summary Get user by ID
// @Description Get a user by ID
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} domain.UserResponse
// @Failure 400 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/user [get]
// @Security bearerToken
func (uh *userHandler) GetCredencials(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetCredencials"),
		slog.String("handler", "user"))

	idFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("Error getting user ID from token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := util.IsValidUUID(idFromToken); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Invalid UUID",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := util.IsValidUUID(idFromToken); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Invalid parameters",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	userResponse, err := uh.userService.GetById(idFromToken)
	if err != nil {
		log.Error("Error trying to call get user by id service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Error retrieving user by ID",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("User successfully retrieved")

	if userResponse == nil {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

// GetByNameOrUsername godoc
// @Summary Get user by name or username
// @Description Get a user by name or username
// @Tags users
// @Produce json
// @Param name query string true "Name or Username"
// @Success 200 {array} domain.UserResponse
// @Failure 400 {object} domain.ErrorResponse
// @Failure 404
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/name [get]
// @Security bearerToken
func (uh *userHandler) GetByNameOrUsername(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetByNameOrUsername"),
		slog.String("handler", "user"))

	name := c.QueryParam("name")

	if name == "" {
		log.Warn("Empty entry of name query params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Missing parameter",
			Message:   "The 'name' parameter is required",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	userResponse, err := uh.userService.GetByNameOrUsername(name)
	if err != nil {
		log.Error("Error trying to call get user by name service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Error retrieving user by name or username",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("User successfully retrieved")

	if userResponse == nil {
		return c.NoContent(http.StatusNoContent)
	}

	return c.JSON(http.StatusOK, userResponse)
}

// GetByEmail godoc
// @Summary Get user by email
// @Description Get a user by their email address
// @Tags users
// @Accept json
// @Produce json
// @Param e query string true "e"
// @Success 200 {object} domain.UserResponse
// @Failure 400 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/email [get]
// @Security bearerToken
func (uh *userHandler) GetByEmail(c echo.Context) error {
	log := slog.With(
		slog.String("func", "GetByEmail"),
		slog.String("handler", "user"))

	email := c.QueryParam("e")

	if email == "" {
		log.Warn("Empty entry of email query params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Empty Email",
			Message:   "The 'email' parameter is required",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := checkmail.ValidateFormat(email); err != nil {
		log.Warn("Invalid entry of email query params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Invalid Email",
			Message:   "The 'email' parameter is invalid",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	userResponse, err := uh.userService.GetByEmail(email)
	if err != nil {
		log.Error("Error trying to call get user by email service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("User successfully rescued")

	if userResponse == nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, userResponse)
}

// Update godoc
// @Summary Update a user
// @Description Update a user's information
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body domain.UserUpdatePayLoad true "User Update Payload"
// @Success 204
// @Failure 400 {object} domain.ErrorResponse
// @Failure 401 {object} domain.ErrorResponse
// @Failure 403
// @Failure 404 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/{id} [put]
// @Security bearerToken
func (uh *userHandler) Update(c echo.Context) error {
	log := slog.With(
		slog.String("func", "update"),
		slog.String("handler", "user"))

	id := c.Param("id")
	if err := util.IsValidUUID(id); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Invalid UUID",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	idFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("Error getting user ID from token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if id != idFromToken {
		log.Warn("You cannot update the data of a user other than yourself")
		return c.JSON(http.StatusForbidden, domain.ErrorResponse{
			Error:     "Forbidden",
			Message:   "You cannot update another user's data",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	var userUpdatePayLoad domain.UserUpdatePayLoad
	if err := c.Bind(&userUpdatePayLoad); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if userUpdatePayLoad.Email == "" && userUpdatePayLoad.Name == "" {
		log.Warn("Both name and email are empty")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Bad Request",
			Message:   "Both name and email cannot be empty",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if userUpdatePayLoad.Name != "" {
		if err := userUpdatePayLoad.Validate(); err != nil {
			log.Warn("Invalid user data")
			return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
				Error:     "Unprocessable Entity",
				Message:   err.Error(),
				TimeStamp: time.Now(),
				Path:      c.Path(),
			})
		}
	}

	if userUpdatePayLoad.Email != "" {
		if err := checkmail.ValidateFormat(userUpdatePayLoad.Email); err != nil {
			log.Warn("Invalid user data")
			return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
				Error:     "Unprocessable Entity",
				Message:   err.Error(),
				TimeStamp: time.Now(),
				Path:      c.Path(),
			})
		}
	}

	err = uh.userService.Update(id, userUpdatePayLoad)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found to update your information's")
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not Found",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil && errors.Is(err, domain.ErrSameEmail) {
		log.Warn("User not found to update your information's")
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not Found",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Error trying to call update user service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Update executed successfully")
	return c.NoContent(http.StatusNoContent)
}

// Delete godoc
// @Summary Delete a user
// @Description Delete a user by ID
// @Tags users
// @Param id path string true "User ID"
// @Success 204
// @Failure 400 {object} domain.ErrorResponse
// @Failure 401 {object} domain.ErrorResponse
// @Failure 403
// @Failure 404 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/{id} [delete]
// @Security bearerToken
func (uh *userHandler) Delete(c echo.Context) error {
	log := slog.With(
		slog.String("func", "delete"),
		slog.String("handler", "user"))

	id := c.Param("id")
	if err := util.IsValidUUID(id); err != nil {
		log.Warn("Invalid params")
		return c.JSON(http.StatusBadRequest, domain.ErrorResponse{
			Error:     "Bad Request",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	idFromToken, err := util.ExtractUserIdFromToken(c)
	if err != nil {
		log.Warn("Error getting user ID from token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if id != idFromToken {
		log.Warn("You cannot delete the data of a user other than yourself")
		return c.NoContent(http.StatusForbidden)
	}

	err = uh.userService.Delete(id)

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found to delete")
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not Found",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Error trying to call delete service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("User successfully deleted")

	return c.NoContent(http.StatusNoContent)
}

// Login godoc
// @Summary Login a user
// @Description Authenticate user and return JWT token
// @Tags authentication
// @Accept json
// @Produce json
// @Param login body domain.Login true "Login Payload"
// @Success 200 {object} string "JWT Token"
// @Failure 422 {object} domain.ErrorResponse
// @Failure 403
// @Failure 404 {object} domain.ErrorResponse
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/auth/login [post]
func (uh *userHandler) Login(c echo.Context) error {
	log := slog.With(
		slog.String("func", "Login"),
		slog.String("handler", "authentication"))

	log.Info("Login service initiated")

	var login domain.Login
	if err := c.Bind(&login); err != nil {
		log.Warn("Failed to bind user data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := login.Validate(); err != nil {
		log.Warn("Invalid login data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	token, err := uh.userService.Login(login)
	if err != nil && errors.Is(err, domain.ErrPasswordNotMatch) {
		log.Warn("Invalid username or password")
		return c.JSON(http.StatusForbidden, domain.ErrorResponse{
			Error:     "Forbidden",
			Message:   "Invalid username or password",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil && errors.Is(err, domain.ErrUserNotFound) {
		log.Warn("User not found with username: " + login.Username)
		return c.JSON(http.StatusNotFound, domain.ErrorResponse{
			Error:     "Not Found",
			Message:   "User not found with username: " + login.Username,
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Error trying to call login service.")
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Login executed successfully")
	return c.JSON(http.StatusOK, token)
}

// ConfirmEmail godoc
// @Summary Confirm user's email
// @Description Confirm a user's email with the confirmation code
// @Tags users
// @Accept json
// @Produce json
// @Param confirmCode body domain.ConfirmCode true "Confirmation Code Payload"
// @Success 200
// @Failure 422 {object} domain.ErrorResponse
// @Failure 401
// @Failure 500 {object} domain.ErrorResponse
// @Router /v1/users/email/confirm [post]
// @Security bearerToken
func (uh *userHandler) ConfirmEmail(c echo.Context) error {
	log := slog.With(
		slog.String("func", "ConfirmEmail"),
		slog.String("handler", "authentication"))

	log.Info("ConfirmEmail service initiated")

	var confirmCodeEmail domain.ConfirmCode
	if err := c.Bind(&confirmCodeEmail); err != nil {
		log.Warn("Failed to bind confirmCodeData data to domain")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err := confirmCodeEmail.Validate(); err != nil {
		log.Warn("Invalid confirmCodeEmail data")
		return c.JSON(http.StatusUnprocessableEntity, domain.ErrorResponse{
			Error:     "Unprocessable Entity",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	err := uh.userService.ConfirmEmail(confirmCodeEmail)

	if err != nil && errors.Is(err, domain.ErrInvalidOTP) {
		log.Warn("Expired token or wrong token")
		return c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
			Error:     "Unauthorized",
			Message:   "Expired token or wrong token",
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	if err != nil {
		log.Error("Error trying to confirm email:", err)
		return c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
			Error:     "Internal Server Error",
			Message:   err.Error(),
			TimeStamp: time.Now(),
			Path:      c.Path(),
		})
	}

	log.Info("Email confirmed successfully")
	return c.NoContent(http.StatusOK)
}
