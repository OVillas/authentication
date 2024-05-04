package handler

import (
	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/middleware"
	"github.com/OVillas/autentication/repository"
	"github.com/OVillas/autentication/service"
	"github.com/labstack/echo/v4"
)

func SetupRoutes(e *echo.Echo) {
	configureUserRoutes(e)
	configureAuthenticationRoutes(e)
}

func configureUserRoutes(e *echo.Echo) {
	userRepository := repository.NewUserRepository()
	userService := service.NewUserService(userRepository)
	emailService := service.NewEmailService("Social Network", config.EmailSender, config.EMailSenderPassword)
	authenticationService := service.NewAuthenticationService(userRepository, emailService)
	userHandler := NewUserHandler(userService, authenticationService)

	group := e.Group("v1/user")
	group.POST("", userHandler.Create)
	group.GET("", userHandler.GetAll)
	group.GET("/:id", userHandler.GetById)
	group.GET("/name", userHandler.GetByNameOrNick)
	group.GET("/email", userHandler.GetByEmail)
	group.PUT("/:id", userHandler.Update, middleware.CheckLoggedIn)
	group.DELETE("/:id", userHandler.Delete, middleware.CheckLoggedIn)
}

func configureAuthenticationRoutes(e *echo.Echo) {
	userRepository := repository.NewUserRepository()
	emailService := service.NewEmailService("Social Network", config.EmailSender, config.EMailSenderPassword)
	authenticationService := service.NewAuthenticationService(userRepository, emailService)
	authenticationHandler := NewAuthenticationHandler(authenticationService)

	group := e.Group("v1/authentication")
	group.POST("/login", authenticationHandler.Login)
	group.PATCH("/user/:userId/password", authenticationHandler.UpdatePassword, middleware.CheckLoggedIn)
	group.PATCH("/email/confirm", authenticationHandler.ConfirmEmail)
}
