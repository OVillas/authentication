package handler

import (
	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/middleware"
	"github.com/labstack/echo/v4"
	"github.com/samber/do"
)

func SetupRoutes(e *echo.Echo, i *do.Injector) {
	setupUserRoutes(e, i)
	setupAuthRoutes(e, i)
	setupHealthCheckRoutes(e, i)
}

func setupUserRoutes(e *echo.Echo, i *do.Injector) {
	userHandler := do.MustInvoke[domain.UserHandler](i)
	userPasswordHandler := do.MustInvoke[domain.UserPasswordHandler](i)

	group := e.Group("v1/users")
	group.POST("", userHandler.Create)
	group.GET("", userHandler.GetAll, middleware.CheckLoggedIn)
	group.GET("/:id", userHandler.GetById, middleware.CheckLoggedIn)
	group.GET("/name", userHandler.GetByNameOrUsername, middleware.CheckLoggedIn)
	group.GET("/email", userHandler.GetByEmail, middleware.CheckLoggedIn)
	group.PUT("/:id", userHandler.Update, middleware.CheckLoggedIn)
	group.DELETE("/:id", userHandler.Delete, middleware.CheckLoggedIn)
	group.PATCH("/:id/password", userPasswordHandler.UpdatePassword, middleware.CheckLoggedIn)
	group.PATCH("/email/confirm", userHandler.ConfirmEmail)

	e.GET("v1/user", userHandler.GetCredencials, middleware.CheckLoggedIn)
}

func setupAuthRoutes(e *echo.Echo, i *do.Injector) {
	userHandler := do.MustInvoke[domain.UserHandler](i)
	userPasswordHandler := do.MustInvoke[domain.UserPasswordHandler](i)

	group := e.Group("v1/auth")
	group.POST("/password/forgot", userPasswordHandler.ForgotPassword)
	group.POST("/password/confirm", userPasswordHandler.ConfirmResetPasswordCode)
	group.POST("/password/reset", userPasswordHandler.ResetPassword)
	group.POST("/login", userHandler.Login)
}

func setupHealthCheckRoutes(e *echo.Echo, i *do.Injector) {
	healthCheckHandler := do.MustInvoke[domain.HealthCheckHandler](i)

	e.GET("/", healthCheckHandler.HealthCheck)
}
