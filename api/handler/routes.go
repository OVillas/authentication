package handler

import (
	"github.com/OVillas/autentication/domain"
	"github.com/OVillas/autentication/middleware"
	"github.com/labstack/echo/v4"
	"github.com/samber/do"
)

func SetupRoutes(e *echo.Echo, i *do.Injector) {
	configureUserRoutes(e, i)
}

func configureUserRoutes(e *echo.Echo, i *do.Injector) {
	userHandler := do.MustInvoke[domain.UserHandler](i)

	group := e.Group("v1/user")
	group.POST("", userHandler.Create)
	group.GET("", userHandler.GetAll, middleware.CheckLoggedIn)
	group.GET("/:id", userHandler.GetById, middleware.CheckLoggedIn)
	group.GET("/name", userHandler.GetByNameOrNick, middleware.CheckLoggedIn)
	group.GET("/email", userHandler.GetByEmail, middleware.CheckLoggedIn)
	group.PUT("/:id", userHandler.Update, middleware.CheckLoggedIn)
	group.DELETE("/:id", userHandler.Delete, middleware.CheckLoggedIn)
	group.POST("/login", userHandler.Login)
	group.PATCH("/:id/password", userHandler.UpdatePassword, middleware.CheckLoggedIn)
	group.PATCH("/email/confirm", userHandler.ConfirmEmail)
	group.POST("/password/forgot", userHandler.ForgotPassword)
	group.POST("/password/confirm", userHandler.ConfirmResetPasswordCode)
	group.POST("/password/reset", userHandler.ResetPassword)
}
