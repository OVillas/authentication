package main

import (
	"fmt"

	"github.com/OVillas/autentication/api/handler"
	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/database"
	"github.com/OVillas/autentication/repository"
	"github.com/OVillas/autentication/service"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/samber/do"
	"gorm.io/gorm"
)

func main() {
	config.Load()
	e := echo.New()
	i := do.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	db, err := database.NewMysqlConnection()
	if err != nil {
		panic(err)
	}

	do.Provide(i, func(i *do.Injector) (*gorm.DB, error) {
		return db, nil
	})

	do.Provide(i, repository.NewUserRepository)
	do.Provide(i, service.NewEmailService)
	do.Provide(i, service.NewUserService)
	do.Provide(i, handler.NewUserHandler)
	handler.SetupRoutes(e, i)

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", config.Port)))
}
