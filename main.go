package main

import (
	"fmt"

	"github.com/OVillas/autentication/api/handler"
	"github.com/OVillas/autentication/config"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	config.Load()
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	handler.SetupRoutes(e)
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", config.Port)))
}
