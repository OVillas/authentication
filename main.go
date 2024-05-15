package main

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/OVillas/autentication/api/handler"
	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/database"
	_ "github.com/OVillas/autentication/docs"
	"github.com/OVillas/autentication/repository"
	"github.com/OVillas/autentication/service"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/samber/do"
	echoSwagger "github.com/swaggo/echo-swagger"
	"gorm.io/gorm"
)

// @title Authentication Pulse Tech API
// @version 1.0
// @description API para gerenciamento de autenticação, incluindo registro de usuários, login, confirmação de e-mail, e recuperação de senha.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @SecurityDefinitions.apiKey bearerToken
// @in header
// @name Authorization

// @host localhost:8080
// @BasePath /
// @schemes http
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
	do.Provide(i, service.NewCodeService)
	do.Provide(i, service.NewUserPasswordService)
	do.Provide(i, handler.NewUserPasswordHandler)
	do.Provide(i, handler.NewHealthCheckHandler)
	do.Provide(i, handler.NewUserHandler)

	handler.SetupRoutes(e, i)
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	go openBrowser(fmt.Sprintf("http://localhost:%d/swagger/index.html", config.Port))

	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", config.Port)))

}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "darwin":
		err = exec.Command("open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = exec.Command("xdg-open", url).Start()
	}

	if err != nil {
		fmt.Println(err)
	}
}
