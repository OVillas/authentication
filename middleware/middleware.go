package middleware

import (
	"net/http"
	"strings"

	"github.com/OVillas/autentication/config"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

func CheckLoggedIn(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		authorizationHeader := ctx.Request().Header.Get("Authorization")

		if authorizationHeader == "" {
			return ctx.NoContent(http.StatusUnauthorized)
		}

		parts := strings.Split(authorizationHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return ctx.NoContent(http.StatusUnauthorized)
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.SecretKey), nil
		})

		if err != nil {
			if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorExpired != 0 {
					return ctx.JSON(http.StatusUnauthorized, map[string]string{"error": "token expired"})
				}
			}
			return ctx.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		}

		if !token.Valid {
			return ctx.NoContent(http.StatusUnauthorized)
		}

		return next(ctx)
	}
}
