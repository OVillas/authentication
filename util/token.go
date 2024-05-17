package util

import (
	"crypto/rand"
	"io"
	"strings"
	"time"

	"github.com/OVillas/autentication/config"
	"github.com/OVillas/autentication/domain"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

func CreateToken(user domain.User) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 6).Unix(),
	})

	tokenString, err := token.SignedString([]byte(config.SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func CreateResetPasswordToken(user domain.User) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  user.ID,
		"exp": time.Now().Add(time.Hour * 6).Unix(),
	})

	tokenString, err := token.SignedString([]byte(config.SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func getVerificationKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, domain.ErrUnexpectedSigningMethod
	}

	return config.SecretKey, nil
}

func extractToken(c echo.Context) string {
	token := c.Request().Header.Get("Authorization")

	length := len(strings.Split(token, " "))
	if length == 2 {
		return strings.Split(token, " ")[1]
	}
												
	return ""
}

func ExtractUserIdFromToken(c echo.Context) (string, error) {
	tokenString := extractToken(c)
	token, err := jwt.Parse(tokenString, getVerificationKey)
	if err != nil {
		return "", err
	}

	permissions, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		return "", domain.ErrInvalidToken
	}

	idInterface, exists := permissions["id"]
	if !exists {
		return "", domain.ErrIdNotFoundInPermissions
	}

	id, ok := idInterface.(string)
	if !ok {
		return "", domain.ErrIdIsNotAString
	}

	if err := IsValidUUID(id); err != nil {
		return "", domain.ErrInvalidId
	}

	return id, nil
}

func GenerateOTP(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}
