package handler

import (
	"net/http"

	"github.com/OVillas/autentication/domain"
	"github.com/labstack/echo/v4"
	"github.com/samber/do"
)

type HealthCheckHandler struct {
	i *do.Injector
}

func NewHealthCheckHandler(i *do.Injector) (domain.HealthCheckHandler, error) {
	return &HealthCheckHandler{i: i}, nil
}

// HealthCheck godoc
// @Summary Show the status of server.
// @Description get the status of server.
// @Tags HealthCheck
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router / [get]
func (h *HealthCheckHandler) HealthCheck(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"data": "Server is up and running",
	})
}
