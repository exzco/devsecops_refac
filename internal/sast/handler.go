package sast

import (
	"net/http"
	"time"
	"strconv"

	"github.com/labstack/echo/v5"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

type CreateScanRequest struct {
	RepoURL  string        `json:"repo_url"`
	Language string        `json:"language"`
	Timeout  time.Duration `json:"timeout"`
}

func (h *Handler) CreateScanRequest(c *echo.Context) error {
	var req CreateScanRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request",
		})
	}

	scan, err := h.service.CreateScan(c.Request().Context(), req.RepoURL, req.Language, time.Duration(req.Timeout)*time.Second)

	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, scan)

}

func (h *Handler) ListWorkers(c *echo.Context) error {
	workers, err := h.service.ListWorkers(c.Request().Context())
	if err != nil {
		c.Logger().Error("list workers failed", "error", err)
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "worker status is unavailable",
		})
	}
	return c.JSON(http.StatusOK, workers)
}

func (h *Handler) GetScan(c *echo.Context) error {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 63)
	if err != nil || scanID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid scan id",
		})
	}

	scan, err := h.service.GetScan(c.Request().Context(), scanID)
	if err != nil {
		c.Logger().Error("get scan failed", "scan_id", scanID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get scan",
		})
	}

	return c.JSON(http.StatusOK, scan)
}