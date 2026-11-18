package sast

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
	contentType := c.Request().Header.Get("Content-Type")
	if strings.Contains(contentType, "multipart/form-data") {
		file, err := c.FormFile("file")
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "请上传源码 zip 压缩包 (字段名: 'file')",
			})
		}

		src, err := file.Open()
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "无法读取上传的 zip 文件: " + err.Error(),
			})
		}
		defer src.Close()

		language := strings.TrimSpace(c.FormValue("language"))
		timeoutSec, _ := strconv.Atoi(c.FormValue("timeout"))
		if timeoutSec <= 0 {
			timeoutSec = 600
		}

		scan, err := h.service.CreateScanWithZip(c.Request().Context(),file.Filename,src,language,time.Duration(timeoutSec)*time.Second,)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
		}

		return c.JSON(http.StatusCreated, scan)
	}

	var req CreateScanRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request",
		})
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 600
	}

	scan, err := h.service.CreateScan(
		c.Request().Context(),
		req.RepoURL,
		req.Language,
		time.Duration(timeout)*time.Second,
	)
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

func (h *Handler) ListScans(c *echo.Context) error {
	scans, err := h.service.ListScans(c.Request().Context())
	if err != nil {
		c.Logger().Error("list scans failed", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to list scans",
		})
	}
	return c.JSON(http.StatusOK, scans)
}

func (h *Handler) GetScan(c *echo.Context) error {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 63)
	if err != nil || scanID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid scan id",
		})
	}

	scan, err := h.service.GetScan(c.Request().Context(), scanID)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "scan not found"})
	}
	if err != nil {
		c.Logger().Error("get scan failed", "scan_id", scanID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get scan",
		})
	}

	return c.JSON(http.StatusOK, scan)
}

func (h *Handler) GetScanFindings(c *echo.Context) error {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 63)
	if err != nil || scanID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid scan id",
		})
	}

	findings, err := h.service.GetScanFindings(c.Request().Context(), scanID)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "scan not found"})
	}
	if err != nil {
		c.Logger().Error("get scan findings failed", "scan_id", scanID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get scan findings"})
	}

	return c.JSON(http.StatusOK, findings)
}

func (h *Handler) DeleteScanFindings(c *echo.Context) error {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 63)
	if err != nil || scanID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid scan id",
		})
	}

	err = h.service.DeleteScanFindings(c.Request().Context(), scanID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "findings deleted successfully",
		"scan_id": scanID,
	})
}

func (h *Handler) DeleteScan(c *echo.Context) error {
	scanID, err := strconv.ParseUint(c.Param("id"), 10, 63)
	if err != nil || scanID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid scan id",
		})
	}

	err = h.service.DeleteScan(c.Request().Context(), scanID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "scan deleted successfully",
		"scan_id": scanID,
	})
}

