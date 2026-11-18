package dast

import (
	"devsecops/internal/dast/domain"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"
)

type HandlerConfig struct {
	UserID       func(*http.Request) (string, error)
	MaxBodyBytes int64
}

type Handler struct {
	service *Service
	cfg     HandlerConfig
}

func NewHandler(service *Service, cfg HandlerConfig) (*Handler, error) {
	if service == nil || cfg.UserID == nil || cfg.MaxBodyBytes <= 0 {
		return nil, fmt.Errorf("DAST service, user authenticator and body limit are required")
	}
	return &Handler{service: service, cfg: cfg}, nil
}

func fail(c *echo.Context, err error) error {
	return failStatus(c, http.StatusBadRequest, err)
}

func failStatus(c *echo.Context, status int, err error) error {
	return c.JSON(status, map[string]string{"error": err.Error()})
}

func (h *Handler) authenticateUser(c *echo.Context) (string, error) {
	id, err := h.cfg.UserID(c.Request())
	if err != nil || id == "" {
		return "", errors.New("user authentication required")
	}
	return id, nil
}

func (h *Handler) decodeRequest(c *echo.Context, dst any) error {
	body := http.MaxBytesReader(c.Response(), c.Request().Body, h.cfg.MaxBodyBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errors.New("request body exceeds configured limit")
		}
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}
func parsePathID(c *echo.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid ID")
	}
	return id, nil
}
func (h *Handler) ListAssets(c *echo.Context) error {
	if _, err := h.authenticateUser(c); err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	filter := domain.AssetFilter{SourceID: c.QueryParam("source_id"), ClusterID: c.QueryParam("cluster_id"), NetworkZone: c.QueryParam("network_zone"), BusinessID: c.QueryParam("business_id")}
	result, err := h.service.ListAssets(c.Request().Context(), filter)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(200, result)
}
func (h *Handler) CreateAsset(c *echo.Context) error {
	if _, err := h.authenticateUser(c); err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	var asset domain.Asset
	if err := h.decodeRequest(c, &asset); err != nil {
		return fail(c, err)
	}
	result, err := h.service.CreateAsset(c.Request().Context(), asset)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(http.StatusCreated, result)
}

func (h *Handler) CreateScan(c *echo.Context) error {
	user, err := h.authenticateUser(c)
	if err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	var req domain.CreateScanRequest
	if err := h.decodeRequest(c, &req); err != nil {
		return fail(c, err)
	}
	result, err := h.service.CreateScan(c.Request().Context(), user, req)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(201, result)
}
func (h *Handler) ListScans(c *echo.Context) error {
	user, err := h.authenticateUser(c)
	if err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	result, err := h.service.ListScans(c.Request().Context(), user)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(200, result)
}
func (h *Handler) CancelScan(c *echo.Context) error {
	user, err := h.authenticateUser(c)
	if err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	id, err := parsePathID(c)
	if err != nil {
		return fail(c, err)
	}
	changed, err := h.service.CancelScan(c.Request().Context(), id, user)
	if err != nil {
		return failStatus(c, http.StatusInternalServerError, err)
	}
	if !changed {
		return failStatus(c, http.StatusConflict, errors.New("没有可取消的任务"))
	}
	return c.NoContent(http.StatusNoContent)
}
func (h *Handler) GetScan(c *echo.Context) error {
	user, err := h.authenticateUser(c)
	if err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	id, err := parsePathID(c)
	if err != nil {
		return fail(c, err)
	}
	result, err := h.service.GetScan(c.Request().Context(), id, user)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(200, result)
}
func (h *Handler) GetTask(c *echo.Context) error {
	user, err := h.authenticateUser(c)
	if err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	id, err := parsePathID(c)
	if err != nil {
		return fail(c, err)
	}
	result, err := h.service.GetTask(c.Request().Context(), id, user)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(200, result)
}
func (h *Handler) ListFindings(c *echo.Context) error {
	user, err := h.authenticateUser(c)
	if err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	id, err := parsePathID(c)
	if err != nil {
		return fail(c, err)
	}
	result, err := h.service.ListFindings(c.Request().Context(), id, user)
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(200, result)
}
func (h *Handler) ListWorkers(c *echo.Context) error {
	if _, err := h.authenticateUser(c); err != nil {
		return failStatus(c, http.StatusUnauthorized, err)
	}
	result, err := h.service.ListWorkers(c.Request().Context())
	if err != nil {
		return fail(c, err)
	}
	return c.JSON(200, result)
}
