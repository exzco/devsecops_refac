package dashboard

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
)

type Handler struct {
	store store
	userID func(*http.Request) (string, error)
}

func NewHandler(db *pgxpool.Pool, userID func(*http.Request) (string, error)) (*Handler, error) {
	if db == nil || userID == nil {
		return nil, errors.New("dashboard database and user authenticator are required")
	}
	return &Handler{store: store{db: db}, userID: userID}, nil
}

func (h *Handler) Show(c *echo.Context) error {
	user, err := h.userID(c.Request())
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}
	result, err := h.store.summary(c.Request().Context(), user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, result)
}
