package webui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestEmbeddedFrontend(t *testing.T) {
	e := echo.New()
	e.GET("/health", func(c *echo.Context) error {
		return c.String(http.StatusOK, "healthy")
	})
	Register(e)

	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", path, response.Code, response.Body.String())
		}
		return response
	}

	index := get("/")
	if !strings.Contains(index.Header().Get("Content-Type"), "text/html") || !strings.Contains(index.Body.String(), `<div id="app">`) {
		t.Fatal("root did not serve the built frontend")
	}
	script := regexp.MustCompile(`src="([^"]+\.js)"`).FindStringSubmatch(index.Body.String())
	if len(script) != 2 {
		t.Fatal("frontend entry script is missing")
	}
	asset := get(script[1])
	if !strings.Contains(asset.Header().Get("Content-Type"), "javascript") {
		t.Fatal("frontend script resolved to HTML instead of JavaScript")
	}
	if get("/scans/123").Body.String() != index.Body.String() {
		t.Fatal("client route did not fall back to the frontend")
	}
	if get("/health").Body.String() != "healthy" {
		t.Fatal("frontend fallback replaced an API route")
	}
}
