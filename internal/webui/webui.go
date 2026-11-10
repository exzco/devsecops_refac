package webui

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/labstack/echo/v5"
)

//go:embed all:dist
var distFS embed.FS
func Register(e *echo.Echo) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("webui: embed dist missing: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))

	e.GET("/*", func(c *echo.Context) error {
		req := c.Request()
		f, err := sub.Open(req.URL.Path[1:]) 
		if err != nil {
			// fallback → index.html
			req.URL.Path = "/"
		} else {
			f.Close()
		}
		fileServer.ServeHTTP(c.Response(), req)
		return nil
	})
}
