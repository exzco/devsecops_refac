package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"devsecops/internal/config"
	"devsecops/internal/infra"
	"devsecops/internal/sast"
	"devsecops/internal/webui"
	"github.com/labstack/echo/v5"
)

func main() {
	cfg, err := config.LoadEnv()
	if err != nil {
		log.Fatalf("load .env: %v", err)
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Host,
		cfg.Postgres.Port, cfg.Postgres.Database)
	db, err := infra.ConnectDB(context.Background(), dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rdb, err := infra.ConnectRedis(context.Background(), cfg.Redis.Host, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		panic(err)
	}
	defer rdb.Close()

	store := sast.NewStore(db)
	queue := sast.NewQueue(rdb)
	scanner := sast.NewSASTScanner(cfg.SASTScanner)
	service := sast.NewService(store, queue, scanner)
	handler := sast.NewHandler(service)

	e := echo.New()

	e.GET("/health", func(c *echo.Context) error {
		return c.String(http.StatusOK, "healthy\n")
	})
	e.POST("/api/v1/scans", handler.CreateScanRequest)
	e.GET("/api/v1/scans", handler.ListScans)
	e.GET("/api/v1/workers", handler.ListWorkers)
	e.GET("/api/v1/scans/:id", handler.GetScan)
	e.GET("/api/v1/scans/:id/findings", handler.GetScanFindings)
	e.DELETE("/api/v1/scans/:id/findings", handler.DeleteScanFindings)
	webui.Register(e)

	port := 9000
	if cfg.ServerPort > 0 {
		port = cfg.ServerPort
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatalf("listen tcp4 0.0.0.0:%d: %v", port, err)
	}
	log.Printf("listening on %s (IPv4)", ln.Addr())

	srv := &http.Server{Handler: e}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server stopped: %v", err)
	}
}