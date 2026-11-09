package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"devsecops/internal/config"
	"devsecops/internal/infra"
	"devsecops/internal/sast"
	"github.com/labstack/echo/v5"
)

func main() {
	// 加载环境变量
	cfg, err := config.LoadEnv()
	if err != nil {
		log.Fatalf("load .env: %v", err)
	}

	// 连接 postgresql, redis
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Host, cfg.Postgres.Port, cfg.Postgres.Database)
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

	// sast 依赖注入
	store := sast.NewStore(db)
	queue := sast.NewQueue(rdb)
	scanner := sast.NewSASTScanner(cfg.SASTScanner)
	service := sast.NewService(store, queue, scanner)
	handler := sast.NewHandler(service)

	// echo 框架路由
	e := echo.New()

	e.GET("/health", func(c *echo.Context) error {
		return c.String(http.StatusOK, "healthy\n")
	})
	e.POST("/api/v1/scans/create", handler.CreateScanRequest)
	e.GET("/api/v1/workers", handler.ListWorkers)
	e.GET("/api/v1/scans/:id", handler.GetScan)

	// 服务启动
	if err := e.Start(":9000"); err != nil {
		e.Logger.Error("server stopped", "error", err)
	}
}
