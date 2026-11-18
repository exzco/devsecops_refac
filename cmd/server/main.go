package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"devsecops/internal"
	"devsecops/internal/dashboard"
	"devsecops/internal/dast"
	"devsecops/internal/infra"
	"devsecops/internal/poc"
	"devsecops/internal/sast"
	"devsecops/internal/webui"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// userID 是现有身份体系提供的调用方身份；接入统一登录后替换为令牌校验。
func userID(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.Header.Get("X-User-Id"))
	if id == "" {
		return "", errors.New("X-User-Id header is required")
	}
	return id, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := internal.LoadEnv()
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
	if err := store.InitPolicy(ctx, cfg.SASTScanner.QuerySuite); err != nil { log.Fatal(err) }
	queue := sast.NewQueue(rdb)
	scanner := sast.NewSASTScanner(cfg.SASTScanner)
	service := sast.NewService(store, queue, scanner)
	handler := sast.NewHandler(service)

	dastStore, err := dast.NewStore(db)
	if err != nil {
		log.Fatal(err)
	}
	dastService, err := dast.NewService(dastStore, rdb, nil, dastStore, cfg.DASTServer)
	if err != nil {
		log.Fatal(err)
	}
	dastHandler, err := dast.NewHandler(dastService, dast.HandlerConfig{
		UserID:       userID,
		MaxBodyBytes: 32 << 20,
	})
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := dastService.ExpireRun(ctx); err != nil {
			log.Fatalf("DAST task cleanup stopped: %v", err)
		}
	}()

	dashboardHandler, err := dashboard.NewHandler(db, userID)
	if err != nil {
		log.Fatal(err)
	}

	e := echo.New()

	// 调试
	// e.HTTPErrorHandler = echo.DefaultHTTPErrorHandler(true)
	// e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
	// 	LogStatus:   true,
	// 	LogURI:      true,
	// 	LogMethod:   true,
	// 	LogLatency:  true,
	// 	LogRemoteIP: true,
	// 	HandleError: true,
	// 	LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
	// 		latency := v.Latency
	// 		if v.Error != nil {
	// 			log.Printf("[HTTP] \033[1;31m%d\033[0m | %8v | %-6s %s | error: %v", v.Status, latency, v.Method, v.URI, v.Error)
	// 		} else if latency > 300*time.Millisecond {
	// 			log.Printf("[HTTP] \033[1;33m%d\033[0m | \033[1;33m%8v\033[0m \033[1;31m[SLOW]\033[0m | %-6s %s", v.Status, latency, v.Method, v.URI)
	// 		} else {
	// 			log.Printf("[HTTP] \033[1;32m%d\033[0m | %8v | %-6s %s", v.Status, latency, v.Method, v.URI)
	// 		}
	// 		return nil
	// 	},
	// }))

	e.GET("/health", func(c *echo.Context) error {
		return c.String(http.StatusOK, "healthy\n")
	})
	e.GET("/api/v1/dashboard", dashboardHandler.Show)
	e.POST("/api/v1/scans", handler.CreateScanRequest)
	e.GET("/api/v1/scans", handler.ListScans)
	e.GET("/api/v1/sast/policy", handler.GetPolicy)
	e.PUT("/api/v1/sast/policy", func(c *echo.Context) error {
		if _, err := userID(c.Request()); err != nil { return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()}) }
		return handler.PutPolicy(c)
	})
	e.GET("/api/v1/workers", handler.ListWorkers)
	e.GET("/api/v1/scans/:id", handler.GetScan)
	e.DELETE("/api/v1/scans/:id", handler.DeleteScan)
	e.GET("/api/v1/scans/:id/findings", handler.GetScanFindings)
	e.DELETE("/api/v1/scans/:id/findings", handler.DeleteScanFindings)
	dastRoutes := e.Group("/api/v1/dast")
	dastRoutes.GET("/assets", dastHandler.ListAssets)
	dastRoutes.POST("/assets", dastHandler.CreateAsset)
	dastRoutes.POST("/scans", dastHandler.CreateScan)
	dastRoutes.GET("/scans", dastHandler.ListScans)
	dastRoutes.POST("/scans/:id/cancel", dastHandler.CancelScan)
	dastRoutes.GET("/scans/:id", dastHandler.GetScan)
	dastRoutes.GET("/tasks/:id", dastHandler.GetTask)
	dastRoutes.GET("/scans/:id/findings", dastHandler.ListFindings)
	dastRoutes.GET("/workers", dastHandler.ListWorkers)
	
	// poc 路由注册
	pocService := poc.New(db, rdb, poc.Config{
		GitHubToken: os.Getenv("GITHUB_TOKEN"),
		Agent: infra.AgentConfig{Protocol: os.Getenv("AI_PROTOCOL"), BaseURL: os.Getenv("AI_BASE_URL"), Model: os.Getenv("AI_MODEL"), APIKey: os.Getenv("AI_API_KEY")},
	})
	pocRoutes := e.Group("/api/v1/dast", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if _, err := userID(c.Request()); err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
			}
			return next(c)
		}
	})
	pocService.Register(pocRoutes)
	go func() {
		if err := pocService.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("PoC jobs stopped: %v", err)
		}
	}()
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
