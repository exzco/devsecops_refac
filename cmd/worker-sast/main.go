package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"devsecops/internal/config"
	"devsecops/internal/infra"
	"devsecops/internal/sast"
)

func main() {
	// run 返回前会执行资源清理，之后 main 才决定退出码。
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	workerID := strings.TrimSpace(cfg.WorkerID)
	if workerID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("get worker hostname: %w", err)
		}
		workerID = "sast-" + hostname + "-" + rand.Text()
	}
	if strings.TrimSpace(cfg.SASTScanner.WorkRoot) == "" {
		return fmt.Errorf("WORK_ROOT is required")
	}
	if err := os.MkdirAll(cfg.SASTScanner.WorkRoot, 0700); err != nil {
		return fmt.Errorf("create scan work root: %w", err)
	}

	startupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dsn := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.Postgres.User, cfg.Postgres.Password),
		Host:     net.JoinHostPort(cfg.Postgres.Host, strconv.Itoa(cfg.Postgres.Port)),
		Path:     "/" + cfg.Postgres.Database,
		RawQuery: "sslmode=disable",
	}
	db, err := infra.ConnectDB(startupCtx, dsn.String())
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer db.Close()

	rdb, err := infra.ConnectRedis(startupCtx, cfg.Redis.Host, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	defer rdb.Close()

	// 退出时关闭客户端，解除正在进行的 Redis 网络读取。
	stopRedisClose := context.AfterFunc(ctx, func() {
		_ = rdb.Close()
	})
	defer stopRedisClose()

	store := sast.NewStore(db)
	queue := sast.NewQueue(rdb)
	scanner := sast.NewSASTScanner(cfg.SASTScanner)
	service := sast.NewService(store, queue, scanner)
	worker := sast.NewWorker(workerID, service)

	log.Printf("SAST worker started: id=%s", workerID)
	if err := worker.Run(ctx); err != nil {
		return err
	}
	log.Printf("SAST worker stopped: id=%s", workerID)
	return nil
}
