package config

import (
	"fmt"
	"os"
	"strconv"

	"devsecops/internal/dast"
	"devsecops/internal/sast"
	"github.com/joho/godotenv"
)

type Config struct {
	AppName    string
	ServerAddr string
	ServerPort int
	WorkerID   string

	Postgres    PostgresConfig
	Redis       RedisConfig
	SASTScanner sast.SASTScanner
	DASTScanner dast.DASTScannerConfig
	DASTServer  dast.ServerConfig
	DASTWorker  dast.WorkerConfig
}

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Database string
	Password string
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

func envInt(key string) (int, error) {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return 0, fmt.Errorf("load %s : %w ", key, err)
	}
	return value, nil
}

func LoadEnv() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("load .env : %w ", err)
	}

	serverPort, err := envInt("SERVER_PORT")
	if err != nil {
		return nil, err
	}

	postgresPort, err := envInt("POSTGRES_PORT")
	if err != nil {
		return nil, err
	}

	redisPort, err := envInt("REDIS_PORT")
	if err != nil {
		return nil, err
	}

	redisDB, err := envInt("REDIS_DB")
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		AppName:    os.Getenv("APP_NAME"),
		ServerAddr: os.Getenv("SERVER_ADDR"),
		ServerPort: serverPort,
		WorkerID:   os.Getenv("WORKER_ID"),
		Postgres: PostgresConfig{
			Host:     os.Getenv("POSTGRES_HOST"),
			Port:     postgresPort,
			User:     os.Getenv("POSTGRES_USER"),
			Password: os.Getenv("POSTGRES_PASSWORD"),
			Database: os.Getenv("POSTGRES_DATABASE"),
		},
		Redis: RedisConfig{
			Host:     os.Getenv("REDIS_HOST"),
			Port:     redisPort,
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       redisDB,
		},
		SASTScanner: sast.SASTScanner{
			CodeQLPath: os.Getenv("CODEQL_PATH"),
			WorkRoot:   os.Getenv("WORK_ROOT"),
			QuerySuite: os.Getenv("QUERY_SUITE"),
		},
		DASTScanner: dast.DASTScannerConfig{
			NmapPath:     os.Getenv("DAST_NMAP_PATH"),
			NucleiPath:   os.Getenv("DAST_NUCLEI_PATH"),
			TemplateRoot: os.Getenv("DAST_TEMPLATE_ROOT"),
		},
		DASTServer: dast.ServerConfig{
			ResultRoot: os.Getenv("DAST_RESULT_ROOT"),
		},
		DASTWorker: dast.WorkerConfig{
			ClusterID:   os.Getenv("DAST_CLUSTER_ID"),
			NetworkZone: os.Getenv("DAST_NETWORK_ZONE"),
		},
	}

	return cfg, nil
}
