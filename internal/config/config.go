package config

import "fmt"
import "os"
import "strconv"
import "github.com/joho/godotenv"
import "devsecops/internal/sast"

type Config struct {
	AppName    string
	ServerAddr string
	ServerPort int
	WorkerID   string

	Postgres    PostgresConfig
	Redis       RedisConfig
	SASTScanner sast.SASTScanner
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

func LoadEnv() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("load .env : %w ", err)
	}

	serverPort, err := strconv.Atoi(os.Getenv("SERVER_PORT"))
	if err != nil {
		return nil, fmt.Errorf("load SERVER_PORT : %w ", err)
	}

	postgresPort, err := strconv.Atoi(os.Getenv("POSTGRES_PORT"))
	if err != nil {
		return nil, fmt.Errorf("load POSTGRES_PORT : %w ", err)
	}

	redisPort, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
	if err != nil {
		return nil, fmt.Errorf("load REDIS_PORT : %w ", err)
	}

	redisDB, err := strconv.Atoi(os.Getenv("REDIS_DB"))
	if err != nil {
		return nil, fmt.Errorf("load REDIS_DB : %w ", err)
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
	}

	return cfg, nil
}
