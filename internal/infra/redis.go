package infra

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
)

func ConnectRedis(c context.Context, addr, password string, db int) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
		Password: password,
		DB: db,
		ContextTimeoutEnabled: true,
	})

	if err := rdb.Ping(c).Err(); err != nil {
		rdb.Close()
		return nil,err
	}
	fmt.Print("redis init success")
	return rdb,nil
}