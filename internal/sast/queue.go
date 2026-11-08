package sast

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const scanQueueKey = "sast:scan:queue"

type Queue struct {
	redis *redis.Client
}

func NewQueue(rdb *redis.Client) *Queue {
	return &Queue{
		redis: rdb,
	}
}

func (q *Queue) Push(c context.Context, scanID uint64) error {
	err := q.redis.LPush(c, scanQueueKey, strconv.FormatUint(scanID, 10)).Err()
	if err != nil {
		return fmt.Errorf("push scan to queue: %w", err)
	}
	return nil
}

func (q *Queue) Pop(c context.Context) (scanID uint64, err error) {
	for {
		if err := c.Err(); err != nil {
			return 0, err
		}
		result, err := q.redis.BRPop(c, 2*time.Second, scanQueueKey).Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("pop scan queue: %w", errors.Join(err, c.Err()))
		}
		if len(result) != 2 {
			return 0, fmt.Errorf("invalid scan queue response: %v", result)
		}
		scanID, err := strconv.ParseUint(result[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse scan ID: %w", err)
		}
		if scanID == 0 {
			return 0, errors.New("scan ID must be positive")
		}
		return scanID, nil
	}
}
