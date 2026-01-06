package redis

import (
	"auth/internal/config"
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"time"
)

type Client interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Incr(ctx context.Context, key string) *redis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	SMembers(ctx context.Context, key string) *redis.StringSliceCmd
	SRem(ctx context.Context, key string, members ...interface{}) *redis.IntCmd
}

func NewClient(ctx context.Context, maxAttempts int, sc config.StorageRedis) (client *redis.Client, err error) {

	// Попытки подключиться с повторениями в случае неудачи
	err = doWithTries(func() error {
		// Создаем новый контекст с таймаутом
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Создаем новый Redis клиент
		client = redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%s", sc.Host, sc.Port),
			Password: sc.Password,
			DB:       0,
		})

		_, err := client.Ping(ctx).Result()
		if err != nil {
			return err
		}
		return nil
	}, maxAttempts, 5*time.Second)

	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis after %d attempts: %w", maxAttempts, err)
	}

	return client, nil
}

func doWithTries(fn func() error, attempts int, delay time.Duration) (err error) {
	for attempts > 0 {
		if err = fn(); err != nil {
			time.Sleep(delay)

			attempts--

			continue
		}
		return nil
	}
	return
}
