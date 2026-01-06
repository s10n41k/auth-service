package redis

import (
	"auth/internal/model"
	"auth/internal/storage"
	"auth/pkg/client/redis"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	redis2 "github.com/redis/go-redis/v9"
	"strconv"
	"time"
)

type repositoryRedis struct {
	Client     redis.Client
	RefreshTTL time.Duration
}

func NewRepositoryRedis(client redis.Client, RefreshTTl time.Duration) storage.Storage {
	return &repositoryRedis{Client: client, RefreshTTL: RefreshTTl}
}

func (r *repositoryRedis) Save(ctx context.Context, userId string, refreshToken string) error {
	token, err := json.Marshal(refreshToken)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("session:%s", userId)

	res := r.Client.Set(ctx, key, token, r.RefreshTTL)
	if res.Err() != nil {
		return err
	}

	return nil
}

func (r *repositoryRedis) DeleteRefreshToken(ctx context.Context, session string) error {

	key := fmt.Sprintf("session:%s", session)

	err := r.Client.Del(ctx, key).Err()
	if err != nil {
		return err
	}

	return nil
}

func (r *repositoryRedis) Get(ctx context.Context, userId string) (token string, err error) {
	key := fmt.Sprintf("session:%s", userId)

	res := r.Client.Get(ctx, key)
	if res.Err() != nil {
		return "", res.Err()
	}
	err = json.Unmarshal([]byte(res.Val()), &token)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (r *repositoryRedis) GetTokenVersion(ctx context.Context, userID string) (int, error) {
	key := fmt.Sprintf("token_ver:%s", userID)

	val, err := r.Client.Get(ctx, key).Result()
	if errors.Is(err, redis2.Nil) {
		// Если ключа нет - версия 1
		return 1, nil
	}
	if err != nil {
		return 0, err
	}

	version, _ := strconv.Atoi(val)
	return version, nil
}

// IncrementTokenVersion - атомарно увеличивает версию токенов пользователя
func (r *repositoryRedis) IncrementTokenVersion(ctx context.Context, userID string) (int, error) {
	key := fmt.Sprintf("token_ver:%s", userID)

	// Атомарное увеличение
	newVersion, err := r.Client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Устанавливаем TTL (совпадает с refresh TTL)
	r.Client.Expire(ctx, key, r.RefreshTTL)

	return int(newVersion), nil
}

func (r *repositoryRedis) DeleteVersionToken(ctx context.Context, session string) error {
	key := fmt.Sprintf("token_ver:%s", session)
	err := r.Client.Del(ctx, key).Err()
	if err != nil {
		return err
	}
	return nil
}

func (r *repositoryRedis) AddSession(ctx context.Context, userID, deviceID string) error {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return r.Client.SAdd(ctx, key, deviceID).Err()
}

func (r *repositoryRedis) RemoveSession(ctx context.Context, userID, deviceID string) error {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return r.Client.SRem(ctx, key, deviceID).Err()
}

func (r *repositoryRedis) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return r.Client.SMembers(ctx, key).Result()
}

func (r *repositoryRedis) DeleteAllSessions(ctx context.Context, userID string) error {
	key := fmt.Sprintf("user_sessions:%s", userID)
	return r.Client.Del(ctx, key).Err()
}

func (r *repositoryRedis) SaveTemporarySession(ctx context.Context, userTemporary *model.UserTemporary) error {
	key := userTemporary.SessionId

	user, err := json.Marshal(userTemporary)
	if err != nil {
		return err
	}

	r.Client.Set(ctx, key, user, 3*time.Minute)

	return nil
}

func (r *repositoryRedis) GetTemporarySession(ctx context.Context, session string) (user *model.UserTemporary, err error) {
	res := r.Client.Get(ctx, session)
	if res.Err() != nil {
		return nil, res.Err()
	}
	err = json.Unmarshal([]byte(res.Val()), &user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *repositoryRedis) DeleteTemporarySession(ctx context.Context, session string) error {
	err := r.Client.Del(ctx, session).Err()
	if err != nil {
		return err
	}
	return nil
}
