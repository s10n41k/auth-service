package storage

import (
	"auth/internal/model"
	"context"
)

type Storage interface {
	Save(ctx context.Context, userId string, refreshToken string) error
	Get(ctx context.Context, userId string) (string, error)
	IncrementTokenVersion(ctx context.Context, session string) (int, error)
	GetTokenVersion(ctx context.Context, session string) (int, error)
	DeleteVersionToken(ctx context.Context, session string) error
	DeleteRefreshToken(ctx context.Context, session string) error

	AddSession(ctx context.Context, userID, deviceID string) error
	RemoveSession(ctx context.Context, userID, deviceID string) error
	GetUserSessions(ctx context.Context, userID string) ([]string, error) // возвращает deviceIDs
	DeleteAllSessions(ctx context.Context, userID string) error

	SaveTemporarySession(ctx context.Context, userTemporary *model.UserTemporary) error
	GetTemporarySession(ctx context.Context, session string) (*model.UserTemporary, error)
	DeleteTemporarySession(ctx context.Context, session string) error
}
