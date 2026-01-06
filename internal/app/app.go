package app

import (
	"auth/internal/app/grpc"
	"auth/internal/config"
	"auth/internal/provider/users"
	redis2 "auth/internal/redis"
	"auth/internal/sender"
	"auth/internal/servises/auth"
	"auth/internal/token"
	"auth/pkg/client/redis"
	"context"
	"log/slog"
)

type App struct {
	GRPCServer *grpc.App
}

func New(ctx context.Context, cfg config.Config, log *slog.Logger) *App {

	client, err := redis.NewClient(ctx, 5, cfg.Redis)
	if err != nil {
		return nil
	}
	repositoryRedis := redis2.NewRepositoryRedis(client, cfg.Token.RefreshTTL)

	provider := users.NewUsersProvider(cfg.Provider.Protocol, cfg.Provider.Host, cfg.Provider.Port, *log)
	manager := token.NewJWTManager(cfg.Token.RefreshSecret, cfg.Token.AccessSecret, cfg.Token.AccessTTL, cfg.Token.RefreshTTL)

	smtp, err := sender.NewEmailSender(cfg.SMTPConfig)
	if err != nil {
		return nil
	}

	server := auth.NewServer(provider, manager, repositoryRedis, smtp, *log)

	app := grpc.New(log, server, cfg.GRPCConfig.Port)

	return &App{
		GRPCServer: app,
	}

}
