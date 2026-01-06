package grpc

import (
	grpcAuth "auth/internal/grpc/auth"
	"fmt"
	"google.golang.org/grpc"
	"log/slog"
	"net"
)

type App struct {
	log  *slog.Logger
	grpc *grpc.Server
	port int
}

func New(log *slog.Logger, server grpcAuth.Auth, port int) *App {
	grpcServer := grpc.NewServer()
	grpcAuth.Register(grpcServer, server)

	return &App{log: log, grpc: grpcServer, port: port}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("grpc server started", slog.String("addr", l.Addr().String()))

	if err := a.grpc.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// Stop stops gRPC server.
func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).
		Info("stopping gRPC server", slog.Int("port", a.port))

	a.grpc.GracefulStop()
}
