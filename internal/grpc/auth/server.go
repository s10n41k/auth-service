package auth

import (
	"auth/internal/model"
	"auth/internal/provider"
	"context"
	"errors"
	"fmt"
	"github.com/s10n41k/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"log/slog"
	"strings"
)

type Auth interface {
	Login(ctx context.Context, email string, password string, deviceID string) (token *model.Token, err error)
	RegisterNewUser(ctx context.Context, email string, name, password string) (session string, err error)
	VerifyEmail(ctx context.Context, session string, code string) (userID string, err error)
	GetRefreshToken(ctx context.Context, refreshToken string) (*model.Token, error)
	Logout(ctx context.Context, accessToken string) error
	LogoutAll(ctx context.Context, accessToken string) error
}
type serverApi struct {
	sso.UnimplementedAuthServer
	auth Auth
}

func Register(server *grpc.Server, auth Auth) {
	sso.RegisterAuthServer(server, &serverApi{auth: auth})
}

func (s *serverApi) Register(ctx context.Context, in *sso.RegisterRequest) (*sso.RegisterResponse, error) {
	if in.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing email")
	}
	if in.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing password")
	}

	uid, err := s.auth.RegisterNewUser(ctx, in.GetEmail(), in.GetName(), in.GetPassword())
	if err != nil {
		if errors.Is(err, provider.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &sso.RegisterResponse{Session: uid}, nil
}

func (s *serverApi) Login(ctx context.Context, in *sso.LoginRequest) (*sso.LoginResponse, error) {
	// Логируем запрос
	slog.Debug("gRPC Login called",
		slog.String("email", in.GetEmail()),
		slog.String("remote_addr", getClientIP(ctx)))

	if in.GetEmail() == "" {
		slog.Warn("Missing email in request")
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	if in.GetPassword() == "" {
		slog.Warn("Missing password in request")
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if in.GetDeviceID() == "" {
		slog.Warn("Missing device id in request")
		return nil, status.Error(codes.InvalidArgument, "device id is required")
	}

	// Вызываем бизнес-логику
	token, err := s.auth.Login(ctx, in.GetEmail(), in.GetPassword(), in.GetDeviceID())

	if err != nil {
		if errors.Is(err, provider.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		if errors.Is(err, provider.ErrMissingData) {
			return nil, status.Error(codes.InvalidArgument, "missing data")
		}
		if errors.Is(err, provider.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	// Проверяем что токен не nil
	if token == nil {
		slog.Error("Token is nil after successful login")
		return nil, status.Error(codes.Internal, "internal error")
	}

	if token.AccessToken == "" {
		slog.Error("Empty access token")
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Успешный ответ
	slog.Info("Login successful",
		slog.String("email", in.GetEmail()),
		slog.Int("token_length", len(token.AccessToken)))

	return &sso.LoginResponse{
		TokenAccess:  token.AccessToken,
		TokenRefresh: token.RefreshToken,
	}, nil
}

// Вспомогательная функция для получения IP
func getClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}

func (s *serverApi) GetAccessToken(ctx context.Context, request *sso.TokenRequest) (*sso.TokenResponse, error) {

	if request.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "missing refresh token")
	}

	token, err := s.auth.GetRefreshToken(ctx, request.GetRefreshToken())
	if err != nil {
		return nil, err
	}

	if token.AccessToken == "" {
		return nil, status.Error(codes.PermissionDenied, "failed to get access token")
	}
	if token.RefreshToken == "" {
		return nil, status.Error(codes.PermissionDenied, "failed to get refresh token")
	}

	if request.RefreshToken == token.RefreshToken {
		return nil, status.Error(codes.PermissionDenied, "failed to get refresh token")
	}

	return &sso.TokenResponse{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken}, nil
}

func (s *serverApi) Logout(ctx context.Context, request *sso.LogoutRequest) (*sso.LogoutResponse, error) {
	incomingContext, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing incoming context")
	}
	tokens := incomingContext.Get("Authorization")
	if len(tokens) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing token")
	}

	// ИСПРАВЛЕНО: добавляем пробел после Bearer
	token := strings.TrimPrefix(tokens[0], "Bearer ")

	// Также хорошо бы удалить возможные пробелы:
	token = strings.TrimSpace(token)

	err := s.auth.Logout(ctx, token)
	if err != nil {
		fmt.Println(err)
		return nil, status.Error(codes.Internal, "failed to logout")
	}
	return &sso.LogoutResponse{}, nil
}
func (s *serverApi) LogoutAll(ctx context.Context, request *sso.LogoutAllRequest) (*sso.LogoutAllResponse, error) {
	incomingContext, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing incoming context")
	}
	tokens := incomingContext.Get("Authorization")
	if len(tokens) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing token")
	}

	// ИСПРАВЛЕНО: добавить пробел после Bearer
	token := strings.TrimPrefix(tokens[0], "Bearer ")
	token = strings.TrimSpace(token) // дополнительно удалить пробелы

	err := s.auth.LogoutAll(ctx, token)
	if err != nil {
		fmt.Println(err)
		return nil, status.Error(codes.Internal, "failed to logoutAll")
	}
	return &sso.LogoutAllResponse{}, nil
}

func (s *serverApi) VerifyEmail(ctx context.Context, request *sso.VerifyEmailRequest) (*sso.VerifyEmailResponse, error) {
	if request.Session == "" {
		return nil, status.Error(codes.InvalidArgument, "missing session")
	}

	if request.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "missing code")
	}

	userID, err := s.auth.VerifyEmail(ctx, request.Session, request.Code)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to verify")
	}

	return &sso.VerifyEmailResponse{UserId: userID}, nil
}
