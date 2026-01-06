package tests

import (
	"auth/internal/tests/suite"
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/s10n41k/protos/gen/go/sso"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"strings"
	"testing"
)

func TestLogout_HappyPath(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testAccessToken = "valid-access-token"
		testSessionID   = "user-123:device-123"
		testUserID      = "user-123"
		testDeviceID    = "device-123"
	)

	// 1. Мок верификации токена
	s.MockToken.On("VerifyAccessToken", testAccessToken).
		Return(jwt.MapClaims{
			"session": testSessionID,
			"ver":     1.0,
		}, nil).
		Once()

	// 2. Мок получения версии токена из Redis
	s.MockStorage.On("GetTokenVersion", mock.Anything, testSessionID).
		Return(1, nil).
		Once()

	// 3. Моки удаления из Redis
	s.MockStorage.On("RemoveSession", mock.Anything, testUserID, testDeviceID).
		Return(nil).
		Once()
	s.MockStorage.On("DeleteRefreshToken", mock.Anything, testSessionID).
		Return(nil).
		Once()
	s.MockStorage.On("DeleteVersionToken", mock.Anything, testSessionID).
		Return(nil).
		Once()

	// 4. СОЗДАЕМ КОНТЕКСТ С МЕТАДАННЫМИ
	// Добавляем токен в метаданные как в реальном запросе
	md := metadata.Pairs("authorization", "Bearer "+testAccessToken)
	ctxWithMetadata := metadata.NewOutgoingContext(ctx, md)

	// 5. Вызываем метод (теперь запрос пустой, т.к. токен в метаданных)
	_, err := s.Client.Logout(ctxWithMetadata, &sso.LogoutRequest{})

	// 6. Проверяем результат
	require.NoError(t, err)

	// 7. Проверяем моки
	s.MockToken.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
}

func TestLogout_MissingMetadata(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	// 1. Вызываем без метаданных вообще
	_, err := s.Client.Logout(ctx, &sso.LogoutRequest{})

	// 2. Проверяем ошибку
	require.Error(t, err)

	grpcErr, ok := status.FromError(err)
	require.True(t, ok, "Should return gRPC status error")
	require.Equal(t, codes.InvalidArgument, grpcErr.Code())
	require.Contains(t, strings.ToLower(grpcErr.Message()), "missing")

	// 3. Моки не должны вызываться
	s.MockToken.AssertNotCalled(t, "VerifyAccessToken")
	s.MockStorage.AssertNotCalled(t, "GetTokenVersion")
	s.MockStorage.AssertNotCalled(t, "RemoveSession")
}
