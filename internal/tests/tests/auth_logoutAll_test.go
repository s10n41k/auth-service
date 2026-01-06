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

// ===================== ТЕСТЫ НА УСПЕШНЫЕ СЦЕНАРИИ =====================

func TestLogoutAll_HappyPath_MultipleSessions(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testAccessToken = "valid-access-token"
		testSessionID   = "user-123:device-123"
		testUserID      = "user-123"
	)

	// Список активных сессий пользователя
	deviceIDs := []string{"device-123", "device-456", "device-789"}
	sessionIDs := []string{
		"user-123:device-123",
		"user-123:device-456",
		"user-123:device-789",
	}

	// 1. Мок верификации токена
	s.MockToken.On("VerifyAccessToken", testAccessToken).
		Return(jwt.MapClaims{
			"session": testSessionID,
		}, nil).
		Once()

	// 2. Мок получения всех сессий пользователя
	s.MockStorage.On("GetUserSessions", mock.Anything, testUserID).
		Return(deviceIDs, nil).
		Once()

	// 3. Моки удаления refresh токенов для каждой сессии
	for _, sessionID := range sessionIDs {
		s.MockStorage.On("DeleteRefreshToken", mock.Anything, sessionID).
			Return(nil).
			Once()
	}

	// 4. Моки удаления версий токенов для каждой сессии
	for _, sessionID := range sessionIDs {
		s.MockStorage.On("DeleteVersionToken", mock.Anything, sessionID).
			Return(nil).
			Once()
	}

	// 5. Мок удаления списка сессий
	s.MockStorage.On("DeleteAllSessions", mock.Anything, testUserID).
		Return(nil).
		Once()

	// 6. Создаем контекст с метаданными
	md := metadata.Pairs("authorization", "Bearer "+testAccessToken)
	ctxWithMetadata := metadata.NewOutgoingContext(ctx, md)

	// 7. Вызываем метод
	_, err := s.Client.LogoutAll(ctxWithMetadata, &sso.LogoutAllRequest{})

	// 8. Проверяем результат
	require.NoError(t, err)

	// 9. Проверяем моки
	s.MockToken.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
}

func TestLogoutAll_HappyPath_NoActiveSessions(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testAccessToken = "valid-access-token"
		testSessionID   = "user-123:device-123"
		testUserID      = "user-123"
	)

	// 1. Мок верификации токена
	s.MockToken.On("VerifyAccessToken", testAccessToken).
		Return(jwt.MapClaims{
			"session": testSessionID,
		}, nil).
		Once()

	// 2. Мок получения всех сессий - пустой список
	s.MockStorage.On("GetUserSessions", mock.Anything, testUserID).
		Return([]string{}, nil).
		Once()

	// 3. DeleteAllSessions НЕ должен вызываться для пустого списка
	// (согласно реализации метода LogoutAll)

	// 4. Создаем контекст с метаданными
	md := metadata.Pairs("authorization", "Bearer "+testAccessToken)
	ctxWithMetadata := metadata.NewOutgoingContext(ctx, md)

	// 5. Вызываем метод
	_, err := s.Client.LogoutAll(ctxWithMetadata, &sso.LogoutAllRequest{})

	// 6. Проверяем результат
	require.NoError(t, err)

	// 7. Проверяем моки
	s.MockToken.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
	s.MockStorage.AssertNotCalled(t, "DeleteRefreshToken")
	s.MockStorage.AssertNotCalled(t, "DeleteVersionToken")
	s.MockStorage.AssertNotCalled(t, "DeleteAllSessions")
}

func TestLogoutAll_HappyPath_SingleSession(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testAccessToken = "valid-access-token"
		testSessionID   = "user-123:device-123"
		testUserID      = "user-123"
	)

	deviceIDs := []string{"device-123"}

	// 1. Мок верификации токена
	s.MockToken.On("VerifyAccessToken", testAccessToken).
		Return(jwt.MapClaims{
			"session": testSessionID,
		}, nil).
		Once()

	// 2. Мок получения всех сессий
	s.MockStorage.On("GetUserSessions", mock.Anything, testUserID).
		Return(deviceIDs, nil).
		Once()

	// 3. Моки удаления для одной сессии
	s.MockStorage.On("DeleteRefreshToken", mock.Anything, testSessionID).
		Return(nil).
		Once()
	s.MockStorage.On("DeleteVersionToken", mock.Anything, testSessionID).
		Return(nil).
		Once()

	// 4. Мок удаления списка сессий
	s.MockStorage.On("DeleteAllSessions", mock.Anything, testUserID).
		Return(nil).
		Once()

	// 5. Создаем контекст с метаданными
	md := metadata.Pairs("authorization", "Bearer "+testAccessToken)
	ctxWithMetadata := metadata.NewOutgoingContext(ctx, md)

	// 6. Вызываем метод
	_, err := s.Client.LogoutAll(ctxWithMetadata, &sso.LogoutAllRequest{})

	// 7. Проверяем результат
	require.NoError(t, err)

	// 8. Проверяем моки
	s.MockToken.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
}

// ===================== ТЕСТЫ НА СЦЕНАРИИ С ОШИБКАМИ =====================

func TestLogoutAll_MissingMetadata(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	// 1. Вызываем без метаданных
	_, err := s.Client.LogoutAll(ctx, &sso.LogoutAllRequest{})

	// 2. Проверяем ошибку
	require.Error(t, err)

	grpcErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, grpcErr.Code())
	require.Contains(t, strings.ToLower(grpcErr.Message()), "missing")

	// 3. Моки не должны вызываться
	s.MockToken.AssertNotCalled(t, "VerifyAccessToken")
	s.MockStorage.AssertNotCalled(t, "GetUserSessions")
}

func TestLogoutAll_MissingAuthorizationHeader(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	// 1. Контекст без authorization header
	md := metadata.Pairs("content-type", "application/grpc")
	ctxWithMetadata := metadata.NewOutgoingContext(ctx, md)

	// 2. Вызываем метод
	_, err := s.Client.LogoutAll(ctxWithMetadata, &sso.LogoutAllRequest{})

	// 3. Проверяем ошибку
	require.Error(t, err)

	grpcErr, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, grpcErr.Code())
	require.Contains(t, strings.ToLower(grpcErr.Message()), "token")

	// 4. Моки не должны вызываться
	s.MockToken.AssertNotCalled(t, "VerifyAccessToken")
	s.MockStorage.AssertNotCalled(t, "GetUserSessions")
}
