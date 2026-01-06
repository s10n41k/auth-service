package tests

import (
	"auth/internal/model"
	"auth/internal/tests/suite"
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/s10n41k/protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetRefreshToken_HappyPath(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		oldRefreshToken = "old-refresh-token-123"
		sessionID       = "user-123:iphone-13"
		userID          = "user-123"
		userName        = "John Doe"
		userEmail       = "john@example.com"
		userRole        = "user"
	)

	// 1. Настраиваем моки
	claims := jwt.MapClaims{
		"session": sessionID,
	}
	s.MockToken.On("VerifyRefreshToken", oldRefreshToken).
		Return(claims, nil).
		Once()

	s.MockStorage.On("Get", mock.Anything, sessionID).
		Return(oldRefreshToken, nil).
		Once()

	s.MockProvider.On("FindOneUsers", mock.Anything, userID).
		Return(&model.UserRefresh{
			UserID: userID,
			Name:   userName,
			Email:  userEmail,
			Role:   userRole,
		}, nil).
		Once()

	s.MockStorage.On("IncrementTokenVersion", mock.Anything, sessionID).
		Return(2, nil).
		Once()

	var capturedUserRefresh *model.UserRefresh
	s.MockToken.On("GenerateAccessToken", mock.Anything).
		Run(func(args mock.Arguments) {
			capturedUserRefresh = args.Get(0).(*model.UserRefresh)
		}).
		Return("new-access-token-456", nil).
		Once()

	s.MockToken.On("GenerateRefreshToken", sessionID).
		Return("new-refresh-token-789", nil).
		Once()

	s.MockStorage.On("Save", mock.Anything, sessionID, "new-refresh-token-789").
		Return(nil).
		Once()

	// 2. Вызываем
	resp, err := s.Client.GetAccessToken(ctx, &sso.TokenRequest{
		RefreshToken: oldRefreshToken,
	})

	// 3. Проверяем
	require.NoError(t, err, "GetRefreshToken should succeed")
	require.NotNil(t, resp, "Response should not be nil")

	assert.Equal(t, "new-access-token-456", resp.GetAccessToken())
	assert.Equal(t, "new-refresh-token-789", resp.GetRefreshToken())

	require.NotNil(t, capturedUserRefresh)
	assert.Equal(t, sessionID, capturedUserRefresh.SessionId)
	assert.Equal(t, userID, capturedUserRefresh.UserID)
	assert.Equal(t, 2, capturedUserRefresh.Version)
	assert.Equal(t, userName, capturedUserRefresh.Name)
	assert.Equal(t, userEmail, capturedUserRefresh.Email)
	assert.Equal(t, userRole, capturedUserRefresh.Role)

	s.MockToken.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
	s.MockProvider.AssertExpectations(t)
}

func TestGetRefreshToken_ExpiredToken(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		oldRefreshToken = "expired_refresh_token"
	)

	// 1. Настраиваем моки для сценария просроченного токена
	s.MockToken.On("VerifyRefreshToken", oldRefreshToken).
		Return(nil, fmt.Errorf("token expired")).
		Once()

	// 2. Вызываем метод
	resp, err := s.Client.GetAccessToken(ctx, &sso.TokenRequest{
		RefreshToken: oldRefreshToken,
	})

	// 3. Проверяем результаты
	require.Error(t, err, "GetRefreshToken should fail with expired token")
	require.Nil(t, resp, "Response should be nil on error")

	// Исправленная проверка сообщения ошибки
	require.ErrorContains(t, err, "token expired",
		"Error should contain 'token expired' message")

	// 4. Проверяем, что определённые методы НЕ вызывались
	s.MockToken.AssertNotCalled(t, "GenerateAccessToken")
	s.MockToken.AssertNotCalled(t, "GenerateRefreshToken")
	s.MockStorage.AssertNotCalled(t, "Get") // Redis.Get
	s.MockStorage.AssertNotCalled(t, "IncrementTokenVersion")
	s.MockStorage.AssertNotCalled(t, "Save")
	s.MockProvider.AssertNotCalled(t, "FindOneUsers")

	// 5. Проверяем, что ожидаемые методы были вызваны
	s.MockToken.AssertExpectations(t)
}
