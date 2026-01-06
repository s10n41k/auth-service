package tests

import (
	"auth/internal/model"
	"auth/internal/provider"
	"auth/internal/tests/suite"
	"context"
	"github.com/s10n41k/protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestLogin_HappyPath(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testEmail    = "test@gmail.com"
		testPassword = "Password123"
		testDeviceID = "device-123"
		testUserID   = "user-123"
	)

	// 1. Переменная для захвата UserRefresh
	var capturedUserRefresh *model.UserRefresh

	// 2. Настраиваем моки
	s.MockProvider.On("LoginUsers", mock.Anything, testEmail, testPassword).
		Return(&model.User{
			UserID: testUserID,
			Name:   "Test User",
			Email:  testEmail,
			Role:   "user",
		}, nil).
		Once()

	s.MockStorage.On("AddSession", mock.Anything, testUserID, testDeviceID).
		Return(nil).
		Once()

	sessionKey := testUserID + ":" + testDeviceID
	s.MockStorage.On("IncrementTokenVersion", mock.Anything, sessionKey).
		Return(1, nil).
		Once()

	// 3. Мок токена с ПЕРЕХВАТОМ аргументов
	s.MockToken.On("GenerateAccessToken", mock.Anything).
		Run(func(args mock.Arguments) {
			// Захватываем UserRefresh для проверки
			capturedUserRefresh = args.Get(0).(*model.UserRefresh)
		}).
		Return("access-token-123", nil).
		Once()

	s.MockToken.On("GenerateRefreshToken", sessionKey).
		Return("refresh-token-456", nil).
		Once()

	s.MockStorage.On("Save", mock.Anything, sessionKey, "refresh-token-456").
		Return(nil).
		Once()

	// 4. Вызываем
	resp, err := s.Client.Login(ctx, &sso.LoginRequest{
		Email:    testEmail,
		Password: testPassword,
		DeviceID: testDeviceID,
	})

	// 5. Проверяем gRPC ответ
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "access-token-123", resp.GetTokenAccess())
	assert.Equal(t, "refresh-token-456", resp.GetTokenRefresh())

	// 6. Проверяем структуру UserRefresh ПРЯМО В ТЕСТЕ
	require.NotNil(t, capturedUserRefresh, "UserRefresh should be passed to GenerateAccessToken")
	assert.Equal(t, sessionKey, capturedUserRefresh.SessionId)
	assert.Equal(t, testUserID, capturedUserRefresh.UserID)
	assert.Equal(t, 1, capturedUserRefresh.Version)
	assert.Equal(t, "Test User", capturedUserRefresh.Name)
	assert.Equal(t, testEmail, capturedUserRefresh.Email)
	assert.Equal(t, "user", capturedUserRefresh.Role)

	// 7. Проверяем моки
	s.MockProvider.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
	s.MockToken.AssertExpectations(t)
}

func TestLogin_UserNotFound(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		nonexistentEmail = "ghostuser@notfound.com"
		testPassword     = "SomePassword123"
		testDeviceID     = "device-123"
	)

	// 1. Provider говорит: пользователь с таким email не найден
	s.MockProvider.On("LoginUsers",
		mock.Anything,                         // любой context
		nonexistentEmail,                      // именно этот email
		testPassword).                         // именно этот пароль
		Return(nil, provider.ErrUserNotFound). // ОШИБКА!
		Once()                                 // должен быть вызван ровно 1 раз

	// 2. Вызываем gRPC Login
	resp, err := s.Client.Login(ctx, &sso.LoginRequest{
		Email:    nonexistentEmail,
		Password: testPassword,
		DeviceID: testDeviceID,
	})

	// 3. Проверяем результат
	require.Error(t, err, "Should return error for non-existent user")
	assert.Nil(t, resp, "Response should be nil on error")

	grpcErr, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status error")

	assert.Equal(t, codes.NotFound, grpcErr.Code(),
		"Should return NotFound for non-existent user")
	assert.Contains(t, grpcErr.Message(), "user",
		"Error message should mention user")

	s.MockStorage.AssertNotCalled(t, "AddSession")
	s.MockStorage.AssertNotCalled(t, "IncrementTokenVersion")
	s.MockToken.AssertNotCalled(t, "GenerateAccessToken")
	s.MockToken.AssertNotCalled(t, "GenerateRefreshToken")
	s.MockStorage.AssertNotCalled(t, "Save")

	s.MockProvider.AssertExpectations(t)
}

func TestLogin_NoValidPassword(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		nonexistentEmail = "ghostuser@notfound.com"
		testPassword     = "SomePassword123"
		testDeviceID     = "device-123"
	)

	// 1. Provider говорит: пользователь с таким email не найден
	s.MockProvider.On("LoginUsers",
		mock.Anything,                        // любой context
		nonexistentEmail,                     // именно этот email
		testPassword).                        // именно этот пароль
		Return(nil, provider.ErrMissingData). // ОШИБКА!
		Once()                                // должен быть вызван ровно 1 раз

	// 2. Вызываем gRPC Login
	resp, err := s.Client.Login(ctx, &sso.LoginRequest{
		Email:    nonexistentEmail,
		Password: testPassword,
		DeviceID: testDeviceID,
	})

	// 3. Проверяем результат
	require.Error(t, err, "Should return error for non-existent user")
	assert.Nil(t, resp, "Response should be nil on error")

	grpcErr, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status error")

	assert.Equal(t, codes.InvalidArgument, grpcErr.Code(),
		"Should return NotFound for non-existent user")
	assert.Contains(t, grpcErr.Message(), "missing data",
		"Error message should mention user")

	s.MockStorage.AssertNotCalled(t, "AddSession")
	s.MockStorage.AssertNotCalled(t, "IncrementTokenVersion")
	s.MockToken.AssertNotCalled(t, "GenerateAccessToken")
	s.MockToken.AssertNotCalled(t, "GenerateRefreshToken")
	s.MockStorage.AssertNotCalled(t, "Save")

	s.MockProvider.AssertExpectations(t)
}
