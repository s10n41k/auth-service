package tests

import (
	"auth/internal/model"
	"auth/internal/tests/suite"
	"context"
	"fmt"
	"testing"

	"github.com/s10n41k/protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVerifyEmail_HappyPath(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		session      = "user:test@gmail.com"
		code         = "1234"
		expectedID   = "user-id-123"
		testEmail    = "test@gmail.com"
		testName     = "Test User"
		testPassword = "Password123"
	)

	// 1. Storage возвращает временного пользователя
	s.MockStorage.On("GetTemporarySession", mock.Anything, session).
		Return(&model.UserTemporary{
			SessionId: session,
			Code:      code,
			Name:      testName,
			Email:     testEmail,
			Password:  testPassword,
		}, nil).
		Once()

	// 2. Provider регистрирует пользователя
	s.MockProvider.On("RegisterUsers", mock.Anything, testEmail, testName, testPassword).
		Return(expectedID, nil).
		Once()

	// 3. Storage удаляет временную сессию
	s.MockStorage.On("DeleteTemporarySession", mock.Anything, session).
		Return(nil).
		Once()

	// 4. Вызываем
	resp, err := s.Client.VerifyEmail(ctx, &sso.VerifyEmailRequest{
		Session: session,
		Code:    code,
	})

	// 5. Проверяем
	require.NoError(t, err)
	assert.Equal(t, expectedID, resp.GetUserId())

	// 6. Проверяем вызовы моков
	s.MockStorage.AssertExpectations(t)
	s.MockProvider.AssertExpectations(t)
}

func TestVerifyEmail_InvalidSession(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	testCases := []struct {
		name    string
		session string
		code    string
	}{
		{"Empty session", "", "1234"},
		{"Empty code", "user:test@gmail.com", ""},
		{"Both empty", "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.Client.VerifyEmail(ctx, &sso.VerifyEmailRequest{
				Session: tc.session,
				Code:    tc.code,
			})

			require.Error(t, err)
			assert.Nil(t, resp)

			grpcErr, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, grpcErr.Code())

			// Моки не должны вызываться
			s.MockStorage.AssertNotCalled(t, "GetTemporarySession")
			s.MockProvider.AssertNotCalled(t, "RegisterUsers")
			s.MockStorage.AssertNotCalled(t, "DeleteTemporarySession")
		})
	}
}

func TestVerifyEmail_SessionNotFound(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		session = "user:notfound@gmail.com"
		code    = "1234"
	)

	// 1. Storage не находит сессию
	s.MockStorage.On("GetTemporarySession", mock.Anything, session).
		Return((*model.UserTemporary)(nil), fmt.Errorf("session not found")).
		Once()

	// 2. Вызываем
	resp, err := s.Client.VerifyEmail(ctx, &sso.VerifyEmailRequest{
		Session: session,
		Code:    code,
	})

	// 3. Проверяем
	require.Error(t, err)
	assert.Nil(t, resp)

	// 4. Проверяем что это Internal ошибка (как в handler)
	grpcErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, grpcErr.Code())
	assert.Contains(t, grpcErr.Message(), "failed to verify")

	// 5. Provider не должен вызываться
	s.MockProvider.AssertNotCalled(t, "RegisterUsers")
	s.MockStorage.AssertNotCalled(t, "DeleteTemporarySession")

	// 6. Проверяем вызовы
	s.MockStorage.AssertExpectations(t)
}

func TestVerifyEmail_WrongCode(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		session   = "user:test@gmail.com"
		realCode  = "1234"
		wrongCode = "9999"
	)

	// 1. Storage возвращает пользователя с другим кодом
	s.MockStorage.On("GetTemporarySession", mock.Anything, session).
		Return(&model.UserTemporary{
			SessionId: session,
			Code:      realCode, // правильный код
			Email:     "test@gmail.com",
			Name:      "Test",
			Password:  "Password123",
		}, nil).
		Once()

	// 2. Вызываем с неправильным кодом
	resp, err := s.Client.VerifyEmail(ctx, &sso.VerifyEmailRequest{
		Session: session,
		Code:    wrongCode,
	})

	// 3. Проверяем
	require.Error(t, err)
	assert.Nil(t, resp)

	// 4. Должна быть Internal ошибка
	grpcErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, grpcErr.Code())

	// 5. Provider не должен вызываться
	s.MockProvider.AssertNotCalled(t, "RegisterUsers")
	s.MockStorage.AssertNotCalled(t, "DeleteTemporarySession")

	// 6. Проверяем вызовы
	s.MockStorage.AssertExpectations(t)
}

func TestVerifyEmail_ProviderRegistrationError(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		session      = "user:test@gmail.com"
		code         = "1234"
		testEmail    = "test@gmail.com"
		testName     = "Test User"
		testPassword = "Password123"
	)

	// 1. Storage возвращает пользователя
	s.MockStorage.On("GetTemporarySession", mock.Anything, session).
		Return(&model.UserTemporary{
			SessionId: session,
			Code:      code,
			Name:      testName,
			Email:     testEmail,
			Password:  testPassword,
		}, nil).
		Once()

	// 2. Provider возвращает ошибку при регистрации
	s.MockProvider.On("RegisterUsers", mock.Anything, testEmail, testName, testPassword).
		Return("", fmt.Errorf("database error")).
		Once()

	// 3. Вызываем
	resp, err := s.Client.VerifyEmail(ctx, &sso.VerifyEmailRequest{
		Session: session,
		Code:    code,
	})

	// 4. Проверяем
	require.Error(t, err)
	assert.Nil(t, resp)

	// 5. Должна быть Internal ошибка
	grpcErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, grpcErr.Code())

	// 6. Storage не должен удалять сессию при ошибке регистрации
	s.MockStorage.AssertNotCalled(t, "DeleteTemporarySession")

	// 7. Проверяем вызовы
	s.MockStorage.AssertExpectations(t)
	s.MockProvider.AssertExpectations(t)
}

func TestVerifyEmail_CompleteFlow_RegisterAndVerify(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testEmail    = "complete@gmail.com"
		testName     = "Complete User"
		testPassword = "Password123"
		expectedID   = "user-id-456"
	)

	var generatedCode string

	// === ЧАСТЬ 1: РЕГИСТРАЦИЯ ===

	// 1.1 Настраиваем моки для регистрации
	s.MockProvider.On("Exists", mock.Anything, testEmail).
		Return(nil).
		Once()

	s.MockStorage.On("SaveTemporarySession", mock.Anything, mock.MatchedBy(func(user interface{}) bool {
		u := user.(*model.UserTemporary)
		generatedCode = u.Code
		return u.Email == testEmail &&
			u.Name == testName &&
			u.Password == testPassword &&
			len(u.Code) == 4
	})).Return(nil).Once()

	s.MockSender.On("SendVerificationCode", testEmail, testName, mock.Anything).
		Return(nil).
		Once()

	// 1.2 Вызываем регистрацию
	registerResp, err := s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     testName,
		Email:    testEmail,
		Password: testPassword,
	})

	require.NoError(t, err)
	session := registerResp.GetSession()
	assert.Equal(t, "user:"+testEmail, session)

	// 1.3 Проверяем регистрацию
	s.MockProvider.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
	s.MockSender.AssertExpectations(t)

	// === ЧАСТЬ 2: ВЕРИФИКАЦИЯ ===

	// 2.1 Настраиваем моки для верификации
	s.MockStorage.On("GetTemporarySession", mock.Anything, session).
		Return(&model.UserTemporary{
			SessionId: session,
			Code:      generatedCode,
			Name:      testName,
			Email:     testEmail,
			Password:  testPassword,
		}, nil).
		Once()

	s.MockProvider.On("RegisterUsers", mock.Anything, testEmail, testName, testPassword).
		Return(expectedID, nil).
		Once()

	s.MockStorage.On("DeleteTemporarySession", mock.Anything, session).
		Return(nil).
		Once()

	// 2.2 Вызываем верификацию
	verifyResp, err := s.Client.VerifyEmail(ctx, &sso.VerifyEmailRequest{
		Session: session,
		Code:    generatedCode,
	})

	// 2.3 Проверяем верификацию
	require.NoError(t, err)
	assert.Equal(t, expectedID, verifyResp.GetUserId())

	// 2.4 Проверяем все вызовы
	s.MockStorage.AssertExpectations(t)
	s.MockProvider.AssertExpectations(t)
}
