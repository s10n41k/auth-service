package tests

import (
	"auth/internal/model"
	"auth/internal/tests/suite"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/s10n41k/protos/gen/go/sso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegister_HappyPath(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const (
		testEmail    = "test@gmail.com"
		testName     = "Test User"
		testPassword = "Password123"
	)

	var savedCode string

	// 1. Provider
	s.MockProvider.On("Exists", mock.Anything, testEmail).
		Return(nil).
		Once()

	// 2. Storage - проверяем ЧТО код состоит из 4 ЦИФР
	s.MockStorage.On("SaveTemporarySession", mock.Anything, mock.MatchedBy(func(user interface{}) bool {
		u := user.(*model.UserTemporary)
		savedCode = u.Code

		// Строгая проверка!
		if len(u.Code) != 4 {
			t.Errorf("Code should be 4 characters, got: %s", u.Code)
			return false
		}

		// Проверяем что код состоит из цифр
		for _, ch := range u.Code {
			if ch < '0' || ch > '9' {
				t.Errorf("Code should contain only digits, got: %s", u.Code)
				return false
			}
		}

		return u.Email == testEmail &&
			u.Name == testName &&
			u.Password == testPassword
	})).Return(nil).Once()

	// 3. Email - проверяем что отправляется ТОТ ЖЕ код
	s.MockSender.On("SendVerificationCode", testEmail, testName, mock.MatchedBy(func(code string) bool {
		// Проверяем что код совпадает с сохраненным
		if code != savedCode {
			t.Errorf("Email code doesn't match saved code: email=%s, saved=%s", code, savedCode)
			return false
		}
		return true
	})).Return(nil).Once()

	// 4. Вызываем
	resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     testName,
		Email:    testEmail,
		Password: testPassword,
	})

	// 5. Проверяем
	require.NoError(t, err)
	assert.Equal(t, "user:"+testEmail, resp.GetSession())

	// 6. Проверяем моки
	s.MockProvider.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
	s.MockSender.AssertExpectations(t)
}
func TestRegister_EmptyFields(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	// 1. Без настроек моков - они не должны вызываться

	// 2. Пустой email
	resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     "Test",
		Email:    "",
		Password: "Password123",
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "email")

	// 3. Пустой пароль
	resp, err = s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     "Test",
		Email:    "test@gmail.com",
		Password: "",
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "password")

	// 4. Проверяем что моки НЕ вызывались
	s.MockProvider.AssertNotCalled(t, "Exists")
	s.MockStorage.AssertNotCalled(t, "SaveTemporarySession")
	s.MockSender.AssertNotCalled(t, "SendVerificationCode")
}

func TestRegister_InvalidEmailFormat(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	testCases := []struct {
		name  string
		email string
	}{
		{"Без @", "invalidemail"},
		{"Только @", "@"},
		{"Нет домена", "test@"},
		{"Нет имени", "@gmail.com"},
		{"С пробелом", "test @gmail.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
				Name:     "Test",
				Email:    tc.email,
				Password: "Password123",
			})

			require.Error(t, err)
			assert.Nil(t, resp)

			grpcErr, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, grpcErr.Code())
		})
	}

	// Проверяем что моки НЕ вызывались
	s.MockProvider.AssertNotCalled(t, "Exists")
	s.MockStorage.AssertNotCalled(t, "SaveTemporarySession")
	s.MockSender.AssertNotCalled(t, "SendVerificationCode")
}

func TestRegister_InvalidPassword(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	testCases := []struct {
		name     string
		password string
	}{
		{"Слишком короткий", "Ab1"},
		{"Без заглавной", "password123"},
		{"Без цифры", "Password"},
		{"Только цифры", "12345678"},
		{"Только строчные", "password"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
				Name:     "Test",
				Email:    "test@gmail.com",
				Password: tc.password,
			})

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), "password")
		})
	}

	// Provider не должен вызываться
	s.MockProvider.AssertNotCalled(t, "Exists")
}

func TestRegister_UserAlreadyExists(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const testEmail = "existing@gmail.com"

	// 1. Provider говорит что пользователь уже существует
	s.MockProvider.On("Exists", mock.Anything, testEmail).
		Return(fmt.Errorf("user already exists")).
		Once()

	// 2. Вызываем
	resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     "Test",
		Email:    testEmail,
		Password: "Password123",
	})

	// 3. Проверяем
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "already exists")

	// 4. Storage и sender не должны вызываться
	s.MockStorage.AssertNotCalled(t, "SaveTemporarySession")
	s.MockSender.AssertNotCalled(t, "SendVerificationCode")

	// 5. Provider должен был быть вызван
	s.MockProvider.AssertExpectations(t)
}

func TestRegister_StorageError(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const testEmail = "test@gmail.com"

	// 1. Provider успешен
	s.MockProvider.On("Exists", mock.Anything, testEmail).
		Return(nil).
		Once()

	// 2. Storage возвращает ошибку
	s.MockStorage.On("SaveTemporarySession", mock.Anything, mock.Anything).
		Return(fmt.Errorf("redis error")).
		Once()

	// 3. Вызываем
	resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     "Test",
		Email:    testEmail,
		Password: "Password123",
	})

	// 4. Проверяем
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "redis")

	// 5. Email не должен отправляться
	s.MockSender.AssertNotCalled(t, "SendVerificationCode")

	// 6. Проверяем вызовы
	s.MockProvider.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
}

func TestRegister_EmailSendError(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const testEmail = "test@gmail.com"

	// 1. Provider успешен
	s.MockProvider.On("Exists", mock.Anything, testEmail).
		Return(nil).
		Once()

	// 2. Storage успешен
	s.MockStorage.On("SaveTemporarySession", mock.Anything, mock.Anything).
		Return(nil).
		Once()

	// 3. Email sender возвращает ошибку (асинхронно)
	s.MockSender.On("SendVerificationCode", testEmail, mock.Anything, mock.Anything).
		Return(fmt.Errorf("SMTP error")).
		Once()

	// 4. Вызываем - email отправка асинхронная, не влияет на ответ
	resp, err := s.Client.Register(ctx, &sso.RegisterRequest{
		Name:     "Test",
		Email:    testEmail,
		Password: "Password123",
	})

	// 5. Проверяем - регистрация должна пройти успешно
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "user:"+testEmail, resp.GetSession())

	// 6. Ждем немного и проверяем что email пытался отправиться
	time.Sleep(100 * time.Millisecond)
	s.MockSender.AssertExpectations(t)

	// 7. Проверяем все вызовы
	s.MockProvider.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
}

func TestRegister_Concurrent(t *testing.T) {
	s := suite.New(t)
	ctx := context.Background()

	const numUsers = 3

	// Настраиваем моки для всех пользователей
	for i := 0; i < numUsers; i++ {
		email := fmt.Sprintf("user%d@gmail.com", i)

		s.MockProvider.On("Exists", mock.Anything, email).
			Return(nil).
			Once()

		s.MockStorage.On("SaveTemporarySession", mock.Anything, mock.MatchedBy(func(user interface{}) bool {
			u := user.(*model.UserTemporary)
			return u.Email == email
		})).Return(nil).Once()

		s.MockSender.On("SendVerificationCode", email, mock.Anything, mock.Anything).
			Return(nil).
			Once()
	}

	// Запускаем конкурентно
	errors := make(chan error, numUsers)

	for i := 0; i < numUsers; i++ {
		go func(index int) {
			_, err := s.Client.Register(ctx, &sso.RegisterRequest{
				Name:     fmt.Sprintf("User %d", index),
				Email:    fmt.Sprintf("user%d@gmail.com", index),
				Password: fmt.Sprintf("Password%d", index),
			})

			if err != nil {
				errors <- err
			}
		}(i)
	}

	// Ждем
	time.Sleep(300 * time.Millisecond)

	// Проверяем что нет ошибок
	select {
	case err := <-errors:
		t.Errorf("Concurrent request failed: %v", err)
	default:
		// OK
	}

	// Проверяем что все моки вызвались
	s.MockProvider.AssertExpectations(t)
	s.MockStorage.AssertExpectations(t)
	s.MockSender.AssertExpectations(t)
}
