package mock

import (
	"auth/internal/model"
	"context"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
)

// ===================== МОК PROVIDER =====================

type MockProvider struct {
	mock.Mock
}

func NewProvider() *MockProvider {
	return &MockProvider{}
}

func (m *MockProvider) Exists(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *MockProvider) RegisterUsers(ctx context.Context, email, name, password string) (string, error) {
	args := m.Called(ctx, email, name, password)
	return args.String(0), args.Error(1)
}

func (m *MockProvider) LoginUsers(ctx context.Context, email, password string) (*model.User, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockProvider) FindOneUsers(ctx context.Context, id string) (*model.UserRefresh, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserRefresh), args.Error(1)
}

// ===================== МОК STORAGE =====================

type MockStorage struct {
	mock.Mock
}

func NewMockStorage() *MockStorage {
	return &MockStorage{}
}

func (m *MockStorage) SaveTemporarySession(ctx context.Context, userTemporary *model.UserTemporary) error {
	args := m.Called(ctx, userTemporary)
	return args.Error(0)
}

func (m *MockStorage) GetTemporarySession(ctx context.Context, session string) (*model.UserTemporary, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.UserTemporary), args.Error(1)
}

func (m *MockStorage) DeleteTemporarySession(ctx context.Context, session string) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

// Остальные методы для соответствия интерфейсу
func (m *MockStorage) Save(ctx context.Context, userId, refreshToken string) error {
	args := m.Called(ctx, userId, refreshToken)
	return args.Error(0)
}

func (m *MockStorage) Get(ctx context.Context, userId string) (string, error) {
	args := m.Called(ctx, userId)
	return args.String(0), args.Error(1)
}

func (m *MockStorage) IncrementTokenVersion(ctx context.Context, session string) (int, error) {
	args := m.Called(ctx, session)
	return args.Int(0), args.Error(1)
}

func (m *MockStorage) GetTokenVersion(ctx context.Context, session string) (int, error) {
	args := m.Called(ctx, session)
	return args.Int(0), args.Error(1)
}

func (m *MockStorage) DeleteVersionToken(ctx context.Context, session string) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockStorage) DeleteRefreshToken(ctx context.Context, session string) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockStorage) AddSession(ctx context.Context, userID, deviceID string) error {
	args := m.Called(ctx, userID, deviceID)
	return args.Error(0)
}

func (m *MockStorage) RemoveSession(ctx context.Context, userID, deviceID string) error {
	args := m.Called(ctx, userID, deviceID)
	return args.Error(0)
}

func (m *MockStorage) GetUserSessions(ctx context.Context, userID string) ([]string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorage) DeleteAllSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// ===================== МОК EMAIL SENDER =====================

type MockEmailSender struct {
	mock.Mock
	sentEmails []SentEmail
	mu         sync.Mutex
}

type SentEmail struct {
	ToEmail  string
	UserName string
	Code     string
	Time     time.Time
}

func NewMockEmailSender() *MockEmailSender {
	return &MockEmailSender{
		sentEmails: make([]SentEmail, 0),
	}
}

func (m *MockEmailSender) SendVerificationCode(toEmail, userName, code string) error {
	m.mu.Lock()
	m.sentEmails = append(m.sentEmails, SentEmail{
		ToEmail:  toEmail,
		UserName: userName,
		Code:     code,
		Time:     time.Now(),
	})
	m.mu.Unlock()

	args := m.Called(toEmail, userName, code)
	return args.Error(0)
}

func (m *MockEmailSender) GetSentEmails() []SentEmail {
	m.mu.Lock()
	defer m.mu.Unlock()

	emails := make([]SentEmail, len(m.sentEmails))
	copy(emails, m.sentEmails)
	return emails
}

func (m *MockEmailSender) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentEmails = nil
	m.ExpectedCalls = nil
	m.Calls = nil
}

// ===================== МОК TOKEN =====================

type MockToken struct {
	mock.Mock
}

func NewMockToken() *MockToken {
	return &MockToken{}
}

func (m *MockToken) GenerateAccessToken(user *model.UserRefresh) (string, error) {
	args := m.Called(user)
	return args.String(0), args.Error(1)
}

func (m *MockToken) GenerateRefreshToken(sessionId string) (string, error) {
	args := m.Called(sessionId)
	return args.String(0), args.Error(1)
}

func (m *MockToken) VerifyRefreshToken(tokenString string) (jwt.MapClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}

func (m *MockToken) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}
