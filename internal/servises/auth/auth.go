package auth

import (
	"auth/internal/grpc/auth"
	"auth/internal/model"
	"auth/internal/provider/users"
	"auth/internal/sender"
	"auth/internal/storage"
	"auth/internal/token"
	"context"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"math/rand"
	"regexp"
	"strings"
	"unicode"
)

type Auth struct {
	provider users.Provider
	token    token.Generate
	redis    storage.Storage
	sender   sender.EmailSender
	log      slog.Logger
}

func NewServer(provider users.Provider, token token.Generate, redis storage.Storage, sender sender.EmailSender, log slog.Logger) auth.Auth {
	return &Auth{
		provider: provider,
		token:    token,
		redis:    redis,
		sender:   sender,
		log:      log,
	}
}

func (a *Auth) Login(ctx context.Context, email string, password string, deviceID string) (*model.Token, error) {
	// 1. Аутентификация пользователя
	user, err := a.provider.LoginUsers(ctx, email, password)
	if err != nil {
		a.log.Error("login failed", "email", email, "error", err)
		return nil, err
	}

	// 2. Создаем сессию
	session := fmt.Sprintf("%s:%s", user.UserID, deviceID)

	// 3. Добавляем сессию в список сессий пользователя
	err = a.redis.AddSession(ctx, user.UserID, deviceID)
	if err != nil {
		a.log.Warn("failed to add session to list",
			"user_id", user.UserID,
			"device_id", deviceID,
			"error", err)
		// Не прерываем логин, только логируем
	}

	// 4. Увеличиваем версию токенов для этой сессии
	version, err := a.redis.IncrementTokenVersion(ctx, session)
	if err != nil {
		a.log.Error("failed to increment token version",
			"session", session,
			"error", err)
		return nil, fmt.Errorf("increment token version: %w", err)
	}

	// 5. Создаем UserRefresh для генерации токенов
	userRefresh := &model.UserRefresh{
		SessionId: session,
		UserID:    user.UserID,
		Version:   version,
		Name:      user.Name,
		Email:     user.Email,
		Role:      user.Role,
	}

	// 6. Генерируем access token
	accessToken, err := a.token.GenerateAccessToken(userRefresh)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 7. Генерируем refresh token
	refreshToken, err := a.token.GenerateRefreshToken(session)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	// 8. Сохраняем refresh token в Redis
	err = a.redis.Save(ctx, session, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	a.log.Info("user logged in successfully",
		"user_id", user.UserID,
		"email", email,
		"device_id", deviceID)

	return &model.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
	}, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, name, password string) (userID string, err error) {

	if err = validateEmail(email); err != nil {
		return "", err
	}

	if err = validatePassword(password); err != nil {
		return "", err
	}

	err = a.provider.Exists(ctx, email)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	session := fmt.Sprintf("user:%s", email)

	code := generateCode()

	TempUser := model.UserTemporary{
		SessionId: session,
		Code:      code,
		Name:      name,
		Email:     email,
		Password:  password,
	}

	err = a.redis.SaveTemporarySession(ctx, &TempUser)
	if err != nil {
		return "", err
	}

	go func() {
		err = a.sender.SendVerificationCode(email, name, code)
		if err != nil {
			return
		}
	}()

	return session, nil
}

func (a *Auth) VerifyEmail(ctx context.Context, session string, code string) (userID string, err error) {

	user, err := a.redis.GetTemporarySession(ctx, session)
	if err != nil {
		return "", errors.New("operations timed out")
	}

	if user.Code != code {
		return "", errors.New("invalid code")
	}

	id, err := a.provider.RegisterUsers(ctx, user.Email, user.Name, user.Password)
	if err != nil {
		return "", err
	}

	err = a.redis.DeleteTemporarySession(ctx, session)
	if err != nil {
		return "", err
	}

	return id, nil
}

func (a *Auth) GetRefreshToken(ctx context.Context, refreshToken string) (*model.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is empty")
	}

	// 1. Верифицируем refresh token
	claims, err := a.token.VerifyRefreshToken(refreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, fmt.Errorf("refresh token expired")
		}
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// 2. Извлекаем session из claims
	sessionID, ok := claims["session"].(string)
	if !ok || sessionID == "" {
		return nil, fmt.Errorf("invalid token: missing session")
	}

	// 3. Проверяем в Redis
	storedToken, err := a.redis.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("token revoked or user logged out")
		}
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if storedToken != refreshToken {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// 4. Парсим sessionID для получения userID
	parts := strings.Split(sessionID, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid session format: %s", sessionID)
	}
	userID := parts[0]

	// 5. Получаем данные пользователя
	user, err := a.provider.FindOneUsers(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// 6. Увеличиваем версию токенов для этой сессии
	version, err := a.redis.IncrementTokenVersion(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("increment token version: %w", err)
	}

	// 7. Генерируем новый access token
	userRefresh := &model.UserRefresh{
		SessionId: sessionID,
		UserID:    user.UserID,
		Version:   version,
		Name:      user.Name,
		Email:     user.Email,
		Role:      user.Role,
	}

	newAccessToken, err := a.token.GenerateAccessToken(userRefresh)
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	// 8. Генерируем новый refresh token
	newRefreshToken, err := a.token.GenerateRefreshToken(sessionID)
	if err != nil {
		return nil, fmt.Errorf("generate new refresh token: %w", err)
	}

	// 9. Сохраняем новый refresh token
	err = a.redis.Save(ctx, sessionID, newRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to save new refresh token: %w", err)
	}

	a.log.Info("token refreshed successfully",
		"user_id", user.UserID,
		"session", sessionID)

	return &model.Token{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
	}, nil
}

func (a *Auth) Logout(ctx context.Context, accessToken string) error {
	// 1. Верифицируем access token
	claims, err := a.token.VerifyAccessToken(accessToken)
	if err != nil {
		a.log.Error("invalid access token", "error", err)
		return fmt.Errorf("invalid access token: %w", err)
	}

	// 2. Извлекаем session ID
	sessionID, ok := claims["session"].(string)
	if !ok || sessionID == "" {
		return fmt.Errorf("invalid token: missing session")
	}

	// 3. Парсим sessionID для получения userID и deviceID
	parts := strings.Split(sessionID, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid session format: %s", sessionID)
	}
	userID := parts[0]
	deviceID := parts[1]

	// 4. Проверяем версию токена
	versionFloat, ok := claims["ver"].(float64)
	if !ok {
		return fmt.Errorf("invalid version in token")
	}
	versionFromToken := int(versionFloat)

	currentVersion, err := a.redis.GetTokenVersion(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("get version: %w", err)
	}

	if versionFromToken != currentVersion {
		return fmt.Errorf("invalid token version")
	}

	// 5. Удаляем deviceID из списка сессий пользователя
	err = a.redis.RemoveSession(ctx, userID, deviceID)
	if err != nil && !errors.Is(err, redis.Nil) {
		a.log.Warn("failed to remove session from list",
			"user_id", userID,
			"device_id", deviceID,
			"error", err)
		// Не прерываем логаут, только логируем
	}

	// 6. Удаляем refresh token
	err = a.redis.DeleteRefreshToken(ctx, sessionID)
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("delete refresh token: %w", err)
	}

	// 7. Удаляем версию токена
	err = a.redis.DeleteVersionToken(ctx, sessionID)
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("delete version token: %w", err)
	}

	a.log.Info("user logged out",
		"user_id", userID,
		"device_id", deviceID,
		"session", sessionID)

	return nil
}

func (a *Auth) LogoutAll(ctx context.Context, accessToken string) error {
	// 1. Верифицируем access token
	claims, err := a.token.VerifyAccessToken(accessToken)
	if err != nil {
		a.log.Error("invalid access token", "error", err)
		return fmt.Errorf("invalid access token: %w", err)
	}

	// 2. Извлекаем userID
	session, ok := claims["session"].(string)
	if !ok || session == "" {
		return fmt.Errorf("invalid token: missing user_id")
	}

	parts := strings.Split(session, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid session format: %s", session)
	}
	userID := parts[0]

	// 3. Получаем все сессии пользователя
	deviceIDs, err := a.redis.GetUserSessions(ctx, userID)
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("get user sessions: %w", err)
	}

	if len(deviceIDs) == 0 {
		a.log.Info("no active sessions found", "user_id", userID)
		return nil
	}

	// 4. Удаляем все сессии и связанные токены
	var lastErr error
	for _, deviceID := range deviceIDs {
		sessionID := fmt.Sprintf("%s:%s", userID, deviceID)

		// Удаляем refresh token
		err := a.redis.DeleteRefreshToken(ctx, sessionID)
		if err != nil && !errors.Is(err, redis.Nil) {
			lastErr = err
			a.log.Warn("failed to delete refresh token",
				"session", sessionID,
				"error", err)
		}

		// Удаляем версию токена
		err = a.redis.DeleteVersionToken(ctx, sessionID)
		if err != nil && !errors.Is(err, redis.Nil) {
			lastErr = err
			a.log.Warn("failed to delete version token",
				"session", sessionID,
				"error", err)
		}
	}

	// 5. Удаляем список сессий пользователя
	err = a.redis.DeleteAllSessions(ctx, userID)
	if err != nil && !errors.Is(err, redis.Nil) {
		lastErr = err
		a.log.Warn("failed to delete sessions list",
			"user_id", userID,
			"error", err)
	}

	a.log.Info("logged out all sessions",
		"user_id", userID,
		"sessions_count", len(deviceIDs))

	if lastErr != nil {
		return fmt.Errorf("some sessions were not deleted properly: %w", lastErr)
	}

	return nil
}

var (
	ErrEmailMissingAt     = errors.New("your email doesn't contain the '@' symbol")
	ErrEmailInvalidFmt    = errors.New("your email contains not valid characters")
	ErrEmailUnknownDomain = errors.New("your domain isn't allowed")
)

func validateEmail(email string) error {
	// Проверяем есть ли пробелы
	if strings.Contains(email, " ") {
		return errors.New("email cannot contain spaces")
	}

	if !strings.Contains(email, "@") {
		return ErrEmailMissingAt
	}

	// Regexp с заглавными буквами
	re := regexp.MustCompile("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$")
	if !re.MatchString(email) {
		return ErrEmailInvalidFmt
	}

	// Для проверки домена все равно нужно нижний регистр
	// потому что allowedDomains содержит домены в нижнем регистре
	lowerEmail := strings.ToLower(email)
	paths := strings.Split(lowerEmail, "@")
	domain := paths[1]

	if !allowedDomains[domain] {
		return ErrEmailUnknownDomain
	}

	return nil
}

var allowedDomains = map[string]bool{
	"gmail.com": true,
	"yandex.ru": true,
	"mail.ru":   true,
	"mail.com":  true,
}

var (
	ErrPasswordLow = errors.New("the password must contain at 8 characters or more")
	ErrPasswordFmt = errors.New("the password must contain at least one uppercase character and one number")
)

func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrPasswordLow
	}

	var hasDigit bool
	var hasUpper bool

	for _, ch := range password {
		switch {
		case unicode.IsDigit(ch):
			hasDigit = true
		}
		if unicode.IsUpper(ch) {
			hasUpper = true
		}
	}
	if !hasDigit || !hasUpper {
		return ErrPasswordFmt
	}
	return nil
}

func generateCode() string {
	// Генерация от 0000 до 9999
	return fmt.Sprintf("%04d", rand.Intn(10000))
}
