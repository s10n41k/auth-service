package users

import (
	"auth/internal/model"
	"auth/internal/provider"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type usersResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type Provider interface {
	LoginUsers(ctx context.Context, email, password string) (*model.User, error)
	RegisterUsers(ctx context.Context, email, name, password string) (id string, err error)
	FindOneUsers(ctx context.Context, id string) (*model.UserRefresh, error)
	Exists(ctx context.Context, email string) error
}

type usersProvider struct {
	protocol string
	host     string
	port     string
	client   *http.Client
	log      slog.Logger
}

func NewUsersProvider(protocol string, host string, port string, log slog.Logger) Provider {
	return &usersProvider{
		protocol: protocol,
		host:     host,
		port:     port,
		log:      log,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   20,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ForceAttemptHTTP2:     true,
				DisableKeepAlives:     false,
				DisableCompression:    false,
				MaxConnsPerHost:       50, // не более 50 одновременных соединений
			},
			Timeout: 5 * time.Second,
		},
	}
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required,min=6"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	UserID string `json:"id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Valid  bool   `json:"valid"`
	Role   string `json:"role"`
}

func (u *usersProvider) LoginUsers(ctx context.Context, email, password string) (*model.User, error) {
	url := fmt.Sprintf("%s://%s:%s/user/login", u.protocol, u.host, u.port)

	u.log.Debug("Calling users API",
		slog.String("url", url),
		slog.String("email", email))

	body, err := json.Marshal(loginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		u.log.Error("Failed to marshal request", slog.String("error", err.Error()))
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		u.log.Error("Failed to create request", slog.String("error", err.Error()))
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Выполняем запрос
	resp, err := u.client.Do(req)
	if err != nil {
		u.log.Error("HTTP request failed",
			slog.String("error", err.Error()),
			slog.String("url", url))
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Читаем ВЕСЬ ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		u.log.Error("Failed to read response body", slog.String("error", err.Error()))
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Логируем ответ
	u.log.Debug("Users API response",
		slog.Int("status", resp.StatusCode),
		slog.Int("body_length", len(respBody)), // КРИТИЧЕСКИ ВАЖНО!
		slog.String("body", string(respBody)))

	// СНАЧАЛА проверяем статус код!
	if resp.StatusCode != http.StatusOK {
		u.log.Warn("API returned error status",
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(respBody)))

		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, provider.ErrUserNotFound
		case http.StatusUnauthorized:
			return nil, provider.ErrMissingData
		case http.StatusBadRequest:
			return nil, fmt.Errorf("bad request")
		default:
			return nil, fmt.Errorf("api error %d", resp.StatusCode)
		}
	}

	// ТОЛЬКО ЕСЛИ статус 200, парсим JSON
	if len(respBody) == 0 {
		u.log.Error("API returned empty body for successful response")
		return nil, fmt.Errorf("empty response body")
	}

	var out loginResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		u.log.Error("Failed to decode response",
			slog.String("error", err.Error()),
			slog.String("body", string(respBody)))
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Проверяем, что user_id не пустой (опционально)
	if out.UserID == "" {
		u.log.Warn("API returned empty user_id in successful response")
		// Можно вернуть ошибку или продолжить в зависимости от логики
	}

	// Создаем пользователя
	user := &model.User{
		UserID: out.UserID,
		Name:   out.Name,
		Email:  out.Email,
		Role:   out.Role,
		Valid:  out.Valid,
	}

	u.log.Debug("Login request completed",
		slog.String("user_id", user.UserID))

	return user, nil
}
func (u *usersProvider) RegisterUsers(ctx context.Context, email, name, password string) (string, error) {
	url := fmt.Sprintf("%s://%s:%s/user/register", u.protocol, u.host, u.port)

	body, err := json.Marshal(RegisterRequest{
		Email:    email,
		Password: password,
		Name:     name,
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := u.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// Читаем ВЕСЬ ответ
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	// Логируем
	u.log.Debug("Users API register response",
		slog.Int("status", resp.StatusCode),
		slog.String("body", string(respBody)))

	// СНАЧАЛА проверяем статус код!
	if resp.StatusCode != http.StatusCreated {
		u.log.Warn("API returned error status",
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(respBody)))

		switch resp.StatusCode {
		case http.StatusConflict:
			return "", provider.ErrUserExists
		case http.StatusBadRequest:
			return "", fmt.Errorf("bad request")
		default:
			return "", fmt.Errorf("internal error")
		}
	}

	// ВМЕСТО json.Unmarshal - ручной парсинг
	bodyStr := string(respBody)
	bodyStr = strings.TrimSpace(bodyStr)

	// Проверяем формат
	if len(bodyStr) == 0 {
		return "", fmt.Errorf("empty response")
	}

	// Если это JSON string в кавычках
	if bodyStr[0] == '"' && bodyStr[len(bodyStr)-1] == '"' {
		// Убираем кавычки
		id := bodyStr[1 : len(bodyStr)-1]
		return id, nil
	}

	// Если это plain text
	return bodyStr, nil
}
func (u *usersProvider) FindOneUsers(ctx context.Context, id string) (*model.UserRefresh, error) {
	url := fmt.Sprintf("%s://%s:%s/users/%s", u.protocol, u.host, u.port, id)

	// Логируем начало запроса
	u.log.Debug("calling users service to find user",
		slog.String("user_id", id),
		slog.String("url", url))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		u.log.Error("failed to create request",
			slog.String("error", err.Error()),
			slog.String("user_id", id))
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Выполняем запрос
	resp, err := u.client.Do(req)
	if err != nil {
		// Проверяем, была ли отмена контекста
		if errors.Is(err, context.Canceled) {
			u.log.Warn("request cancelled",
				slog.String("user_id", id))
			return nil, fmt.Errorf("request cancelled: %w", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			u.log.Warn("request timeout",
				slog.String("user_id", id))
			return nil, fmt.Errorf("request timeout: %w", err)
		}

		u.log.Error("failed to call users service",
			slog.String("error", err.Error()),
			slog.String("user_id", id))
		return nil, fmt.Errorf("call users service: %w", err)
	}
	defer resp.Body.Close()

	// ВСЕГДА читаем тело полностью перед возвратом
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		u.log.Error("failed to read response body",
			slog.String("error", err.Error()),
			slog.String("user_id", id),
			slog.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// Проверяем статус код
	if resp.StatusCode != http.StatusOK {
		u.log.Warn("users service returned error",
			slog.Int("status", resp.StatusCode),
			slog.String("user_id", id),
			slog.String("body", string(body)))

		// Обрабатываем разные статусы
		switch resp.StatusCode {
		case http.StatusNotFound:
			return nil, fmt.Errorf("user not found: %s", id)
		case http.StatusBadRequest:
			return nil, fmt.Errorf("invalid user id: %s", id)
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, fmt.Errorf("access denied for user: %s", id)
		case http.StatusInternalServerError:
			return nil, fmt.Errorf("users service internal error")
		default:
			return nil, fmt.Errorf("users service error (status=%d): %s",
				resp.StatusCode, string(body))
		}
	}

	// Декодируем успешный ответ
	var respUser usersResponse
	if err := json.Unmarshal(body, &respUser); err != nil {
		u.log.Error("failed to decode response",
			slog.String("error", err.Error()),
			slog.String("user_id", id),
			slog.String("body", string(body))) // Логируем тело для отладки
		return nil, fmt.Errorf("decode response: %w", err)
	}

	user := model.UserRefresh{
		UserID: respUser.ID,
		Name:   respUser.Name,
		Email:  respUser.Email,
		Role:   respUser.Role,
	}

	// Проверяем, что пользователь действительно найден
	if user.UserID == "" {
		u.log.Warn("empty user returned from service",
			slog.String("requested_id", id),
			slog.Any("response", user))
		return nil, fmt.Errorf("user not found: %s", id)
	}

	// Логируем успех
	u.log.Debug("user found successfully",
		slog.String("user_id", user.UserID),
		slog.String("requested_id", id))

	return &user, nil
}

func (u *usersProvider) Exists(ctx context.Context, email string) error {
	// URL encode email на случай спецсимволов
	encodedEmail := url.PathEscape(email)
	url := fmt.Sprintf("%s://%s:%s/check-email/%s", u.protocol, u.host, u.port, encodedEmail)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		u.log.Error("failed to create request",
			slog.String("error", err.Error()),
			slog.String("email", email))
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json") // Content-Type для GET не нужен

	resp, err := u.client.Do(req)
	if err != nil {
		// Проверяем, была ли отмена контекста
		if errors.Is(err, context.Canceled) {
			u.log.Warn("request cancelled",
				slog.String("email", email))
			return fmt.Errorf("request cancelled: %w", err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			u.log.Warn("request timeout",
				slog.String("email", email))
			return fmt.Errorf("request timeout: %w", err)
		}

		u.log.Error("failed to call users service",
			slog.String("error", err.Error()),
			slog.String("email", email))
		return fmt.Errorf("call users service: %w", err)
	}
	defer resp.Body.Close()

	// Читаем тело ответа для дебага
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		u.log.Error("failed to read response body",
			slog.String("error", err.Error()),
			slog.String("email", email),
			slog.Int("status_code", resp.StatusCode))
		return fmt.Errorf("read response body: %w", err)
	}

	// Проверяем статус код
	switch resp.StatusCode {
	case http.StatusOK:
		// Пользователь не существует
		return nil

	case http.StatusConflict:
		// Пользователь уже существует
		u.log.Debug("user already exists",
			slog.String("email", email),
			slog.String("response_body", string(body)))
		return provider.ErrUserExists

	case http.StatusBadRequest:
		u.log.Warn("bad request to users service",
			slog.String("email", email),
			slog.String("response_body", string(body)))
		return fmt.Errorf("bad request: %s", string(body))

	default:
		u.log.Error("users service returned error",
			slog.String("email", email),
			slog.Int("status_code", resp.StatusCode),
			slog.String("response_body", string(body)))
		return fmt.Errorf("users service error (status=%d): %s", resp.StatusCode, string(body))
	}
}
