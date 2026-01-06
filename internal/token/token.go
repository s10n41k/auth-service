package token

import (
	"auth/internal/model"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var (
	ErrRefreshToken = errors.New("refresh token error")
	ErrAccessToken  = errors.New("access token not valid")
)

type Generate interface {
	GenerateAccessToken(user *model.UserRefresh) (string, error)
	GenerateRefreshToken(sessionId string) (string, error)
	VerifyRefreshToken(tokenString string) (jwt.MapClaims, error)
	VerifyAccessToken(tokenString string) (jwt.MapClaims, error)
}

type JWTManager struct {
	accessSecret    string
	refreshSecret   string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewJWTManager(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *JWTManager {
	return &JWTManager{
		accessSecret:    accessSecret,
		refreshSecret:   refreshSecret,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

func (m *JWTManager) GenerateAccessToken(u *model.UserRefresh) (string, error) {
	claims := jwt.MapClaims{
		"session": u.SessionId,
		"role":    u.Role,
		"email":   u.Email,
		"exp":     time.Now().Add(m.accessTokenTTL).Unix(),
		"ver":     u.Version,
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.accessSecret))
}

func (m *JWTManager) GenerateRefreshToken(session string) (string, error) {
	claims := jwt.MapClaims{
		"session": session,
		"exp":     time.Now().Add(m.refreshTokenTTL).Unix(),
		"iat":     time.Now().Unix(),
		"lat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.refreshSecret))
}

func (m *JWTManager) VerifyRefreshToken(session string) (jwt.MapClaims, error) {
	if session == "" {
		return nil, errors.New("token is empty")
	}

	token, err := jwt.Parse(session, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.refreshSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (m *JWTManager) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, ErrAccessToken
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.accessSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("access token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid access token")
}
