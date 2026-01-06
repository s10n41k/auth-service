package suite

import (
	appgrpc "auth/internal/app/grpc"
	grpcAuth "auth/internal/grpc/auth"
	auth "auth/internal/servises/auth"
	mock "auth/internal/tests/mock"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/s10n41k/protos/gen/go/sso"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Suite - тестовая сьюта с testify/mock
type Suite struct {
	*testing.T

	// Сервер
	App    *appgrpc.App
	Server *grpcAuth.Auth

	// Клиент
	Client sso.AuthClient
	Conn   *grpc.ClientConn

	// Моки
	MockProvider *mock.MockProvider
	MockStorage  *mock.MockStorage
	MockSender   *mock.MockEmailSender
	MockToken    *mock.MockToken

	// Порт
	Port int
}

// New создает новую тестовую сьюту
func New(t *testing.T) *Suite {
	t.Helper()

	// Выбираем свободный порт
	port := getFreePort(t)

	// Создаем моки
	mockProvider := mock.NewProvider()
	mockStorage := mock.NewMockStorage()
	mockSender := mock.NewMockEmailSender()
	mockToken := mock.NewMockToken()

	// Создаем сервис
	server := auth.NewServer(
		mockProvider,
		mockToken, // token
		mockStorage,
		mockSender,
		*slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})),
	)

	// Создаем и запускаем App
	app := appgrpc.New(
		slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})),
		server,
		port,
	)

	// Запускаем сервер
	go func() {
		if err := app.Run(); err != nil {
			t.Logf("Server error: %v", err)
		}
	}()

	// Ждем запуска
	waitForServer(t, port)

	// Создаем клиент
	client, conn := createClient(t, port)

	s := &Suite{
		T:            t,
		App:          app,
		Server:       &server,
		Client:       client,
		Conn:         conn,
		MockProvider: mockProvider,
		MockStorage:  mockStorage,
		MockSender:   mockSender,
		MockToken:    mockToken,
		Port:         port,
	}

	// Регистрируем cleanup
	t.Cleanup(func() {
		s.Cleanup()
	})

	return s
}

// Cleanup очищает ресурсы
func (s *Suite) Cleanup() {
	if s.Conn != nil {
		s.Conn.Close()
	}
	if s.App != nil {
		s.App.Stop()
	}

	// Сбрасываем моки
	s.MockProvider.AssertExpectations(s.T)
	s.MockStorage.AssertExpectations(s.T)
	s.MockSender.AssertExpectations(s.T)
}

// Вспомогательные функции
func getFreePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForServer(t *testing.T, port int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	addr := fmt.Sprintf("localhost:%d", port)

	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("Server didn't start in time")
}

func createClient(t *testing.T, port int) (sso.AuthClient, *grpc.ClientConn) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("localhost:%d", port),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err, "Failed to create gRPC client")

	return sso.NewAuthClient(conn), conn
}
