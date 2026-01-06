package config

import (
	"errors"
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"log/slog"
	"os"
	"sync"
	"time"
)

type Config struct {
	ListenConfig ListenConfig   `yaml:"listen"`
	Redis        StorageRedis   `yaml:"redis"`
	Token        TokenConfig    `yaml:"token"`
	Provider     ProviderConfig `yaml:"provider"`
	GRPCConfig   GRPCConfig     `yaml:"grpc"`
	SMTPConfig   SMTPConfig     `yaml:"smtp"`
	Env          string         `yaml:"env"`
}

type SMTPConfig struct {
	Host         string `yaml:"host" env-default:"smtp.gmail.com"`
	Port         string `yaml:"port" env:"SMTP_PORT" env-default:"587"`
	Username     string `yaml:"username" env-default:"s10n41kk@gmail.com"`
	Password     string `yaml:"password" env-default:"adlo atvm reuk coot"`
	FromEmail    string `yaml:"from_email" env-default:"s10n41kk@gmail.com"`
	FromName     string `yaml:"from_name" env-default:"TODOLIST"`
	AppURL       string `yaml:"app_url" env:"APP_URL" env-default:"https://myapp.com"`
	SupportEmail string `yaml:"support_email" env-default:"s10n41kk@gmail.com"`
	UseTLS       bool   `yaml:"use_tls" env:"SMTP_USE_TLS" env-default:"true"`
	Timeout      int    `yaml:"timeout" env:"SMTP_TIMEOUT" env-default:"10"`
}

type ProviderConfig struct {
	Type     string `yaml:"type" env-default:"port"`
	Port     string `yaml:"port" env-default:"8080"`
	Host     string `yaml:"host" env-default:"localhost"`
	Protocol string `yaml:"protocol" env-default:"http"`
	BindIP   string `yaml:"bind_ip" env-default:"127.0.0.1"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

type StorageRedis struct {
	Host     string `yaml:"host" env-default:"localhost"`
	Port     string `yaml:"port" env-default:"1111"`
	Username string
	Password string `yaml:"password" env-default:"yourpassword"`
	Protocol string `yaml:"protocol" env-default:"tcp"`
}

type ListenConfig struct {
	Type   string `yaml:"type" env-default:"port"`
	Port   int    `yaml:"port" env-default:"8787"`
	BindIP string `yaml:"bind_ip" env-default:"0.0.0.0"`
}

type TokenConfig struct {
	AccessSecret  string        `env:"TOKEN_ACCESS_SECRET,required"`
	RefreshSecret string        `env:"TOKEN_REFRESH_SECRET,required"`
	AccessTTL     time.Duration `yaml:"access_ttl" env:"TOKEN_ACCESS_TTL" env-default:"15m"`    // ← добавил env тег!
	RefreshTTL    time.Duration `yaml:"refresh_ttl" env:"TOKEN_REFRESH_TTL" env-default:"168h"` // ← добавил env тег!
}

const (
	flagConfigPath = "config"
	envConfigPath  = "CONFIG_PATH"
)

var instance *Config
var once sync.Once

func GetConfig() *Config {
	once.Do(func() {
		var configPath string
		flag.StringVar(&configPath, flagConfigPath, "", "config file path")
		flag.Parse()

		if path, ok := os.LookupEnv(envConfigPath); ok {
			configPath = path
		}
		instance = &Config{}

		// 1. Сначала читаем yaml конфиг (если есть)
		if configPath != "" {
			errRead := cleanenv.ReadConfig(configPath, instance)
			if errRead != nil {
				desc, errDesc := cleanenv.GetDescription(instance, nil)
				if errDesc != nil {
					panic(errDesc)
				}
				slog.Info(desc)
				slog.Error("failed to read config",
					slog.String("err", errRead.Error()),
					slog.String("path", configPath))
				os.Exit(1)
			}
		}

		// 2. Затем читаем env переменные (имеют приоритет!)
		if err := cleanenv.ReadEnv(instance); err != nil {
			slog.Error("failed to read env variables",
				slog.String("error", err.Error()),
				slog.String("hint", "Check required env variables like TOKEN_ACCESS_SECRET"))
			os.Exit(1)
		}

		// 3. Валидация конфига
		if err := validateConfig(instance); err != nil {
			slog.Error("invalid config", slog.String("error", err.Error()))
			os.Exit(1)
		}

	})
	return instance
}

func validateConfig(cfg *Config) error {
	if cfg.Token.AccessSecret == "" {
		return errors.New("TOKEN_ACCESS_SECRET is required")
	}
	if cfg.Token.RefreshSecret == "" {
		return errors.New("TOKEN_REFRESH_SECRET is required")
	}
	return nil
}
