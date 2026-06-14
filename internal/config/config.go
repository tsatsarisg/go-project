package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

const (
	EnvProduction  = "production"
	EnvDevelopment = "development"
)

// Config holds runtime configuration loaded from the environment.
type Config struct {
	DatabaseURL string
	Port        int
	Env         string
}

// Load reads configuration from the environment. It attempts to load a local
// `.env` file, but silently ignores the "file not found" case so production
// (where no .env exists) keeps working.
func Load() (*Config, error) {
	// Ignore os.IsNotExist; any other error is worth surfacing.
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		// godotenv wraps errors with fmt.Errorf, so also fall back to
		// checking the error string as a pragmatic last resort.
		if !strings.Contains(err.Error(), "no such file") {
			return nil, fmt.Errorf("failed to load .env: %w", err)
		}
	}

	env := getEnv("APP_ENV", EnvDevelopment)

	port, err := strconv.Atoi(getEnv("PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid PORT: %w", err)
	}

	dsn, err := resolveDatabaseURL(env)
	if err != nil {
		return nil, err
	}

	return &Config{
		DatabaseURL: dsn,
		Port:        port,
		Env:         env,
	}, nil
}

// IsProduction reports whether the config is targeting a production environment.
func (c *Config) IsProduction() bool {
	return c.Env == EnvProduction
}

// resolveDatabaseURL prefers DATABASE_URL when set and falls back to the
// discrete PG* variables so both container-style and local-dev flows work.
func resolveDatabaseURL(env string) (string, error) {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		return enforceSSLMode(dsn, env)
	}

	host := getEnv("PGHOST", "localhost")
	port := getEnv("PGPORT", "5432")
	user := getEnv("PGUSER", "postgres")
	password := getEnv("PGPASSWORD", "postgres")
	dbname := getEnv("PGDATABASE", "postgres")
	sslmode := os.Getenv("PGSSLMODE")
	if sslmode == "" {
		if env == EnvProduction {
			sslmode = "require"
		} else {
			sslmode = "disable"
		}
	}

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)
	return enforceSSLMode(dsn, env)
}

// enforceSSLMode ensures production DSNs carry a secure sslmode. In dev it is
// a no-op; in production it appends sslmode=require when missing, and rejects
// an explicit insecure sslmode.
func enforceSSLMode(dsn, env string) (string, error) {
	if env != EnvProduction {
		return dsn, nil
	}

	lower := strings.ToLower(dsn)
	if !strings.Contains(lower, "sslmode=") {
		// Append sslmode depending on DSN style (URL vs keyword).
		if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
			sep := "?"
			if strings.Contains(dsn, "?") {
				sep = "&"
			}
			return dsn + sep + "sslmode=require", nil
		}
		return dsn + " sslmode=require", nil
	}

	if strings.Contains(lower, "sslmode=disable") {
		return "", fmt.Errorf("sslmode=disable is not allowed when APP_ENV=%s", EnvProduction)
	}
	return dsn, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
