package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"golang.org/x/crypto/bcrypt"

	"github.com/tsatsarisg/go-fit/internal/auth"
	"github.com/tsatsarisg/go-fit/internal/config"
	"github.com/tsatsarisg/go-fit/internal/httpx"
	"github.com/tsatsarisg/go-fit/internal/platform/postgres"
	"github.com/tsatsarisg/go-fit/internal/user"
	"github.com/tsatsarisg/go-fit/internal/workout"
	"github.com/tsatsarisg/go-fit/migrations"
)

// Application is the assembled, runnable server. Handlers, middleware, and
// stores are unexported because callers (main, tests) only need Run / Close.
// The old god-struct exposing every handler field is gone (A4): wiring lives
// here, and nothing outside this package can bypass it.
type Application struct {
	cfg    *config.Config
	logger *slog.Logger
	db     *sql.DB
	server *http.Server
}

// New wires up the application: opens the DB, runs migrations, constructs
// stores/services/handlers, assembles the router, and returns an Application
// ready for Run. ctx bounds the initial DB ping (slow startup fails fast).
func New(ctx context.Context, cfg *config.Config) (*Application, error) {
	logger := httpx.NewLogger(httpx.NewHandler(os.Stdout, cfg.IsProduction()))

	// Pretty-print JSON response bodies in development for readability;
	// compact in production to minimize payload size and CPU.
	httpx.SetPrettyJSON(!cfg.IsProduction())

	openCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pgDB, err := postgres.Open(openCtx, cfg.DatabaseURL, logger)
	if err != nil {
		return nil, err
	}

	if err := postgres.MigrateFS(pgDB, migrations.FS, "."); err != nil {
		_ = pgDB.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	logger.InfoContext(ctx, "database migrated")

	// Adapters
	workoutStore := workout.NewPostgresStore(pgDB)
	userStore := user.NewPostgresStore(pgDB)
	tokenStore := auth.NewPostgresStore(pgDB)

	// Services
	hasher := user.NewBcryptHasher(bcrypt.DefaultCost)
	userSvc := user.NewService(userStore, hasher)
	workoutSvc := workout.NewService(workoutStore)
	authSvc := auth.NewService(tokenStore, userSvc)

	// Handlers
	workoutH := workout.NewHandler(workoutSvc, logger)
	userH := user.NewHandler(userSvc, logger)
	tokenH := auth.NewHandler(authSvc, logger)

	// Middleware
	authMW := auth.NewMiddleware(tokenStore)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(httpx.Recoverer(logger))
	r.Use(httpx.RequestLogger(logger))
	r.Use(authMW.Authenticate)

	r.Get("/health", healthCheck)
	r.Post("/users", userH.HandleRegisterUser)
	r.Post("/tokens/authentication", tokenH.HandleCreateToken)
	r.Post("/tokens/authentication/logout", authMW.RequireAuthenticatedUser(tokenH.HandleLogout))

	r.Get("/workouts/{id}", authMW.RequireAuthenticatedUser(workoutH.HandleGetWorkoutByID))
	r.Post("/workouts", authMW.RequireAuthenticatedUser(workoutH.HandleCreateWorkout))
	// PATCH — body is a partial-merge patch (nil fields = untouched), not
	// a full replacement, so PATCH is the correct verb per RFC 5789.
	r.Patch("/workouts/{id}", authMW.RequireAuthenticatedUser(workoutH.HandleUpdateWorkout))
	r.Delete("/workouts/{id}", authMW.RequireAuthenticatedUser(workoutH.HandleDeleteWorkout))

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return &Application{
		cfg:    cfg,
		logger: logger,
		db:     pgDB,
		server: server,
	}, nil
}

// Run starts the HTTP server and blocks until either the server fails or
// ctx is cancelled (signal received). On cancellation, performs a bounded
// graceful shutdown; if that fails, forcibly closes the server.
func (a *Application) Run(ctx context.Context) error {
	a.logger.InfoContext(ctx, "server starting",
		slog.String("addr", a.server.Addr),
		slog.String("env", a.cfg.Env),
	)

	serverErrCh := make(chan error, 1)
	go func() {
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	select {
	case err := <-serverErrCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil

	case <-ctx.Done():
		a.logger.InfoContext(ctx, "shutdown signal received")

		// Detach from the parent ctx so we still get the full shutdown budget
		// after the signal-cancel.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := a.server.Shutdown(shutdownCtx); err != nil {
			a.logger.ErrorContext(ctx, "graceful shutdown failed", slog.Any("err", err))
			if cerr := a.server.Close(); cerr != nil {
				a.logger.ErrorContext(ctx, "forced server close failed", slog.Any("err", cerr))
			}
			return fmt.Errorf("server shutdown: %w", err)
		}

		a.logger.InfoContext(ctx, "server stopped cleanly")
		return nil
	}
}

// Close releases long-lived resources (currently just the DB pool). Safe to
// call after Run; safe to defer in main.
func (a *Application) Close() error {
	a.logger.Info("closing database")
	return a.db.Close()
}

// healthCheck is a bare liveness probe. No logging (L2 fix): health checks
// hit on every ELB heartbeat and logging each would dominate the log volume.
func healthCheck(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
