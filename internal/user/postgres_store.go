package user

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tsatsarisg/go-fit/internal/platform/postgres"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (store *PostgresStore) CreateUser(ctx context.Context, user *User) error {
	query := `INSERT INTO users (username, email, password_hash, bio)
			  VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	err := store.db.QueryRowContext(ctx, query, user.Username, string(user.Email), user.PasswordHash.hash, user.Bio).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return postgres.ClassifyError(err)
	}
	return nil
}

func (store *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{
		PasswordHash: password{},
	}
	query := `SELECT id, username, email, password_hash, bio, created_at, updated_at FROM users WHERE username = $1`
	row := store.db.QueryRowContext(ctx, query, username)

	// Email scans into a *string buffer first then is typed; keeps database/sql
	// happy without requiring a custom sql.Scanner on the VO.
	var emailStr string
	err := row.Scan(&user.ID, &user.Username, &emailStr, &user.PasswordHash.hash, &user.Bio, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	user.Email = Email(emailStr)
	return user, nil
}
