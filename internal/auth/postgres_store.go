package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tsatsarisg/go-fit/internal/user"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Issue mints a fresh token and persists the hashed projection. Returns the
// full Token including plaintext so the caller can hand it back to the client
// (it is never recoverable after this call). Renamed from CreateNewToken per
// D3 to align with ubiquitous language ("issue a token").
func (pts *PostgresStore) Issue(ctx context.Context, userID user.UserID, ttl time.Duration, scope string) (*Token, error) {
	token, err := GenerateToken(userID, ttl, scope)
	if err != nil {
		return nil, err
	}

	if err := pts.insert(ctx, token); err != nil {
		return nil, err
	}

	return token, nil
}

// insert persists the hashed token row. Unexported because Issue is the only
// caller and the auth.Store port no longer exposes a raw insert.
func (pts *PostgresStore) insert(ctx context.Context, token *Token) error {
	query := `
		INSERT INTO tokens (hash, user_id, expiry, scope)
		VALUES ($1, $2, $3, $4)`

	_, err := pts.db.ExecContext(ctx, query, token.Hash, token.UserID, token.Expiry, token.Scope)
	return err
}

func (pts *PostgresStore) DeleteAllForUser(ctx context.Context, scope string, userID user.UserID) error {
	query := `
		DELETE FROM tokens
		WHERE scope = $1 AND user_id = $2`

	_, err := pts.db.ExecContext(ctx, query, scope, userID)
	return err
}

// ResolvePrincipal hashes the plaintext and looks up the matching non-expired
// token, returning a minimal Principal (ID + Username). Returns (nil, nil)
// when the token is unknown or expired — callers treat that as "anonymous"
// rather than as an error so routine unauthenticated traffic doesn't log-spam.
func (pts *PostgresStore) ResolvePrincipal(ctx context.Context, scope, plaintext string) (*Principal, error) {
	tokenHash := HashPlaintext(plaintext)
	query := `SELECT u.id, u.username
	          FROM users u
	          INNER JOIN tokens t ON u.id = t.user_id
	          WHERE t.scope = $1 AND t.hash = $2 AND t.expiry > $3`

	p := &Principal{}
	err := pts.db.QueryRowContext(ctx, query, scope, tokenHash, time.Now()).Scan(&p.ID, &p.Username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}
