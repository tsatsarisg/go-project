package user

import (
	"context"
	"errors"
	"fmt"
)

// Store is the user bounded context's persistence port. Defined on the
// consumer side (D7) so transport/service owns the contract; postgres_store.go
// supplies the adapter. Token → user resolution no longer lives here —
// auth.Store owns that now — so this surface is just "manage the user row".
type Store interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
}

// Domain-level sentinels for the user bounded context.
//   - ErrValidation: invariant / input-shape failure → 400 via errors.Is
//   - ErrNotFound:   username does not exist in the users table → callers that
//     need timing parity with "user exists but wrong password"
//     (e.g. auth.Login) convert to a nil user at their boundary
//     and still run bcrypt via user.VerifyPassword.
var (
	ErrValidation = errors.New("user validation failed")
	ErrNotFound   = errors.New("user not found")
)

// Service is the user bounded context's application service. Owns register
// orchestration (validate → hash → persist) so handlers stay thin. Takes a
// Hasher (D6) rather than calling bcrypt directly so test wiring can swap in
// a cheap-cost hasher without the service caring.
type Service struct {
	store  Store
	hasher Hasher
}

func NewService(store Store, hasher Hasher) *Service {
	return &Service{store: store, hasher: hasher}
}

// RegisterCommand captures the minimum fields needed to create a user. The
// plaintext password is part of the command by necessity, but never leaves
// the service boundary — Service.Register hashes it before any store call.
type RegisterCommand struct {
	Username string
	Email    string
	Password string
	Bio      string
}

// minPasswordLen matches the H4 policy (raised from 6 to 12 for basic
// resistance to offline brute force on stolen hashes).
const minPasswordLen = 12

func (c *RegisterCommand) Validate() error {
	if c.Username == "" || c.Password == "" {
		return errors.New("missing required fields")
	}
	if len(c.Password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters long", minPasswordLen)
	}
	return nil
}

func (s *Service) Register(ctx context.Context, cmd RegisterCommand) (*User, error) {
	if err := cmd.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidation, err)
	}

	// Email validation lives on the VO so it's applied anywhere an Email is
	// constructed — not only in registration. Normalizes case as a side-effect.
	email, err := NewEmail(cmd.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidation, err)
	}

	hash, err := s.hasher.Hash(cmd.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u := &User{
		Username:     cmd.Username,
		Email:        email,
		Bio:          cmd.Bio,
		PasswordHash: hash,
	}
	if err := s.store.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// FindByUsername returns (nil, ErrNotFound) for "no such user" and a non-nil
// User for the happy path — normal Go convention (L9). Callers in the login
// flow must be careful to preserve timing: see auth.Service.Login, which
// folds ErrNotFound into a nil User so VerifyPassword still runs bcrypt
// against the package-level dummy hash.
func (s *Service) FindByUsername(ctx context.Context, username string) (*User, error) {
	return s.store.GetUserByUsername(ctx, username)
}
