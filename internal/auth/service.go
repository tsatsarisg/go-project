package auth

import (
	"context"
	"errors"
	"time"

	"github.com/tsatsarisg/go-fit/internal/user"
)

// Store is the auth bounded context's persistence port. Defined consumer-side
// (D7). Owns token lifecycle (issue / revoke) and, for middleware, resolves a
// bearer plaintext to the Principal it represents. The JOIN against users
// lives behind this interface (see postgres_store.go) so token→identity
// resolution is owned by one boundary.
type Store interface {
	Issue(ctx context.Context, userID user.UserID, ttl time.Duration, scope string) (*Token, error)
	DeleteAllForUser(ctx context.Context, scope string, userID user.UserID) error
	ResolvePrincipal(ctx context.Context, scope, plaintext string) (*Principal, error)
}

// ErrInvalidCredentials is the single-body sentinel returned to the handler
// for both "user not found" and "wrong password". Keeping them identical at
// this layer (and in VerifyPassword's timing) is how C5's enumeration fix
// stays intact.
var ErrInvalidCredentials = errors.New("invalid credentials")

// tokenTTL is the default lifetime of a newly-issued authentication token.
// Pulled up into a service-local constant so the handler doesn't hardcode it.
const tokenTTL = 24 * time.Hour

// Service is the auth bounded context's application service. Owns login
// (verify-then-issue) and logout (revoke-all-for-user).
type Service struct {
	tokenStore Store
	userSvc    *user.Service
}

func NewService(tokenStore Store, userSvc *user.Service) *Service {
	return &Service{tokenStore: tokenStore, userSvc: userSvc}
}

type LoginCommand struct {
	Username string
	Password string
}

// Login verifies credentials and issues a fresh token. Returns
// ErrInvalidCredentials for both "no such user" and "wrong password" so the
// handler can map to 401 without leaking which branch matched.
//
// The ErrNotFound branch intentionally falls through to VerifyPassword with
// u == nil — VerifyPassword runs bcrypt against a package-level dummy hash
// in that case, so the response timing for "missing user" matches the
// "wrong password" path. Skipping bcrypt on ErrNotFound would reintroduce
// the enumeration side-channel C5 closed.
func (s *Service) Login(ctx context.Context, cmd LoginCommand) (*Token, error) {
	u, err := s.userSvc.FindByUsername(ctx, cmd.Username)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return nil, err
	}

	ok, err := user.VerifyPassword(u, cmd.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}

	return s.tokenStore.Issue(ctx, u.ID, tokenTTL, ScopeAuth)
}

// Logout revokes every auth-scoped token for the given principal.
func (s *Service) Logout(ctx context.Context, principalID user.UserID) error {
	return s.tokenStore.DeleteAllForUser(ctx, ScopeAuth, principalID)
}
