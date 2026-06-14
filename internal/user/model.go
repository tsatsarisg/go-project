package user

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserID is a named int64 wrapping the users.id column. Named so the compiler
// refuses to accept (say) a workout id where a user id is expected — kills
// the id-mixup bug class D2 calls out. int64 matches the DB BIGSERIAL and
// also incidentally resolves L3 (ReadIdParam returns int64).
type UserID int64

// Email is a normalized, syntactically-valid email address. Zero value is
// not a valid Email; construct via NewEmail. String-backed so database/sql
// Scan and encoding/json marshal work without custom methods.
type Email string

// NewEmail parses s with net/mail.ParseAddress and returns it lowercased.
// Normalization is intentional: it collapses case variants so the unique
// constraint on users.email catches them.
func NewEmail(s string) (Email, error) {
	if s == "" {
		return "", errors.New("email is required")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("invalid email: %w", err)
	}
	return Email(strings.ToLower(addr.Address)), nil
}

func (e Email) String() string { return string(e) }

// password wraps a bcrypt hash. The field is unexported and the type has no
// setter — instances come only from HashPassword or a DB scan — so plaintext
// is never retained on the value. Zero value (nil hash) is meaningful only
// for the timing-equalization path in VerifyPassword.
type password struct {
	hash []byte
}

type User struct {
	ID           UserID    `json:"id"`
	Username     string    `json:"username"`
	Email        Email     `json:"email"`
	PasswordHash password  `json:"-"`
	Bio          string    `json:"bio,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

var dummyPasswordHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("timing-equalization-dummy"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}()

// VerifyPassword runs bcrypt against the user's hash, or against a fixed dummy
// hash when user is nil, so response timing does not reveal whether the
// username existed. Returns (true, nil) only on a real match.
func VerifyPassword(user *User, plainText string) (bool, error) {
	hash := dummyPasswordHash
	if user != nil {
		hash = user.PasswordHash.hash
	}
	err := bcrypt.CompareHashAndPassword(hash, []byte(plainText))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return user != nil, nil
}
