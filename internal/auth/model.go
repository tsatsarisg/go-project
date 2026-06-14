package auth

import (
	"time"

	"github.com/tsatsarisg/go-fit/internal/user"
)

type Token struct {
	Plaintext string      `json:"token"`
	Hash      []byte      `json:"-"`
	UserID    user.UserID `json:"-"`
	Expiry    time.Time   `json:"expiry"`
	Scope     string      `json:"-"`
}
