package tokenstore

import (
	"context"
	"time"
)

type NotFoundErr struct{}

func (e NotFoundErr) Error() string {
	return "token not found"
}

type Store interface {
	StoreToken(ctx context.Context, jwtToken string, ttl time.Duration) error
	GetToken(ctx context.Context, signature string) (string, error)
	DeleteToken(ctx context.Context, signature string) error
	DeleteTokenByATH(ctx context.Context, ath string) error
}
