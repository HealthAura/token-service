package tokenstore

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/HealthAura/token-service/public/keys"
)

type local struct {
	db map[string]string
}

func NewLocal() Store {
	return &local{
		db: make(map[string]string),
	}
}

func (l *local) StoreToken(ctx context.Context, jwtToken string, ttl time.Duration) error {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	tokenWithoutSignature := parts[0] + "." + parts[1]
	signature := parts[2]
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	l.db[base64.RawURLEncoding.EncodeToString(signatureHash)] = tokenWithoutSignature

	return nil
}

func (l *local) GetToken(ctx context.Context, signature string) (string, error) {
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return "", fmt.Errorf("failed to hash signature: %w", err)
	}

	splitToken, ok := l.db[base64.RawURLEncoding.EncodeToString(signatureHash)]
	if !ok {
		return "", fmt.Errorf("failed to find split token with signature %s", signature)
	}

	return fmt.Sprintf("%s.%s", splitToken, signature), nil
}

func (l *local) DeleteToken(ctx context.Context, signature string) error {
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	delete(l.db, base64.RawURLEncoding.EncodeToString(signatureHash))

	return nil
}

func (l *local) DeleteTokenByATH(ctx context.Context, ath string) error {
	return nil
}
