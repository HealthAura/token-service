package tokenstoremock

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/HealthAura/token-service/public/jwt/tokenstore"
	"github.com/HealthAura/token-service/public/keys"
)

const (
	StoreTokenErr  = "StoreTokenErr"
	GetTokenErr    = "GetTokenErr"
	DeleteTokenErr = "DeleteTokenErr"
)

var _ tokenstore.Store = &Store{}

type Store struct {
	StoreTokenErr  bool
	GetTokenErr    bool
	DeleteTokenErr bool

	Store map[string]string
}

func (s *Store) StoreToken(ctx context.Context, jwtToken string, ttl time.Duration) error {
	if s.StoreTokenErr {
		return errors.New(StoreTokenErr)
	}

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

	s.Store[base64.RawURLEncoding.EncodeToString(signatureHash)] = tokenWithoutSignature

	return nil
}

func (s *Store) GetToken(ctx context.Context, signature string) (string, error) {
	if s.GetTokenErr {
		return "", errors.New(GetTokenErr)
	}

	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return "", fmt.Errorf("failed to hash signature: %w", err)
	}

	token, ok := s.Store[base64.RawURLEncoding.EncodeToString(signatureHash)]
	if !ok {
		return "", errors.New("token not found")
	}

	return token + "." + signature, nil
}

func (s *Store) DeleteToken(ctx context.Context, signature string) error {
	if s.DeleteTokenErr {
		return errors.New(DeleteTokenErr)
	}

	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	delete(s.Store, base64.RawURLEncoding.EncodeToString(signatureHash))

	return nil
}

func (s *Store) DeleteTokenByATH(ctx context.Context, ath string) error {
	delete(s.Store, ath)

	return nil
}
