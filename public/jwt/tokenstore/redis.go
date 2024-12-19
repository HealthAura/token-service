package tokenstore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/HealthAura/token-service/public/keys"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-redis/redis"
)

type redisStore struct {
	redisClient *redis.Client
	kmsClient   *kms.Client
	keyID       string
}

func NewRedis(redisClient *redis.Client, kmsClient *kms.Client, keyID string) Store {
	return redisStore{
		redisClient: redisClient,
		kmsClient:   kmsClient,
		keyID:       keyID,
	}
}

// StoreToken - stores the JWT token without signature in the redis store
func (s redisStore) StoreToken(ctx context.Context, jwtToken string, ttl time.Duration) error {
	// Split the JWT into its parts
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Combine header and payload without the signature
	tokenWithoutSignature := parts[0] + "." + parts[1]

	// Use the signature as the key
	signature := parts[2]
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	cipherText := []byte(tokenWithoutSignature)
	encryptInput := &kms.EncryptInput{
		KeyId:     &s.keyID,
		Plaintext: []byte(tokenWithoutSignature),
	}

	encResp, err := s.kmsClient.Encrypt(ctx, encryptInput)
	if err != nil {
		return fmt.Errorf("failed to encrypt redis data: %w", err)
	}

	cipherText = encResp.CiphertextBlob

	if err := s.redisClient.Set(base64.RawURLEncoding.EncodeToString(signatureHash), cipherText, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store token in redis: %w", err)
	}

	return nil
}

// StoreToken - stores the token in the redis store
func (s redisStore) GetToken(ctx context.Context, signature string) (string, error) {
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return "", fmt.Errorf("failed to hash signature: %w", err)
	}

	result, err := s.redisClient.Get(base64.RawURLEncoding.EncodeToString(signatureHash)).Result()
	if err != nil {
		return "", fmt.Errorf("failed to get token from redis: %w", err)
	}

	splitToken := result
	decryptInput := &kms.DecryptInput{
		CiphertextBlob: []byte(result),
	}

	decResp, err := s.kmsClient.Decrypt(ctx, decryptInput)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt redis data: %w", err)
	}

	splitToken = string(decResp.Plaintext)

	return fmt.Sprintf("%s.%s", splitToken, signature), nil
}

func (s redisStore) DeleteToken(ctx context.Context, signature string) error {
	signatureHash, err := keys.Sha256Hash([]byte(signature))
	if err != nil {
		return fmt.Errorf("failed to hash signature: %w", err)
	}

	result, err := s.redisClient.Del(base64.RawURLEncoding.EncodeToString(signatureHash)).Result()
	if err != nil {
		return fmt.Errorf("failed to delete token from redis: %w", err)
	}

	if result != 1 {
		return errors.New("failed to delete token")
	}

	return nil
}

func (s redisStore) DeleteTokenByATH(ctx context.Context, ath string) error {
	result, err := s.redisClient.Del(ath).Result()
	if err != nil {
		return fmt.Errorf("failed to delete token from redis: %w", err)
	}

	if result != 1 {
		return NotFoundErr{}
	}

	return nil
}
