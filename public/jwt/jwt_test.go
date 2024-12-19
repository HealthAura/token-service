package jwt_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	cjwt "github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/jwt/tokenstore/tokenstoremock"
	"github.com/HealthAura/token-service/public/keys"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/require"
)

func TestDPoP(t *testing.T) {
	type input struct {
		privateKeyFn   func(t *testing.T) *ecdsa.PrivateKey
		validateVerify func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey)
	}

	cases := []struct {
		name  string
		input input
	}{
		{
			"successfully generates new token with dpop proof",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					_, err = orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)
				},
			},
		},
		{
			"successfully validates token bound by proof",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{},
					})
					require.Empty(t, err)
				},
			},
		},
		{
			"handles invalid htm",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm-invalid",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					_, err = orch.GenerateToken(ctx, tokenInput)
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "expected htm-invalid, got htm")
				},
			},
		},
		{
			"handles invalid htu",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu-invalid",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					_, err = orch.GenerateToken(ctx, tokenInput)
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "expected htu-invalid, got htu")
				},
			},
		},
		{
			"handles invalid rh",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh-invalid",
						DPopTTL:     time.Minute,
					}

					_, err = orch.GenerateToken(ctx, tokenInput)
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "expected rh-invalid, got rh")
				},
			},
		},
		{
			"handles invalid ath",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath-invalid",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "ath does not match token hash")
				},
			},
		},
		{
			"handles invalid nonce",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: "invalid-nonce",
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					_, err = orch.GenerateToken(ctx, tokenInput)
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "failed to validate and verify nonce")
				},
			},
		},
		{
			"handles dpop with invalid signature",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: "invalid-nonce",
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					_, err = orch.GenerateToken(ctx, tokenInput)
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "failed to validate and verify nonce")
				},
			},
		},
		{
			"handles token with invalid signature",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					maliciousKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					maliciousKMS := &mockKMSClient{
						privateKey: maliciousKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					maliciousOrch := cjwt.New(maliciousKMS, "keyID", "https://healthaura.test", store)
					nonce, err := maliciousOrch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := maliciousOrch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = maliciousOrch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "token JWT signature is invalid")
				},
			},
		},
		{
			"handles expired token",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(-time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "token has expired")
				},
			},
		},
		{
			"token is not yet valid",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Add(time.Hour * 2).Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "token is not yet valid")
				},
			},
		},
		{
			"handles issue at failure",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Add(time.Hour).Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "token issue time is in the future")
				},
			},
		},
		{
			"handles missing token scopes but required",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{"NeedScope"},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "token has no scopes")
				},
			},
		},
		{
			"handles token having wrong scopes",
			input{
				privateKeyFn: func(t *testing.T) *ecdsa.PrivateKey {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					require.Empty(t, err)
					return privateKey
				},
				validateVerify: func(t *testing.T, tokenServiceKey *ecdsa.PrivateKey, dpopKey *ecdsa.PrivateKey) {
					ctx := context.Background()
					store := &tokenstoremock.Store{
						Store: map[string]string{},
					}

					kms := &mockKMSClient{
						privateKey: tokenServiceKey,
					}

					orch := cjwt.New(kms, "keyID", "https://healthaura.test", store)
					nonce, err := orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err := cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   "ath",
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					tokenInput := cjwt.GenerateTokenInput{
						Claims: cjwt.Claims{
							Issuer:         "test-issuer",
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"somescope"},
						},
						Proof:       proof,
						ExpectedHTM: "htm",
						ExpectedHTU: "htu",
						ExpectedRH:  "rh",
						DPopTTL:     time.Minute,
					}

					token, err := orch.GenerateToken(ctx, tokenInput)
					require.Empty(t, err)

					tokenHash, err := keys.Sha256Hash([]byte(token))
					require.Empty(t, err)

					nonce, err = orch.GenerateNonce(ctx, cjwt.GenerateNonceInput{
						Claims: cjwt.Claims{
							Subject:        "test-subject",
							Audience:       "test-audience",
							ExpirationTime: time.Now().Add(time.Hour).Unix(),
							NotBefore:      time.Now().Unix(),
							IssuedAt:       time.Now().Unix(),
							Scopes:         []string{"dpopnonce"},
						},
					})
					require.Empty(t, err)

					proof, err = cjwt.EncodeProof(dpopKey, cjwt.DPoPClaims{
						JWT:   "jwt",
						HTM:   "htm",
						HTU:   "htu",
						IAT:   time.Now().Unix(),
						ATH:   base64.RawURLEncoding.EncodeToString(tokenHash),
						RH:    "rh",
						Nonce: nonce,
					})
					require.Empty(t, err)

					err = orch.ValidateAndVerify(ctx, cjwt.ValidateAndVerifyInput{
						Token:          token,
						Proof:          proof,
						ExpectedHTM:    "htm",
						ExpectedHTU:    "htu",
						ExpectedRH:     "rh",
						RequiredScopes: []string{"NeedScope"},
					})
					require.NotEmpty(t, err)
					require.Contains(t, err.Error(), "missing required scope: NeedScope")
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tokenServiceKey := tt.input.privateKeyFn(t)
			dpopKey := tt.input.privateKeyFn(t)

			tt.input.validateVerify(t, tokenServiceKey, dpopKey)
		})
	}
}

type mockKMSClient struct {
	privateKey *ecdsa.PrivateKey
}

func (m mockKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	hash := sha256.Sum256(params.Message)
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	return &kms.SignOutput{
		Signature: signature,
	}, nil
}

func (m mockKMSClient) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	hash := sha256.Sum256(params.Message)

	r := new(big.Int).SetBytes(params.Signature[:len(params.Signature)/2])
	s := new(big.Int).SetBytes(params.Signature[len(params.Signature)/2:])

	valid := ecdsa.Verify(&m.privateKey.PublicKey, hash[:], r, s)

	return &kms.VerifyOutput{
		SignatureValid: valid,
	}, nil
}
