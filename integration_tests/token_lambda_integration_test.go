package integration_tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	tokenservice "github.com/HealthAura/token-service/gen/go/v1"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/keys"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lamdaPreflight struct {
	client  tokenservice.Client
	dpopKey *ecdsa.PrivateKey
}

func newLambdaClient(t *testing.T) lamdaPreflight {
	clientURL := os.Getenv("TOKEN_SERVICE_URL")
	client, err := tokenservice.NewClient(clientURL)
	require.Empty(t, err)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Empty(t, err)

	return lamdaPreflight{
		client:  *client,
		dpopKey: dpopKey,
	}
}

func TestTokenLambdaIntegration(t *testing.T) {
	preflight := newLambdaClient(t)

	type input struct {
		testFn func(t *testing.T)
	}

	cases := []struct {
		name  string
		input input
	}{
		{
			"successfully generates token",
			input{
				testFn: func(t *testing.T) {
					r := tokenservice.TokenServiceGenerateJSONRequestBody{
						Claims: &tokenservice.TokenserviceClaims{
							Aud:    strToPtr("test-audience"),
							Scopes: &[]string{"test-scope"},
							Iss:    strToPtr("test-issuer"),
							Jti:    strToPtr(uuid.NewString()),
							Sub:    strToPtr("test-subject"),
						},
						AccessTokenTtl:  strToPtr("5"),
						RefreshTokenTtl: strToPtr("60"),
						Dpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr(setupDPoPUnboundLambda(t, preflight)),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/token"),
								Rh:  strToPtr("test-rh"),
							},
							TtlMinutes: strToPtr("1"),
						},
					}

					resp, err := preflight.client.TokenServiceGenerate(context.Background(), r)
					require.Empty(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					v, err := io.ReadAll(resp.Body)
					assert.Empty(t, err)

					var genResp tokenservice.TokenserviceGenerateResponse
					err = json.Unmarshal(v, &genResp)
					require.Empty(t, err)
				},
			},
		},
		{
			"successfully refreshes token",
			input{
				testFn: func(t *testing.T) {
					r := tokenservice.TokenServiceGenerateJSONRequestBody{
						Claims: &tokenservice.TokenserviceClaims{
							Aud:    strToPtr("test-audience"),
							Scopes: &[]string{"test-scope"},
							Iss:    strToPtr("test-issuer"),
							Jti:    strToPtr(uuid.NewString()),
							Sub:    strToPtr("test-subject"),
						},
						AccessTokenTtl:  strToPtr("5"),
						RefreshTokenTtl: strToPtr("60"),
						Dpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr(setupDPoPUnboundLambda(t, preflight)),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/token"),
								Rh:  strToPtr("test-rh"),
							},
							TtlMinutes: strToPtr("1"),
						},
					}

					resp, err := preflight.client.TokenServiceGenerate(context.Background(), r)
					require.Empty(t, err)
					require.Equal(t, http.StatusOK, resp.StatusCode)

					v, err := io.ReadAll(resp.Body)
					require.Empty(t, err)

					var genResp tokenservice.TokenserviceGenerateResponse
					err = json.Unmarshal(v, &genResp)
					require.Empty(t, err)

					refreshR := tokenservice.TokenserviceRefreshRequest{
						AccessTokenTtl:  strToPtr("5"),
						RefreshTokenTtl: strToPtr("60"),
						RefreshToken:    genResp.RefreshToken,
						RefreshDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr(setupDPoPBoundLambda(t, preflight, *genResp.AccessToken)),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/token"),
								Rh:  strToPtr("test-rh"),
							},
							TtlMinutes: strToPtr("1"),
						},
						NewTokenDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr(setupDPoPUnboundLambda(t, preflight)),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/token"),
								Rh:  strToPtr("test-rh"),
							},
							TtlMinutes: strToPtr("1"),
						},
					}

					_, err = preflight.client.TokenServiceRefresh(context.Background(), refreshR)
					assert.Empty(t, err)
					assert.Equal(t, http.StatusOK, resp.StatusCode)
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.testFn(t)
		})
	}
}

func setupDPoPUnboundLambda(t *testing.T, preflight lamdaPreflight) string {
	r := tokenservice.TokenServiceGenerateNonceJSONRequestBody{
		Claims: &tokenservice.TokenserviceClaims{
			Aud:    strToPtr("test-audience"),
			Scopes: &[]string{"dpopnonce"},
			Iss:    strToPtr("test-issuer"),
			Jti:    strToPtr(uuid.NewString()),
			Sub:    strToPtr("test-subject"),
		},
		NonceTtl: strToPtr("5"),
	}

	resp, err := preflight.client.TokenServiceGenerateNonce(context.Background(), r)
	require.Empty(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	v, err := io.ReadAll(resp.Body)
	require.Empty(t, err)

	var nonceResp tokenservice.TokenserviceGenerateNonceResponse
	err = json.Unmarshal(v, &nonceResp)
	require.Empty(t, err)

	proof, err := jwt.EncodeProof(preflight.dpopKey, jwt.DPoPClaims{
		HTM:   http.MethodPost,
		HTU:   "https://example.com/token",
		IAT:   time.Now().Unix(),
		RH:    "test-rh",
		Nonce: *nonceResp.Nonce,
		JWT:   uuid.NewString(),
	})

	require.Empty(t, err)

	return proof
}

func setupDPoPBoundLambda(t *testing.T, preflight lamdaPreflight, accessToken string) string {
	r := tokenservice.TokenServiceGenerateNonceJSONRequestBody{
		Claims: &tokenservice.TokenserviceClaims{
			Aud:    strToPtr("test-audience"),
			Scopes: &[]string{"dpopnonce"},
			Iss:    strToPtr("test-issuer"),
			Jti:    strToPtr(uuid.NewString()),
			Sub:    strToPtr("test-subject"),
		},
		NonceTtl: strToPtr("5"),
	}

	resp, err := preflight.client.TokenServiceGenerateNonce(context.Background(), r)
	require.Empty(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	v, err := io.ReadAll(resp.Body)
	require.Empty(t, err)

	var nonceResp tokenservice.TokenserviceGenerateNonceResponse
	err = json.Unmarshal(v, &nonceResp)
	require.Empty(t, err)

	athBytes, err := keys.Sha256Hash([]byte(accessToken))
	require.Empty(t, err)

	proof, err := jwt.EncodeProof(preflight.dpopKey, jwt.DPoPClaims{
		HTM:   http.MethodPost,
		HTU:   "https://example.com/token",
		IAT:   time.Now().Unix(),
		RH:    "test-rh",
		Nonce: *nonceResp.Nonce,
		JWT:   uuid.NewString(),
		ATH:   base64.RawURLEncoding.EncodeToString(athBytes),
	})
	require.Empty(t, err)

	return proof
}

func strToPtr(s string) *string {
	return &s
}
