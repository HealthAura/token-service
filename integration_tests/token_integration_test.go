package integration_tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/HealthAura/token-service/config"
	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
	"github.com/HealthAura/token-service/internal/server"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/jwt/tokenstore"
	"github.com/HealthAura/token-service/public/keys"
	"github.com/aws/aws-lambda-go/events"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type preflight struct {
	client  tokenservice.TokenServiceClient
	jwtOrch jwt.Orchestrator
	dpopKey *ecdsa.PrivateKey
}

func newTestClient(t *testing.T) preflight {
	cfg, err := config.Load()
	require.Empty(t, err)

	if cfg.Service.DevelopmentMode {
		return newLocalClient(t, cfg)
	}

	return newDeployedClient(t, cfg)
}

func newDeployedClient(t *testing.T, cfg *config.Config) preflight {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	awsConfig, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"))
	require.Empty(t, err)

	kmsClient := kms.NewFromConfig(awsConfig)
	redisClient := redis.NewClient(&redis.Options{
		Addr:      cfg.Service.RedisURL,
		DB:        0, // use default DB
		TLSConfig: &tls.Config{},
	})

	store := tokenstore.New(
		redisClient,
		kmsClient,
		cfg.Service.DatabaseKeyARN,
		false,
	)

	orch := jwt.New(kmsClient, cfg.Service.SigningKeyARN, cfg.Service.Issuer, store)

	conn, err := grpc.DialContext(
		ctx,
		cfg.Service.TestURI,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.Empty(t, err)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Empty(t, err)

	return preflight{
		client:  tokenservice.NewTokenServiceClient(conn),
		jwtOrch: orch,
		dpopKey: dpopKey,
	}
}

func newLocalClient(t *testing.T, cfg *config.Config) preflight {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	v, err := base64.RawURLEncoding.DecodeString(cfg.Service.DevelopmentSigningKey)
	require.Empty(t, err)
	privKey, err := keys.DeserializePrivateKey(v)
	require.Empty(t, err)

	kmsClient := &mockKMSClient{
		privateKey: privKey,
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
		DB:   0,
	})

	store := tokenstore.New(
		redisClient,
		nil,
		cfg.Service.DatabaseKeyARN,
		true,
	)

	orch := jwt.New(kmsClient, cfg.Service.SigningKeyARN, cfg.Service.Issuer, store)

	conn, err := grpc.DialContext(
		ctx,
		cfg.Service.TestURI,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.Empty(t, err)

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Empty(t, err)

	return preflight{
		client:  tokenservice.NewTokenServiceClient(conn),
		jwtOrch: orch,
		dpopKey: dpopKey,
	}
}

func TestTokenGRPCIntegration(t *testing.T) {
	preflight := newTestClient(t)

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
					_, err := preflight.client.Generate(context.Background(), &tokenservice.GenerateRequest{
						Claims:          &tokenservice.Claims{},
						AccessTokenTtl:  5,
						RefreshTokenTtl: 60,
						Dpop: &tokenservice.DPoP{
							Proof: setupDPoPUnbound(t, preflight),
							WantClaims: &tokenservice.DPoPClaims{
								Htm: "POST",
								Htu: "https://example.com/token",
								Rh:  "test-rh",
							},
						},
					})
					assert.Empty(t, err)
				},
			},
		},
		{
			"successfully refreshes token",
			input{
				testFn: func(t *testing.T) {
					resp, err := preflight.client.Generate(context.Background(), &tokenservice.GenerateRequest{
						Claims:          &tokenservice.Claims{},
						AccessTokenTtl:  5,
						RefreshTokenTtl: 60,
						Dpop: &tokenservice.DPoP{
							Proof: setupDPoPUnbound(t, preflight),
							WantClaims: &tokenservice.DPoPClaims{
								Htm: "POST",
								Htu: "https://example.com/token",
								Rh:  "test-rh",
							},
						},
					})
					require.Empty(t, err)

					_, err = preflight.client.Refresh(context.Background(), &tokenservice.RefreshRequest{
						RefreshToken:    resp.RefreshToken,
						AccessTokenTtl:  5,
						RefreshTokenTtl: 60,
						RefreshDpop: &tokenservice.DPoP{
							Proof: setupDPoPBound(t, preflight, resp.RefreshToken),
							WantClaims: &tokenservice.DPoPClaims{
								Htm: "POST",
								Htu: "https://example.com/token",
								Rh:  "test-rh",
							},
						},
						NewTokenDpop: &tokenservice.DPoP{
							Proof: setupDPoPUnbound(t, preflight),
							WantClaims: &tokenservice.DPoPClaims{
								Htm: "POST",
								Htu: "https://example.com/token",
								Rh:  "test-rh",
							},
						},
					})
					assert.Empty(t, err)
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

func TestTokenLambdaIntegration(t *testing.T) {
	zlog, _ := zap.NewDevelopment()
	application, err := server.NewApplication(context.Background())
	if err != nil {
		t.Fatalf("failed to create application: %s", err)
	}

	handler := server.StartLambda(application, zlog)
	preflight := newTestClient(t)

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

					req := &tokenservice.GenerateRequest{
						Claims:          &tokenservice.Claims{},
						AccessTokenTtl:  5,
						RefreshTokenTtl: 60,
						Dpop: &tokenservice.DPoP{
							Proof: setupDPoPUnbound(t, preflight),
							WantClaims: &tokenservice.DPoPClaims{
								Htm: "POST",
								Htu: "https://example.com/token",
								Rh:  "test-rh",
							},
						},
					}

					v, err := json.Marshal(req)
					require.Empty(t, err)

					_, err = handler(context.Background(), events.APIGatewayProxyRequest{
						Body: string(v),
					})
					assert.Empty(t, err)
				},
			},
		},
		{
			"successfully refreshes token",
			input{
				testFn: func(t *testing.T) {
					req := &tokenservice.GenerateRequest{
						Claims:          &tokenservice.Claims{},
						AccessTokenTtl:  5,
						RefreshTokenTtl: 60,
						Dpop: &tokenservice.DPoP{
							Proof: setupDPoPUnbound(t, preflight),
							WantClaims: &tokenservice.DPoPClaims{
								Htm: "POST",
								Htu: "https://example.com/token",
								Rh:  "test-rh",
							},
						},
					}

					v, err := json.Marshal(req)
					require.Empty(t, err)

					_, err = handler(context.Background(), events.APIGatewayProxyRequest{
						Body: string(v),
					})
					assert.Empty(t, err)
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

func setupDPoPUnbound(t *testing.T, preflight preflight) string {
	resp, err := preflight.client.GenerateNonce(context.Background(), &tokenservice.GenerateNonceRequest{
		Claims: &tokenservice.Claims{
			Subject:  "test-subject",
			Audience: "test-audience",
			Scopes:   []string{"dpopnonce"},
		},
		NonceTtl: 5,
	})
	require.Empty(t, err)

	proof, err := jwt.EncodeProof(preflight.dpopKey, jwt.DPoPClaims{
		HTM:   http.MethodPost,
		HTU:   "https://example.com/token",
		IAT:   time.Now().Unix(),
		RH:    "test-rh",
		Nonce: resp.Nonce,
		JWT:   uuid.NewString(),
	})
	require.Empty(t, err)

	return proof
}

func setupDPoPBound(t *testing.T, preflight preflight, accessToken string) string {
	resp, err := preflight.client.GenerateNonce(context.Background(), &tokenservice.GenerateNonceRequest{
		Claims: &tokenservice.Claims{
			Subject:  "test-subject",
			Audience: "test-audience",
			Scopes:   []string{"dpopnonce"},
		},
		NonceTtl: 5,
	})
	require.Empty(t, err)

	athBytes, err := keys.Sha256Hash([]byte(accessToken))
	require.Empty(t, err)

	proof, err := jwt.EncodeProof(preflight.dpopKey, jwt.DPoPClaims{
		HTM:   http.MethodPost,
		HTU:   "https://example.com/token",
		IAT:   time.Now().Unix(),
		RH:    "test-rh",
		Nonce: resp.Nonce,
		JWT:   uuid.NewString(),
		ATH:   base64.RawURLEncoding.EncodeToString(athBytes),
	})
	require.Empty(t, err)

	return proof
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
