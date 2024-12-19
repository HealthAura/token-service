package tokens

// import (
// 	"context"
// 	"crypto/ecdsa"
// 	"crypto/elliptic"
// 	"crypto/rand"
// 	"encoding/base64"
// 	"encoding/json"
// 	"testing"
// 	"time"

// 	"github.com/pkg/errors"
// 	"github.com/stretchr/testify/assert"
// 	tokenservice "github.com/HealthAura/token-service/gen/token-service.v1"
// 	"github.com/HealthAura/token-service/public/dpop"
// 	"github.com/HealthAura/token-service/public/keys"
// 	"github.com/HealthAura/token-service/public/tokens"
// 	"github.com/HealthAura/token-service/public/tokens/validator/tokenstore"
// 	"github.com/HealthAura/token-service/public/tokens/validator/tokenstore/tokenstoremock"
// )

// func TestGenerateUnit(t *testing.T) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	goldenProof, _ := generateProof(t)
// 	invalidSignatureProof, _ := generateProofWithBadSignature(t)

// 	type input struct {
// 		req                 *tokenservice.GenerateRequest
// 		store               tokenstore.Store
// 		validateDPoPNonceFn validateDPoPNonceFn
// 	}

// 	type want struct {
// 		err string
// 	}

// 	cases := []struct {
// 		name  string
// 		input input
// 		want  want
// 	}{
// 		{
// 			"handles failure to decode dpop proof",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: "garbage",
// 					},
// 				},
// 			},
// 			want{
// 				err: "failed to decode dpop proof",
// 			},
// 		},
// 		{
// 			"handles invalid proof signature",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: invalidSignatureProof,
// 					},
// 				},
// 			},
// 			want{
// 				err: "dpop proof has invalid signature",
// 			},
// 		},
// 		{
// 			"handles invalid claims",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod: "somemethod",
// 						},
// 					},
// 				},
// 			},
// 			want{
// 				err: "dpop proof has invalid claims",
// 			},
// 		},
// 		{
// 			"handles failure to validate dpop nonce",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod:        "/some/method",
// 							GrpcRequestDigest: []byte("somedigest"),
// 							Ttl:               60, // seconds
// 						},
// 					},
// 				},
// 				validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 					return nil, errors.New("failed to validate dpop nonce")
// 				},
// 			},
// 			want{
// 				err: "failed to validate dpop nonce",
// 			},
// 		},
// 		{
// 			"handles dpop nonce invalid",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod:        "/some/method",
// 							GrpcRequestDigest: []byte("somedigest"),
// 							Ttl:               60, // seconds
// 						},
// 					},
// 				},
// 				validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 					return &tokenservice.ValidateResponse{
// 						ValidationStatus: tokenservice.ValidationStatus_EXPIRED,
// 					}, nil
// 				},
// 			},
// 			want{
// 				err: "dpop nonce invalid",
// 			},
// 		},
// 		{
// 			"handles failure to revoke dpop nonce",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod:        "/some/method",
// 							GrpcRequestDigest: []byte("somedigest"),
// 							Ttl:               60, // seconds
// 						},
// 					},
// 				},
// 				store: tokenstoremock.Store{
// 					DeleteTokenErr: true,
// 				},
// 				validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 					return &tokenservice.ValidateResponse{
// 						ValidationStatus: tokenservice.ValidationStatus_VALID,
// 					}, nil
// 				},
// 			},
// 			want{
// 				err: tokenstoremock.DeleteTokenErr,
// 			},
// 		},
// 		{
// 			"handles failure to store split token in redis",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod:        "/some/method",
// 							GrpcRequestDigest: []byte("somedigest"),
// 							Ttl:               60, // seconds
// 						},
// 					},
// 				},
// 				store: tokenstoremock.Store{
// 					StoreTokenErr: true,
// 				},
// 				validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 					return &tokenservice.ValidateResponse{
// 						ValidationStatus: tokenservice.ValidationStatus_VALID,
// 					}, nil
// 				},
// 			},
// 			want{
// 				err: tokenstoremock.StoreTokenErr,
// 			},
// 		},
// 		{
// 			"is successful with dpop",
// 			input{
// 				req: &tokenservice.GenerateRequest{
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod:        "/some/method",
// 							GrpcRequestDigest: []byte("somedigest"),
// 							Ttl:               60, // seconds
// 						},
// 					},
// 				},
// 				store: tokenstoremock.Store{},
// 				validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 					return &tokenservice.ValidateResponse{
// 						ValidationStatus: tokenservice.ValidationStatus_VALID,
// 					}, nil
// 				},
// 			},
// 			want{},
// 		},
// 		{
// 			"is successful without dpop",
// 			input{
// 				req:   &tokenservice.GenerateRequest{},
// 				store: tokenstoremock.Store{},
// 			},
// 			want{},
// 		},
// 	}

// 	for _, tt := range cases {
// 		t.Run(tt.name, func(t *testing.T) {
// 			manager := manager{
// 				store:               tt.input.store,
// 				privateKey:          privateKey,
// 				validateDPoPNonceFn: tt.input.validateDPoPNonceFn,
// 			}

// 			_, err := manager.Generate(context.Background(), tt.input.req)
// 			if tt.want.err != "" {
// 				if assert.NotNil(t, err) {
// 					assert.Contains(t, err.Error(), tt.want.err)
// 				}
// 			} else {
// 				assert.Nil(t, err)
// 			}
// 		})
// 	}
// }

// func TestValidateUnit(t *testing.T) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	goldenToken, _ := generateToken(t, privateKey)
// 	expiredToken, _ := generateExpiredToken(t, privateKey)
// 	boundToken, _ := generateTokenWithThumbprint(t, privateKey)
// 	goldenProof, _ := generateProof(t)
// 	invalidSignatureProof, _ := generateProofWithBadSignature(t)

// 	type input struct {
// 		req                 *tokenservice.ValidateRequest
// 		store               tokenstore.Store
// 		validateDPoPNonceFn validateDPoPNonceFn
// 		revokeDPoPNonceFn   revokeDPoPNonceFn
// 	}

// 	type want struct {
// 		err    string
// 		status tokenservice.ValidationStatus
// 	}

// 	cases := []struct {
// 		name  string
// 		input input
// 		want  want
// 	}{
// 		{
// 			"handles token not found",
// 			input{
// 				req: &tokenservice.ValidateRequest{
// 					Token: goldenToken.PublicTokenEncoded,
// 				},
// 				store: tokenstoremock.Store{
// 					GetTokenErr: true,
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_NOTFOUND,
// 			},
// 		},
// 		{
// 			"handles invalid signature",
// 			input{
// 				req: &tokenservice.ValidateRequest{},
// 				store: tokenstoremock.Store{
// 					WantToken: generateTokenWithBadSignature(t),
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_INVALID_SIGNATURE,
// 			},
// 		},
// 		{
// 			"handles expired token",
// 			input{
// 				req: &tokenservice.ValidateRequest{
// 					Token: goldenToken.PublicTokenEncoded,
// 				},
// 				store: tokenstoremock.Store{
// 					WantToken: expiredToken,
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_EXPIRED,
// 			},
// 		},
// 		{
// 			"handles missing dpop proof",
// 			input{
// 				req: &tokenservice.ValidateRequest{
// 					Token: goldenToken.PublicTokenEncoded,
// 				},
// 				store: tokenstoremock.Store{
// 					WantToken: boundToken,
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_DPOP_PROOF_FAILURE,
// 			},
// 		},
// 		{
// 			"handles dpop public key not matching token thumbprint",
// 			input{
// 				req: &tokenservice.ValidateRequest{
// 					Token: boundToken.PublicTokenEncoded,
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 					},
// 				},
// 				store: tokenstoremock.Store{
// 					WantToken: boundToken,
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_DPOP_PROOF_FAILURE,
// 			},
// 		},
// 		{
// 			"handles dpop proof signature not matching public key",
// 			input{
// 				req: &tokenservice.ValidateRequest{
// 					Token: boundToken.PublicTokenEncoded,
// 					Dpop: &tokenservice.DPoP{
// 						Proof: invalidSignatureProof,
// 					},
// 				},
// 				store: tokenstoremock.Store{
// 					WantToken: boundToken,
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_DPOP_PROOF_FAILURE,
// 			},
// 		},
// 		{
// 			"handles invalid claims in dpop proof",
// 			input{
// 				req: &tokenservice.ValidateRequest{
// 					Token: boundToken.PublicTokenEncoded,
// 					Dpop: &tokenservice.DPoP{
// 						Proof: goldenProof,
// 						WantedClaims: &tokenservice.Claims{
// 							GrpcMethod: "/garbage",
// 						},
// 					},
// 				},
// 				store: tokenstoremock.Store{
// 					WantToken: boundToken,
// 				},
// 			},
// 			want{
// 				status: tokenservice.ValidationStatus_DPOP_PROOF_FAILURE,
// 			},
// 		},
// 		// {
// 		// 	"handles failure to validate dpop nonce",
// 		// 	input{
// 		// 		req: &tokenservice.ValidateRequest{
// 		// 			Token: goldenToken,
// 		// 			Dpop: &tokenservice.DPoP{
// 		// 				Proof: goldenProof,
// 		// 				WantedClaims: &tokenservice.Claims{
// 		// 					GrpcMethod:        "/some/method",
// 		// 					GrpcRequestDigest: []byte("somedigest"),
// 		// 					Ttl:               60,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		db: mockdb.Repository{
// 		// 			TokenRepo: tokensmock.Repository{
// 		// 				WantToken: tokens.Token{
// 		// 					Expiry:         time.Now().Add(time.Minute).Unix(),
// 		// 					ThumbprintHash: goldenThumbprintHash,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 		// 			return nil, errors.New("failed to validate dpop nonce")
// 		// 		},
// 		// 	},
// 		// 	want{
// 		// 		err: "failed to validate dpop nonce",
// 		// 	},
// 		// },
// 		// {
// 		// 	"handles dpop nonce invalid",
// 		// 	input{
// 		// 		req: &tokenservice.ValidateRequest{
// 		// 			Token: goldenToken,
// 		// 			Dpop: &tokenservice.DPoP{
// 		// 				Proof: goldenProof,
// 		// 				WantedClaims: &tokenservice.Claims{
// 		// 					GrpcMethod:        "/some/method",
// 		// 					GrpcRequestDigest: []byte("somedigest"),
// 		// 					Ttl:               60,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		db: mockdb.Repository{
// 		// 			TokenRepo: tokensmock.Repository{
// 		// 				WantToken: tokens.Token{
// 		// 					Expiry:         time.Now().Add(time.Minute).Unix(),
// 		// 					ThumbprintHash: goldenThumbprintHash,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 		// 			return &tokenservice.ValidateResponse{
// 		// 				ValidationStatus: tokenservice.ValidationStatus_EXPIRED,
// 		// 			}, nil
// 		// 		},
// 		// 	},
// 		// 	want{
// 		// 		status: tokenservice.ValidationStatus_DPOP_PROOF_FAILURE,
// 		// 	},
// 		// },
// 		// {
// 		// 	"handles failure to revoke dpop nonce",
// 		// 	input{
// 		// 		req: &tokenservice.ValidateRequest{
// 		// 			Token: goldenToken,
// 		// 			Dpop: &tokenservice.DPoP{
// 		// 				Proof: goldenProof,
// 		// 				WantedClaims: &tokenservice.Claims{
// 		// 					GrpcMethod:        "/some/method",
// 		// 					GrpcRequestDigest: []byte("somedigest"),
// 		// 					Ttl:               60,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		db: mockdb.Repository{
// 		// 			TokenRepo: tokensmock.Repository{
// 		// 				WantToken: tokens.Token{
// 		// 					Expiry:         time.Now().Add(time.Minute).Unix(),
// 		// 					ThumbprintHash: goldenThumbprintHash,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 		// 			return &tokenservice.ValidateResponse{
// 		// 				ValidationStatus: tokenservice.ValidationStatus_VALID,
// 		// 			}, nil
// 		// 		},
// 		// 		revokeDPoPNonceFn: func(ctx context.Context, req *tokenservice.RevokeRequest) (*tokenservice.RevokeResponse, error) {
// 		// 			return nil, errors.New("failed to revoke nonce")
// 		// 		},
// 		// 	},
// 		// 	want{
// 		// 		err: "failed to revoke nonce",
// 		// 	},
// 		// },
// 		// {
// 		// 	"handles valid token",
// 		// 	input{
// 		// 		req: &tokenservice.ValidateRequest{
// 		// 			Token: goldenToken,
// 		// 			Dpop: &tokenservice.DPoP{
// 		// 				Proof: goldenProof,
// 		// 				WantedClaims: &tokenservice.Claims{
// 		// 					GrpcMethod:        "/some/method",
// 		// 					GrpcRequestDigest: []byte("somedigest"),
// 		// 					Ttl:               60,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		db: mockdb.Repository{
// 		// 			TokenRepo: tokensmock.Repository{
// 		// 				WantToken: tokens.Token{
// 		// 					Expiry:         time.Now().Add(time.Minute).Unix(),
// 		// 					ThumbprintHash: goldenThumbprintHash,
// 		// 				},
// 		// 			},
// 		// 		},
// 		// 		validateDPoPNonceFn: func(ctx context.Context, req *tokenservice.ValidateRequest) (*tokenservice.ValidateResponse, error) {
// 		// 			return &tokenservice.ValidateResponse{
// 		// 				ValidationStatus: tokenservice.ValidationStatus_VALID,
// 		// 			}, nil
// 		// 		},
// 		// 		revokeDPoPNonceFn: func(ctx context.Context, req *tokenservice.RevokeRequest) (*tokenservice.RevokeResponse, error) {
// 		// 			return &tokenservice.RevokeResponse{}, nil
// 		// 		},
// 		// 	},
// 		// 	want{
// 		// 		status: tokenservice.ValidationStatus_VALID,
// 		// 	},
// 		// },
// 	}

// 	for _, tt := range cases {
// 		t.Run(tt.name, func(t *testing.T) {
// 			manager := manager{
// 				store:               tt.input.store,
// 				privateKey:          privateKey,
// 				validateDPoPNonceFn: tt.input.validateDPoPNonceFn,
// 				revokeDPoPNonceFn:   tt.input.revokeDPoPNonceFn,
// 			}

// 			resp, err := manager.Validate(context.Background(), tt.input.req)
// 			if tt.want.err != "" {
// 				if assert.NotNil(t, err) {
// 					assert.Contains(t, err.Error(), tt.want.err)
// 				}
// 			} else {
// 				assert.Nil(t, err)
// 				assert.Equal(t, tt.want.status, resp.ValidationStatus)
// 			}
// 		})
// 	}
// }

// func TestRefreshUnit(t *testing.T) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	goldenToken, _ := generateToken(t, privateKey)

// 	type input struct {
// 		req                *tokenservice.RefreshRequest
// 		db                 db.Repository
// 		generateFn         generateFn
// 		generateWithDPoPFn generateWithDPoPFn
// 	}

// 	type want struct {
// 		err string
// 	}

// 	cases := []struct {
// 		name  string
// 		input input
// 		want  want
// 	}{
// 		{
// 			"handles failure to decode split token",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: "garbage",
// 				},
// 			},
// 			want{
// 				err: "invalid character",
// 			},
// 		},
// 		{
// 			"handles invalid signature",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: generateTokenWithBadSignature(t),
// 				},
// 			},
// 			want{
// 				err: "token signature does not match",
// 			},
// 		},
// 		{
// 			"handles failure to get token from database",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: goldenToken,
// 				},
// 				db: mockdb.Repository{
// 					RefreshTknRepo: refreshtokensmock.Repository{
// 						GetErr: true,
// 					},
// 				},
// 			},
// 			want{
// 				err: refreshtokensmock.GetErr,
// 			},
// 		},
// 		{
// 			"handles expired token",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: goldenToken,
// 				},
// 				db: mockdb.Repository{
// 					RefreshTknRepo: refreshtokensmock.Repository{
// 						WantRefreshToken: tokens.Token{
// 							Expiry: time.Now().Unix(),
// 						},
// 					},
// 				},
// 			},
// 			want{
// 				err: "refresh token is expired",
// 			},
// 		},
// 		{
// 			"handles failure to generate",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: goldenToken,
// 				},
// 				db: mockdb.Repository{
// 					RefreshTknRepo: refreshtokensmock.Repository{
// 						WantRefreshToken: tokens.Token{
// 							Expiry: time.Now().Add(time.Minute).Unix(),
// 						},
// 					},
// 				},
// 				generateFn: func(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error) {
// 					return nil, errors.New("failed to generate")
// 				},
// 			},
// 			want{
// 				err: "failed to generate",
// 			},
// 		},
// 		{
// 			"handles failure to generate with dpop",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: goldenToken,
// 				},
// 				db: mockdb.Repository{
// 					RefreshTknRepo: refreshtokensmock.Repository{
// 						WantRefreshToken: tokens.Token{
// 							Expiry: time.Now().Add(time.Minute).Unix(),
// 						},
// 						WantToken: tokens.Token{
// 							TTL:            60,
// 							ThumbprintHash: []byte("somethumbprint"),
// 						},
// 					},
// 				},
// 				generateWithDPoPFn: func(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error) {
// 					return nil, errors.New("failed to generate with dpop")
// 				},
// 			},
// 			want{
// 				err: "refesh token request requires dpop proof",
// 			},
// 		},
// 		{
// 			"handles failure to delete old tokens",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: goldenToken,
// 					Dpop:         &tokenservice.DPoP{},
// 				},
// 				db: mockdb.Repository{
// 					RefreshTknRepo: refreshtokensmock.Repository{
// 						WantRefreshToken: tokens.Token{
// 							Expiry: time.Now().Add(time.Minute).Unix(),
// 						},
// 						WantToken: tokens.Token{
// 							TTL:            60,
// 							ThumbprintHash: []byte("somethumbprint"),
// 						},
// 					},
// 					TokenRepo: tokensmock.Repository{
// 						DeleteErr: true,
// 					},
// 				},
// 				generateWithDPoPFn: func(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error) {
// 					return &tokenservice.GenerateResponse{}, nil
// 				},
// 			},
// 			want{
// 				err: tokensmock.DeleteErr,
// 			},
// 		},
// 		{
// 			"is succesful",
// 			input{
// 				req: &tokenservice.RefreshRequest{
// 					RefreshToken: goldenToken,
// 					Dpop:         &tokenservice.DPoP{},
// 				},
// 				db: mockdb.Repository{
// 					RefreshTknRepo: refreshtokensmock.Repository{
// 						WantRefreshToken: tokens.Token{
// 							Expiry: time.Now().Add(time.Minute).Unix(),
// 						},
// 						WantToken: tokens.Token{
// 							TTL:            60,
// 							ThumbprintHash: []byte("somethumbprint"),
// 						},
// 					},
// 					TokenRepo: tokensmock.Repository{},
// 				},
// 				generateWithDPoPFn: func(ctx context.Context, req *tokenservice.GenerateRequest) (*tokenservice.GenerateResponse, error) {
// 					return &tokenservice.GenerateResponse{}, nil
// 				},
// 			},
// 			want{},
// 		},
// 	}

// 	for _, tt := range cases {
// 		t.Run(tt.name, func(t *testing.T) {
// 			manager := manager{
// 				dbrepo:             tt.input.db,
// 				privateKey:         privateKey,
// 				generateFn:         tt.input.generateFn,
// 				generateWithDPoPFn: tt.input.generateWithDPoPFn,
// 			}

// 			_, err := manager.Refresh(context.Background(), tt.input.req)
// 			if tt.want.err != "" {
// 				if assert.NotNil(t, err) {
// 					assert.Contains(t, err.Error(), tt.want.err)
// 				}
// 			} else {
// 				assert.Nil(t, err)
// 			}
// 		})
// 	}
// }

// func TestRevokeUnit(t *testing.T) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	goldenToken, _ := generateToken(t, privateKey)

// 	type input struct {
// 		req *tokenservice.RevokeRequest
// 		db  db.Repository
// 	}

// 	type want struct {
// 		err string
// 	}

// 	cases := []struct {
// 		name  string
// 		input input
// 		want  want
// 	}{
// 		{
// 			"handles failure to decode split token",
// 			input{
// 				req: &tokenservice.RevokeRequest{
// 					Token: "garbage",
// 				},
// 			},
// 			want{
// 				err: "invalid character",
// 			},
// 		},
// 		{
// 			"handles failure to delete tokens",
// 			input{
// 				req: &tokenservice.RevokeRequest{
// 					Token: goldenToken,
// 				},
// 				db: mockdb.Repository{
// 					TokenRepo: tokensmock.Repository{
// 						DeleteErr: true,
// 					},
// 				},
// 			},
// 			want{
// 				err: tokensmock.DeleteErr,
// 			},
// 		},
// 		{
// 			"is successful",
// 			input{
// 				req: &tokenservice.RevokeRequest{
// 					Token: goldenToken,
// 				},
// 				db: mockdb.Repository{
// 					TokenRepo: tokensmock.Repository{},
// 				},
// 			},
// 			want{},
// 		},
// 	}

// 	for _, tt := range cases {
// 		t.Run(tt.name, func(t *testing.T) {
// 			manager := New(tt.input.db, privateKey)
// 			_, err := manager.Revoke(context.Background(), tt.input.req)
// 			if tt.want.err != "" {
// 				if assert.NotNil(t, err) {
// 					assert.Contains(t, err.Error(), tt.want.err)
// 				}
// 			} else {
// 				assert.Nil(t, err)
// 			}
// 		})
// 	}
// }

// func generateProofWithBadSignature(t *testing.T) (proof string, thumbprintHash []byte) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}
// 	publicKey := keys.SerializePublicKey(&privateKey.PublicKey)

// 	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	claims := dpop.Claims{
// 		Method:       "/some/method",
// 		MethodDigest: []byte("somedigest"),
// 		IssuedAt:     time.Now().Unix(),
// 	}

// 	v, err := json.Marshal(&claims)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	invalidSignature, err := keys.Sign(privateKey2, v)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	dpopProof := dpop.Proof{
// 		PublicKey: publicKey,
// 		Claims:    v,
// 		Signature: invalidSignature,
// 	}

// 	v, err = json.Marshal(&dpopProof)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	thumbprintHash, err = keys.Sha256Hash(publicKey)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	return base64.RawURLEncoding.EncodeToString(v), thumbprintHash
// }

// func generateProof(t *testing.T) (proof string, thumbprintHash []byte) {
// 	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	claims := dpop.Claims{
// 		Method:       "/some/method",
// 		MethodDigest: []byte("somedigest"),
// 		IssuedAt:     time.Now().Unix(),
// 	}

// 	encodedProof, err := dpop.Encode(privateKey, claims)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	thumbprintHash, err = keys.Sha256Hash(keys.SerializePublicKey(&privateKey.PublicKey))
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	return encodedProof, thumbprintHash
// }

// func generateTokenWithBadSignature(t *testing.T) tokens.GenerateToken {
// 	invalidKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	splitToken := tokens.Token{
// 		Verifier: []byte("verifier"),
// 		Selector: []byte("selector"),
// 		Expiry:   time.Now().Unix(),
// 	}

// 	invalidSignature, err := keys.Sign(invalidKey, append(splitToken.Selector, splitToken.Verifier...))
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}
// 	splitToken.Signature = invalidSignature

// 	return tokens.GenerateToken{
// 		Token: splitToken,
// 	}
// }

// func generateToken(t *testing.T, privateKey *ecdsa.PrivateKey) (token tokens.GenerateToken, verifierHash []byte) {
// 	generatedToken, _, err := tokens.Generate(time.Minute, privateKey, nil)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	verifierHash, err = keys.Sha256Hash(generatedToken.Token.Verifier)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	return generatedToken, verifierHash
// }

// func generateExpiredToken(t *testing.T, privateKey *ecdsa.PrivateKey) (token tokens.GenerateToken, verifierHash []byte) {
// 	generatedToken, _, err := tokens.Generate(time.Minute*-1, privateKey, nil, "somescope")
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	verifierHash, err = keys.Sha256Hash(generatedToken.Token.Verifier)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	return generatedToken, verifierHash
// }

// func generateTokenWithThumbprint(t *testing.T, privateKey *ecdsa.PrivateKey) (token tokens.GenerateToken, verifierHash []byte) {
// 	generatedToken, _, err := tokens.GenerateWithThumbprint(time.Minute, privateKey, []byte("somethumbprint"), nil)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	verifierHash, err = keys.Sha256Hash(generatedToken.Token.Verifier)
// 	if !assert.Nil(t, err) {
// 		t.FailNow()
// 	}

// 	return generatedToken, verifierHash
// }
