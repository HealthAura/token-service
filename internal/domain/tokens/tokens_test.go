package tokens

import (
	"context"
	"net/http"
	"testing"

	tokenservice "github.com/HealthAura/token-service/gen/go/v1"
	"github.com/HealthAura/token-service/public/jwt"
	"github.com/HealthAura/token-service/public/jwt/jwtmock"

	"github.com/stretchr/testify/assert"
)

func TestGenerateUnit(t *testing.T) {
	type input struct {
		req  func() *tokenservice.TokenserviceGenerateRequest
		orch jwt.Orchestrator
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			"handles failure to parse AccessTokenTtl",
			input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					req := mockGenerateRequest()
					req.AccessTokenTtl = strToPtr("invalid")
					return req
				},
			},
			want{
				err: "failed to parse access token TTL",
			},
		},
		{
			"handles failure to parse dpopTTL",
			input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					req := mockGenerateRequest()
					req.Dpop.TtlMinutes = strToPtr("invalid")
					return req
				},
			},
			want{
				err: "failed to parse dpop TTL",
			},
		},
		{
			"failed to generate token",
			input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return mockGenerateRequest()
				},
				orch: jwtmock.MockOrchestrator{
					GenerateTokenError: true,
				},
			},
			want{
				err: jwtmock.GenerateTokenError,
			},
		},
		{
			"failed to parse refresh TTL",
			input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					req := mockGenerateRequest()
					req.RefreshTokenTtl = strToPtr("invalid")

					return req
				},
				orch: jwtmock.MockOrchestrator{},
			},
			want{
				err: "failed to parse refresh TTL",
			},
		},
		{
			"is successful",
			input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return mockGenerateRequest()
				},
				orch: jwtmock.MockOrchestrator{},
			},
			want{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			manager := manager{
				orch: tt.input.orch,
			}

			_, err := manager.Generate(context.Background(), tt.input.req())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestRefreshUnit(t *testing.T) {
	type input struct {
		req  func() *tokenservice.TokenserviceRefreshRequest
		orch jwt.Orchestrator
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			"failed to ValidateAndVerify",
			input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return mockRefreshRequest()
				},
				orch: jwtmock.MockOrchestrator{
					ValidateAndVerifyError: true,
				},
			},
			want{
				err: jwtmock.ValidateAndVerifyError,
			},
		},
		{
			"failed to RevokeToken",
			input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return mockRefreshRequest()
				},
				orch: jwtmock.MockOrchestrator{
					RevokeTokenError: true,
				},
			},
			want{
				err: jwtmock.RevokeTokenError,
			},
		},
		{
			"failed to Generate",
			input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return mockRefreshRequest()
				},
				orch: jwtmock.MockOrchestrator{
					GenerateTokenError: true,
				},
			},
			want{
				err: jwtmock.GenerateTokenError,
			},
		},
		{
			"is sucessful",
			input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return mockRefreshRequest()
				},
				orch: jwtmock.MockOrchestrator{},
			},
			want{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			manager := manager{
				orch: tt.input.orch,
			}

			_, err := manager.Refresh(context.Background(), tt.input.req())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestGenerateNonceUnit(t *testing.T) {
	type input struct {
		req  func() *tokenservice.TokenserviceGenerateNonceRequest
		orch jwt.Orchestrator
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			"handles failure to parse nonce TTL",
			input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					req := mockGenerateNonceRequest()
					req.NonceTtl = strToPtr("invalid")
					return req
				},
			},
			want{
				err: "failed to parse nonce TTL",
			},
		},
		{
			"handles failure to generate nonce",
			input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					return mockGenerateNonceRequest()
				},
				orch: jwtmock.MockOrchestrator{
					GenerateNonceError: true,
				},
			},
			want{
				err: jwtmock.GenerateNonceError,
			},
		},
		{
			"is successful",
			input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					return mockGenerateNonceRequest()
				},
				orch: jwtmock.MockOrchestrator{},
			},
			want{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			manager := manager{
				orch: tt.input.orch,
			}

			_, err := manager.GenerateNonce(context.Background(), tt.input.req())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateGenerateNonceRequestUnit(t *testing.T) {
	type input struct {
		req func() *tokenservice.TokenserviceGenerateNonceRequest
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			name: "nil request",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					return nil
				},
			},
			want: want{
				err: "validation errors: request is nil",
			},
		},
		{
			name: "nil claims",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					return &tokenservice.TokenserviceGenerateNonceRequest{
						Claims:   nil,
						NonceTtl: strToPtr("300"),
					}
				},
			},
			want: want{
				err: "validation errors: claims errors: claims is nil",
			},
		},
		{
			name: "nil audience in claims",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					return &tokenservice.TokenserviceGenerateNonceRequest{
						Claims: &tokenservice.TokenserviceClaims{
							Aud:    nil,
							Iss:    strToPtr("issuer"),
							Jti:    strToPtr("jti"),
							Sub:    strToPtr("subject"),
							Scopes: &[]string{"read", "write"},
							CustomClaims: &map[string]interface{}{
								"custom_key": "custom_value",
							},
						},
						NonceTtl: strToPtr("300"),
					}
				},
			},
			want: want{
				err: "validation errors: claims errors: aud is nil",
			},
		},
		{
			name: "successful validation",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateNonceRequest {
					return &tokenservice.TokenserviceGenerateNonceRequest{
						Claims: &tokenservice.TokenserviceClaims{
							Aud:    strToPtr("audience"),
							Iss:    strToPtr("issuer"),
							Jti:    strToPtr("jti"),
							Sub:    strToPtr("subject"),
							Scopes: &[]string{"read", "write"},
							CustomClaims: &map[string]interface{}{
								"custom_key": "custom_value",
							},
						},
						NonceTtl: strToPtr("300"),
					}
				},
			},
			want: want{
				err: "",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGenerateNonceRequest(tt.input.req())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateRefreshRequestUnit(t *testing.T) {
	type input struct {
		req func() *tokenservice.TokenserviceRefreshRequest
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			name: "nil request",
			input: input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return nil
				},
			},
			want: want{
				err: "validation errors: request is nil",
			},
		},
		{
			name: "nil access token TTL",
			input: input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return &tokenservice.TokenserviceRefreshRequest{
						AccessTokenTtl:  nil,
						RefreshToken:    strToPtr("example_refresh_token"),
						RefreshTokenTtl: strToPtr("86400"),
						RefreshDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/refresh"),
								Rh:  strToPtr("example_rh"),
							},
						},
						NewTokenDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/newtoken"),
								Rh:  strToPtr("example_rh"),
							},
						},
					}
				},
			},
			want: want{
				err: "validation errors: access token TTL is nil",
			},
		},
		{
			name: "nil refresh token",
			input: input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return &tokenservice.TokenserviceRefreshRequest{
						AccessTokenTtl:  strToPtr("3600"),
						RefreshToken:    nil,
						RefreshTokenTtl: strToPtr("86400"),
						RefreshDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/refresh"),
								Rh:  strToPtr("example_rh"),
							},
						},
						NewTokenDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/newtoken"),
								Rh:  strToPtr("example_rh"),
							},
						},
					}
				},
			},
			want: want{
				err: "validation errors: refresh token is nil",
			},
		},
		{
			name: "nil refresh token DPoP",
			input: input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return &tokenservice.TokenserviceRefreshRequest{
						AccessTokenTtl:  strToPtr("3600"),
						RefreshToken:    strToPtr("example_refresh_token"),
						RefreshTokenTtl: strToPtr("86400"),
						RefreshDpop:     nil,
						NewTokenDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/newtoken"),
								Rh:  strToPtr("example_rh"),
							},
						},
					}
				},
			},
			want: want{
				err: "validation errors: refesh token dpop: dpop errors: dpop is nil",
			},
		},
		{
			name: "successful validation",
			input: input{
				req: func() *tokenservice.TokenserviceRefreshRequest {
					return &tokenservice.TokenserviceRefreshRequest{
						AccessTokenTtl:  strToPtr("3600"),
						RefreshToken:    strToPtr("example_refresh_token"),
						RefreshTokenTtl: strToPtr("86400"),
						RefreshDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/refresh"),
								Rh:  strToPtr("example_rh"),
							},
						},
						NewTokenDpop: &tokenservice.TokenserviceDPoP{
							Proof: strToPtr("proof"),
							WantClaims: &tokenservice.TokenserviceDPoPClaims{
								Htm: strToPtr("POST"),
								Htu: strToPtr("https://example.com/newtoken"),
								Rh:  strToPtr("example_rh"),
							},
						},
						RequiredScopes: &[]string{"read", "write"},
					}
				},
			},
			want: want{
				err: "",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRefreshRequest(tt.input.req())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateGenerateRequestUnit(t *testing.T) {
	type input struct {
		req func() *tokenservice.TokenserviceGenerateRequest
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			name: "nil request",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return nil
				},
			},
			want: want{
				err: "validation errors: request is nil",
			},
		},
		{
			name: "nil claims",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return &tokenservice.TokenserviceGenerateRequest{
						Claims:          nil,
						Dpop:            mockDpop(),
						AccessTokenTtl:  strToPtr("3600"),
						RefreshTokenTtl: strToPtr("86400"),
					}
				},
			},
			want: want{
				err: "validation errors: claims errors: claims is nil",
			},
		},
		{
			name: "nil DPoP",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return &tokenservice.TokenserviceGenerateRequest{
						Claims:          mockClaims(),
						Dpop:            nil,
						AccessTokenTtl:  strToPtr("3600"),
						RefreshTokenTtl: strToPtr("86400"),
					}
				},
			},
			want: want{
				err: "validation errors: dpop errors: dpop is nil",
			},
		},
		{
			name: "nil access token TTL",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return &tokenservice.TokenserviceGenerateRequest{
						Claims:          mockClaims(),
						Dpop:            mockDpop(),
						AccessTokenTtl:  nil,
						RefreshTokenTtl: strToPtr("86400"),
					}
				},
			},
			want: want{
				err: "validation errors: access token TTL is nil",
			},
		},
		{
			name: "nil refresh token TTL",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return &tokenservice.TokenserviceGenerateRequest{
						Claims:          mockClaims(),
						Dpop:            mockDpop(),
						AccessTokenTtl:  strToPtr("3600"),
						RefreshTokenTtl: nil,
					}
				},
			},
			want: want{
				err: "validation errors: refresh token TTL is nil",
			},
		},
		{
			name: "successful validation",
			input: input{
				req: func() *tokenservice.TokenserviceGenerateRequest {
					return &tokenservice.TokenserviceGenerateRequest{
						Claims:          mockClaims(),
						Dpop:            mockDpop(),
						AccessTokenTtl:  strToPtr("3600"),
						RefreshTokenTtl: strToPtr("86400"),
					}
				},
			},
			want: want{
				err: "",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGenerateRequest(tt.input.req())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateDPoPUnit(t *testing.T) {
	type input struct {
		dpop func() *tokenservice.TokenserviceDPoP
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			name: "nil DPoP",
			input: input{
				dpop: func() *tokenservice.TokenserviceDPoP {
					return nil
				},
			},
			want: want{
				err: "dpop errors: dpop is nil",
			},
		},
		{
			name: "nil proof",
			input: input{
				dpop: func() *tokenservice.TokenserviceDPoP {
					return &tokenservice.TokenserviceDPoP{
						Proof:      nil,
						WantClaims: mockDPoPClaims(),
						TtlMinutes: strToPtr("10"),
					}
				},
			},
			want: want{
				err: "dpop errors: proof is nil",
			},
		},
		{
			name: "invalid DPoP claims",
			input: input{
				dpop: func() *tokenservice.TokenserviceDPoP {
					return &tokenservice.TokenserviceDPoP{
						Proof: strToPtr("example_proof"),
						WantClaims: &tokenservice.TokenserviceDPoPClaims{
							Htm: nil, // Missing required field
							Htu: strToPtr("https://example.com"),
							Rh:  strToPtr("example_rh"),
						},
						TtlMinutes: strToPtr("10"),
					}
				},
			},
			want: want{
				err: "dpop errors: dpop claim errors: htm is nil",
			},
		},
		{
			name: "nil TTL",
			input: input{
				dpop: func() *tokenservice.TokenserviceDPoP {
					return &tokenservice.TokenserviceDPoP{
						Proof:      strToPtr("example_proof"),
						WantClaims: mockDPoPClaims(),
						TtlMinutes: nil,
					}
				},
			},
			want: want{
				err: "",
			},
		},
		{
			name: "successful validation",
			input: input{
				dpop: func() *tokenservice.TokenserviceDPoP {
					return &tokenservice.TokenserviceDPoP{
						Proof:      strToPtr("example_proof"),
						WantClaims: mockDPoPClaims(),
						TtlMinutes: strToPtr("10"),
					}
				},
			},
			want: want{
				err: "",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDPoP(tt.input.dpop())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestValidateDPoPClaimsUnit(t *testing.T) {
	type input struct {
		claims func() *tokenservice.TokenserviceDPoPClaims
	}

	type want struct {
		err string
	}

	cases := []struct {
		name  string
		input input
		want  want
	}{
		{
			name: "nil claims",
			input: input{
				claims: func() *tokenservice.TokenserviceDPoPClaims {
					return nil
				},
			},
			want: want{
				err: "dpop claim errors: claims is nil",
			},
		},
		{
			name: "nil htm",
			input: input{
				claims: func() *tokenservice.TokenserviceDPoPClaims {
					return &tokenservice.TokenserviceDPoPClaims{
						Htm: nil,
						Htu: strToPtr("https://example.com"),
						Rh:  strToPtr("example_rh"),
					}
				},
			},
			want: want{
				err: "dpop claim errors: htm is nil",
			},
		},
		{
			name: "nil htu",
			input: input{
				claims: func() *tokenservice.TokenserviceDPoPClaims {
					return &tokenservice.TokenserviceDPoPClaims{
						Htm: strToPtr("POST"),
						Htu: nil,
						Rh:  strToPtr("example_rh"),
					}
				},
			},
			want: want{
				err: "dpop claim errors: htu is nil",
			},
		},
		{
			name: "nil rh",
			input: input{
				claims: func() *tokenservice.TokenserviceDPoPClaims {
					return &tokenservice.TokenserviceDPoPClaims{
						Htm: strToPtr("POST"),
						Htu: strToPtr("https://example.com"),
						Rh:  nil,
					}
				},
			},
			want: want{
				err: "dpop claim errors: rh is nil",
			},
		},
		{
			name: "all fields nil",
			input: input{
				claims: func() *tokenservice.TokenserviceDPoPClaims {
					return &tokenservice.TokenserviceDPoPClaims{
						Htm: nil,
						Htu: nil,
						Rh:  nil,
					}
				},
			},
			want: want{
				err: "dpop claim errors: htm is nil, htu is nil, rh is nil",
			},
		},
		{
			name: "successful validation",
			input: input{
				claims: func() *tokenservice.TokenserviceDPoPClaims {
					return &tokenservice.TokenserviceDPoPClaims{
						Htm: strToPtr("POST"),
						Htu: strToPtr("https://example.com"),
						Rh:  strToPtr("example_rh"),
					}
				},
			},
			want: want{
				err: "",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDPoPClaims(tt.input.claims())
			if tt.want.err != "" {
				if assert.NotNil(t, err) {
					assert.Contains(t, err.Error(), tt.want.err)
				}
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func mockDPoPClaims() *tokenservice.TokenserviceDPoPClaims {
	return &tokenservice.TokenserviceDPoPClaims{
		Htm: strToPtr("POST"),
		Htu: strToPtr("https://example.com"),
		Rh:  strToPtr("example_rh"),
	}
}

func mockClaims() *tokenservice.TokenserviceClaims {
	return &tokenservice.TokenserviceClaims{
		Aud:    strToPtr("audience"),
		Iss:    strToPtr("issuer"),
		Jti:    strToPtr("jti"),
		Sub:    strToPtr("subject"),
		Scopes: &[]string{"read", "write"},
		CustomClaims: &map[string]interface{}{
			"key": "value",
		},
	}
}

func mockDpop() *tokenservice.TokenserviceDPoP {
	return &tokenservice.TokenserviceDPoP{
		Proof: strToPtr("proof"),
		WantClaims: &tokenservice.TokenserviceDPoPClaims{
			Htm: strToPtr("POST"),
			Htu: strToPtr("https://example.com"),
			Rh:  strToPtr("example_rh"),
		},
		TtlMinutes: strToPtr("10"),
	}
}

func mockGenerateRequest() *tokenservice.TokenserviceGenerateRequest {
	return &tokenservice.TokenserviceGenerateRequest{
		Claims: &tokenservice.TokenserviceClaims{
			Aud:    strToPtr("example_audience"),
			Iss:    strToPtr("example_issuer"),
			Jti:    strToPtr("example_jti"),
			Sub:    strToPtr("example_subject"),
			Scopes: &[]string{"read", "write"},
			CustomClaims: &map[string]interface{}{
				"custom_key": "custom_value",
			},
		},
		Dpop: &tokenservice.TokenserviceDPoP{
			Proof: strToPtr("example_proof"),
			WantClaims: &tokenservice.TokenserviceDPoPClaims{
				Htm: strToPtr(http.MethodPost),
				Htu: strToPtr("https://example.com/token"),
				Rh:  strToPtr("test_rh"),
			},
			TtlMinutes: strToPtr("5"),
		},
		AccessTokenTtl:  strToPtr("3600"),
		RefreshTokenTtl: strToPtr("86400"),
	}
}

func mockRefreshRequest() *tokenservice.TokenserviceRefreshRequest {
	return &tokenservice.TokenserviceRefreshRequest{
		AccessTokenTtl:  strToPtr("3600"), // 1 hour
		RefreshToken:    strToPtr("example_refresh_token"),
		RefreshTokenTtl: strToPtr("86400"), // 1 day
		RefreshDpop: &tokenservice.TokenserviceDPoP{
			Proof: strToPtr("example_refresh_proof"),
			WantClaims: &tokenservice.TokenserviceDPoPClaims{
				Htm: strToPtr("POST"),
				Htu: strToPtr("https://example.com/refresh"),
				Rh:  strToPtr("example_rh"),
			},
			TtlMinutes: strToPtr("10"),
		},
		NewTokenDpop: &tokenservice.TokenserviceDPoP{
			Proof: strToPtr("example_new_proof"),
			WantClaims: &tokenservice.TokenserviceDPoPClaims{
				Htm: strToPtr("POST"),
				Htu: strToPtr("https://example.com/newtoken"),
				Rh:  strToPtr("example_new_rh"),
			},
			TtlMinutes: strToPtr("10"),
		},
		RequiredScopes: &[]string{"read", "write", "admin"},
	}
}

func mockGenerateNonceRequest() *tokenservice.TokenserviceGenerateNonceRequest {
	return &tokenservice.TokenserviceGenerateNonceRequest{
		Claims: &tokenservice.TokenserviceClaims{
			Aud:    strToPtr("example_audience"),
			Iss:    strToPtr("example_issuer"),
			Jti:    strToPtr("example_jti"),
			Sub:    strToPtr("example_subject"),
			Scopes: &[]string{"read", "write"},
			CustomClaims: &map[string]interface{}{
				"custom_key": "custom_value",
			},
		},
		NonceTtl: strToPtr("300"), // 5 minutes
	}
}
